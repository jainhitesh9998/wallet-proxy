package io.vctrust.trust.server.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Where the service's ES256 private key lives. The public half is exposed as a JWK; signing goes through a
 * {@link JWSSigner}, so a key held by an HSM (PKCS#11) is used without ever being exported.
 */
public interface SigningKeySource {

    /** The public key as published, with {@code kid}, {@code use=sig} and {@code alg=ES256}. */
    ECKey publicKey();

    JWSSigner signer();

    /** For logs: where the key comes from (never key material). */
    String description();

    static SigningKeySource fromConfig(TrustProperties.SigningKey cfg, String defaultFile) {
        String type = cfg.getType() == null ? "jwk-file" : cfg.getType().trim().toLowerCase(Locale.ROOT);
        SigningKeySource source = switch (type) {
            case "jwk-file" -> JwkFile.loadOrGenerate(Path.of(cfg.getFile() != null && !cfg.getFile().isBlank() ? cfg.getFile() : defaultFile), cfg.getKeyId());
            case "keystore" -> Store.keystore(cfg);
            case "pkcs11" -> Store.pkcs11(cfg);
            default -> throw new IllegalStateException("trust.service.signing-key.type must be jwk-file, keystore or pkcs11 (got " + cfg.getType() + ")");
        };
        selfTest(source);
        return source;
    }

    /** Signs and verifies a probe, so a mismatched alias or a broken token fails at startup, not on the first request. */
    private static void selfTest(SigningKeySource source) {
        try {
            byte[] probe = "vc-trust-service signing key self-test".getBytes(StandardCharsets.UTF_8);
            JWSHeader h = new JWSHeader(JWSAlgorithm.ES256);
            Base64URL sig = source.signer().sign(h, probe);
            if (!new ECDSAVerifier(source.publicKey()).verify(h, probe, sig)) {
                throw new IllegalStateException("The signing key (" + source.description() + ") does not match its public key");
            }
        } catch (JOSEException e) {
            throw new IllegalStateException("The signing key (" + source.description() + ") cannot sign: " + e.getMessage(), e);
        }
    }

    /** P-256 public key → published JWK. */
    static ECKey publicJwk(ECPublicKey pub, String keyId, String where) {
        Curve curve = Curve.forECParameterSpec(pub.getParams());
        if (!Curve.P_256.equals(curve)) {
            throw new IllegalStateException(where + ": the signing key must be EC P-256 for ES256 (got " + (curve == null ? "an unknown curve" : curve) + ")");
        }
        ECKey.Builder b = new ECKey.Builder(Curve.P_256, pub).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256);
        try {
            return (keyId != null && !keyId.isBlank() ? b.keyID(keyId) : b.keyIDFromThumbprint()).build();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A private JWK in a file, generated (mode 0600) on first start. */
    record JwkFile(ECKey privateKey, ECKey publicKey, Path path) implements SigningKeySource {
        private static final Logger log = LoggerFactory.getLogger(JwkFile.class);

        static JwkFile loadOrGenerate(Path path, String keyId) {
            try {
                ECKey key;
                if (Files.exists(path)) {
                    JWK jwk = JWK.parse(Files.readString(path));
                    if (!(jwk instanceof ECKey ec) || !Curve.P_256.equals(ec.getCurve()) || !ec.isPrivate()) {
                        throw new IllegalStateException(path + ": the signing key must be a private EC P-256 JWK (got " + jwk.getKeyType()
                                + (jwk instanceof ECKey e ? " " + e.getCurve() : "") + ")");
                    }
                    key = ec;
                } else {
                    ECKey generated = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
                    key = new ECKey.Builder(generated).keyIDFromThumbprint().build();
                    if (path.getParent() != null) {
                        Files.createDirectories(path.getParent());
                    }
                    Files.writeString(path, key.toJSONString(), StandardCharsets.UTF_8);
                    try {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
                    } catch (UnsupportedOperationException ignored) {
                        // non-POSIX file system
                    }
                    log.info("Generated service signing key {} at {}", key.getKeyID(), path.toAbsolutePath());
                }
                if (keyId != null && !keyId.isBlank()) {
                    key = new ECKey.Builder(key).keyID(keyId).build();
                } else if (key.getKeyID() == null) {
                    key = new ECKey.Builder(key).keyIDFromThumbprint().build();
                }
                ECKey pub = new ECKey.Builder(key.toPublicJWK()).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).build();
                return new JwkFile(key, pub, path);
            } catch (IOException | java.text.ParseException | JOSEException e) {
                throw new IllegalStateException("Cannot load the signing key from " + path + ": " + e.getMessage(), e);
            }
        }

        @Override
        public JWSSigner signer() {
            try {
                return new ECDSASigner(privateKey);
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String description() {
            return "JWK file " + path.toAbsolutePath();
        }
    }

    /** A key entry in a Java KeyStore: a PKCS#12 / JKS file, or a PKCS#11 token whose key cannot be exported. */
    record Store(PrivateKey privateKey, ECKey publicKey, Provider provider, String description) implements SigningKeySource {

        static Store keystore(TrustProperties.SigningKey cfg) {
            if (cfg.getKeystore() == null || cfg.getKeystore().isBlank()) {
                throw new IllegalStateException("trust.service.signing-key.keystore is required for type keystore");
            }
            char[] password = chars(cfg.getPassword());
            try (InputStream in = Files.newInputStream(Path.of(cfg.getKeystore()))) {
                KeyStore ks = KeyStore.getInstance(cfg.getKeystoreType());
                ks.load(in, password);
                char[] keyPassword = cfg.getKeyPassword() != null ? cfg.getKeyPassword().toCharArray() : password;
                return fromStore(ks, cfg.getAlias(), keyPassword, null, cfg.getKeyId(), cfg.getKeystoreType() + " keystore " + cfg.getKeystore());
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException("Cannot load the signing key from keystore " + cfg.getKeystore() + ": " + e.getMessage(), e);
            }
        }

        static Store pkcs11(TrustProperties.SigningKey cfg) {
            if (cfg.getPkcs11Config() == null || cfg.getPkcs11Config().isBlank()) {
                throw new IllegalStateException("trust.service.signing-key.pkcs11-config is required for type pkcs11");
            }
            Provider base = Security.getProvider("SunPKCS11");
            if (base == null) {
                throw new IllegalStateException("The SunPKCS11 provider is not available in this JVM");
            }
            Provider p;
            try {
                p = base.configure(cfg.getPkcs11Config());
            } catch (RuntimeException e) {
                throw new IllegalStateException("Cannot configure PKCS#11 from " + cfg.getPkcs11Config() + ": " + e.getMessage(), e);
            }
            try {
                KeyStore ks = KeyStore.getInstance("PKCS11", p);
                ks.load(null, chars(cfg.getPin() != null ? cfg.getPin() : cfg.getPassword()));
                return fromStore(ks, cfg.getAlias(), null, p, cfg.getKeyId(), "PKCS#11 token " + p.getName());
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException("Cannot load the signing key from PKCS#11 (" + cfg.getPkcs11Config() + "): " + e.getMessage(), e);
            }
        }

        static Store fromStore(KeyStore ks, String alias, char[] keyPassword, Provider provider, String keyId, String where)
                throws GeneralSecurityException {
            String a = alias;
            if (a == null || a.isBlank()) {
                List<String> keys = Collections.list(ks.aliases()).stream().filter(x -> {
                    try {
                        return ks.isKeyEntry(x);
                    } catch (GeneralSecurityException e) {
                        return false;
                    }
                }).toList();
                if (keys.size() != 1) {
                    throw new IllegalStateException(where + " holds " + keys.size() + " keys; set trust.service.signing-key.alias");
                }
                a = keys.getFirst();
            }
            Key key = ks.getKey(a, keyPassword);
            Certificate cert = ks.getCertificate(a);
            if (!(key instanceof PrivateKey pk) || cert == null) {
                throw new IllegalStateException(where + " has no private key entry with a certificate under alias " + a);
            }
            if (!(cert.getPublicKey() instanceof ECPublicKey pub) || !"EC".equalsIgnoreCase(pk.getAlgorithm())) {
                throw new IllegalStateException(where + ": the signing key must be EC P-256 for ES256 (alias " + a + " is "
                        + cert.getPublicKey().getAlgorithm() + ")");
            }
            return new Store(pk, publicJwk(pub, keyId, where + " alias " + a), provider, where + " alias " + a);
        }

        @Override
        public JWSSigner signer() {
            try {
                ECDSASigner s = new ECDSASigner(privateKey, Curve.P_256);
                if (provider != null) {
                    s.getJCAContext().setProvider(provider);
                }
                return s;
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }

        private static char[] chars(String s) {
            return s == null ? null : s.toCharArray();
        }
    }
}
