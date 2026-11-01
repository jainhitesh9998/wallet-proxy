package io.vctrust.trust.server.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The service's own ES256 signing key, used for signed responses and offline snapshots. Clients pin its JWK
 * thumbprint. The key comes from a {@link SigningKeySource} (JWK file, keystore or PKCS#11 HSM). Retired public keys
 * stay in the JWKS and in the published thumbprints while clients move to the new key.
 */
public class ServiceKeyManager {

    private static final Logger log = LoggerFactory.getLogger(ServiceKeyManager.class);

    private final SigningKeySource source;
    private final List<ECKey> previous;
    private final String issuer;

    public ServiceKeyManager(SigningKeySource source, List<ECKey> previous, String issuer) {
        this.source = source;
        this.issuer = issuer;
        List<ECKey> p = new ArrayList<>();
        for (ECKey k : previous) {
            if (thumbprint(k).equals(thumbprint(source.publicKey()))) {
                log.warn("Previous signing key {} is the current key; not listed twice", k.getKeyID());
            } else if (p.stream().noneMatch(x -> thumbprint(x).equals(thumbprint(k)))) {
                p.add(k);
            }
        }
        this.previous = List.copyOf(p);
        log.info("Service signing key {} from {}{}", source.publicKey().getKeyID(), source.description(),
                this.previous.isEmpty() ? "" : " (" + this.previous.size() + " previous key(s) still published)");
    }

    /** A generated-on-first-start JWK file (development). */
    public ServiceKeyManager(String keyFile, String issuer) {
        this(SigningKeySource.JwkFile.loadOrGenerate(Path.of(keyFile), null), List.of(), issuer);
    }

    public static ServiceKeyManager fromConfig(TrustProperties.Service cfg) {
        TrustProperties.SigningKey k = cfg.getSigningKey();
        return new ServiceKeyManager(SigningKeySource.fromConfig(k, cfg.getSigningKeyFile()), previousKeys(k.getPreviousKeys()), cfg.getIssuer());
    }

    /** Each entry is inline JWK JSON, a file path, {@code file:} or {@code classpath:}; only the public part is kept. */
    static List<ECKey> previousKeys(List<String> entries) {
        List<ECKey> out = new ArrayList<>();
        for (String e : entries) {
            String json = e.trim();
            try {
                if (!json.startsWith("{")) {
                    json = read(json);
                }
                JWK jwk = JWK.parse(json);
                if (!(jwk instanceof ECKey ec) || !Curve.P_256.equals(ec.getCurve())) {
                    throw new IllegalStateException("trust.service.signing-key.previous-keys: only EC P-256 keys are supported (got "
                            + jwk.getKeyType() + ")");
                }
                ECKey pub = ec.toPublicJWK();
                out.add(pub.getKeyID() != null ? pub : new ECKey.Builder(pub).keyIDFromThumbprint().build());
            } catch (IOException | java.text.ParseException | JOSEException ex) {
                throw new IllegalStateException("trust.service.signing-key.previous-keys: cannot read " + abbreviate(e) + ": " + ex.getMessage(), ex);
            }
        }
        return out;
    }

    private static String read(String location) throws IOException {
        if (location.startsWith("classpath:")) {
            try (InputStream in = ServiceKeyManager.class.getClassLoader().getResourceAsStream(location.substring(10).replaceFirst("^/", ""))) {
                if (in == null) {
                    throw new IOException("not found");
                }
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        Path path = location.startsWith("file:") ? Path.of(URI.create(location)) : Path.of(location);
        return Files.readString(path);
    }

    private static String abbreviate(String s) {
        return s.length() > 60 ? s.substring(0, 57) + "..." : s;
    }

    /** The current key first, then the retired ones. */
    public JWKSet publicJwks() {
        List<JWK> keys = new ArrayList<>();
        keys.add(source.publicKey());
        keys.addAll(previous);
        return new JWKSet(keys);
    }

    public String keyId() {
        return source.publicKey().getKeyID();
    }

    /** RFC 7638 thumbprint of the current key. */
    public String thumbprint() {
        return thumbprint(source.publicKey());
    }

    /** Thumbprints clients may pin: the current key first, then the retired ones. */
    public List<String> thumbprints() {
        List<String> out = new ArrayList<>();
        out.add(thumbprint());
        previous.forEach(k -> out.add(thumbprint(k)));
        return out;
    }

    private static String thumbprint(ECKey k) {
        try {
            return k.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String issuer() {
        return issuer;
    }

    /** Signs {@code claims} as a JWT with {@code iss}, {@code iat} and {@code exp} added. */
    public String sign(String typ, Map<String, Object> claims, Duration ttl, String audience) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(issuer).issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttl)));
            if (audience != null) {
                b.audience(audience);
            }
            claims.forEach(b::claim);
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ))
                    .keyID(keyId()).build(), b.build());
            jwt.sign(source.signer());
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Signing failed", e);
        }
    }
}
