package io.vctrust.trust.server.signing;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.server.config.TrustProperties;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceKeyManagerTest {

    @TempDir
    Path dir;

    static TrustProperties.Service service(TrustProperties.SigningKey k, Path defaultFile) {
        TrustProperties.Service s = new TrustProperties.Service();
        s.setIssuer("https://trust.test");
        s.setSigningKeyFile(defaultFile.toString());
        s.setSigningKey(k);
        return s;
    }

    Path pkcs12(String alias, KeyPair kp, Certificate cert, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(alias, kp.getPrivate(), password.toCharArray(), new Certificate[] {cert});
        Path p = dir.resolve(alias + "-" + System.nanoTime() + ".p12");
        try (OutputStream out = Files.newOutputStream(p)) {
            ks.store(out, password.toCharArray());
        }
        return p;
    }

    @Test
    void jwkFileIsGeneratedOnceAndReloaded() {
        Path file = dir.resolve("keys/signing.jwk");
        ServiceKeyManager first = new ServiceKeyManager(file.toString(), "https://trust.test");
        ServiceKeyManager again = ServiceKeyManager.fromConfig(service(new TrustProperties.SigningKey(), file));
        assertThat(Files.exists(file)).isTrue();
        assertThat(again.thumbprint()).isEqualTo(first.thumbprint());
        assertThat(again.keyId()).isEqualTo(first.thumbprint());
        assertThat(again.thumbprints()).containsExactly(first.thumbprint());
    }

    @Test
    void keystoreKeySignsAndRotationKeepsPreviousKeysPublished() throws Exception {
        TestPki.Issued issued = TestPki.rootCa("CN=Trust service signing,O=Test");
        TrustProperties.SigningKey k = new TrustProperties.SigningKey();
        k.setType("keystore");
        k.setKeystore(pkcs12("snapshot", issued.keys(), issued.certificate(), "changeit").toString());
        k.setPassword("changeit");
        ECKey retiredOne = new ECKeyGenerator(Curve.P_256).keyID("retired-1").generate();
        ECKey retiredTwo = new ECKeyGenerator(Curve.P_256).generate();
        Path retiredFile = dir.resolve("retired-2.jwk");
        Files.writeString(retiredFile, retiredTwo.toJSONString());
        k.setPreviousKeys(List.of(retiredOne.toJSONString(), retiredFile.toString()));

        ServiceKeyManager keys = ServiceKeyManager.fromConfig(service(k, dir.resolve("unused.jwk")));
        assertThat(Files.exists(dir.resolve("unused.jwk"))).isFalse();

        String jwt = keys.sign("trust-snapshot+jwt", Map.of("v", 1), Duration.ofMinutes(5), "wallet");
        SignedJWT parsed = SignedJWT.parse(jwt);
        assertThat(parsed.getHeader().getKeyID()).isEqualTo(keys.keyId());
        ECKey published = (ECKey) keys.publicJwks().getKeyByKeyId(keys.keyId());
        assertThat(parsed.verify(new ECDSAVerifier(published))).isTrue();
        assertThat(published.toECPublicKey()).isEqualTo(issued.keys().getPublic());

        List<JWK> jwks = keys.publicJwks().getKeys();
        assertThat(jwks).hasSize(3).allMatch(j -> !j.isPrivate());
        assertThat(jwks.get(0).getKeyID()).isEqualTo(keys.keyId());
        assertThat(jwks.get(1).getKeyID()).isEqualTo("retired-1");
        assertThat(jwks.get(2).getKeyID()).isEqualTo(retiredTwo.computeThumbprint().toString());
        assertThat(keys.thumbprints()).containsExactly(keys.thumbprint(), retiredOne.computeThumbprint().toString(),
                retiredTwo.computeThumbprint().toString());
    }

    @Test
    void keyIdOverrideAndAliasSelection() throws Exception {
        TestPki.Issued a = TestPki.rootCa("CN=A");
        TestPki.Issued b = TestPki.rootCa("CN=B");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("a", a.keys().getPrivate(), "pw".toCharArray(), new Certificate[] {a.certificate()});
        ks.setKeyEntry("b", b.keys().getPrivate(), "pw".toCharArray(), new Certificate[] {b.certificate()});
        Path p = dir.resolve("two.p12");
        try (OutputStream out = Files.newOutputStream(p)) {
            ks.store(out, "pw".toCharArray());
        }
        TrustProperties.SigningKey k = new TrustProperties.SigningKey();
        k.setType("keystore");
        k.setKeystore(p.toString());
        k.setPassword("pw");
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(k, dir.resolve("x.jwk"))))
                .hasMessageContaining("holds 2 keys; set trust.service.signing-key.alias");
        k.setAlias("b");
        k.setKeyId("service-2026");
        ServiceKeyManager keys = ServiceKeyManager.fromConfig(service(k, dir.resolve("x.jwk")));
        assertThat(keys.keyId()).isEqualTo("service-2026");
        assertThat(((ECKey) keys.publicJwks().getKeys().getFirst()).toECPublicKey()).isEqualTo(b.keys().getPublic());
    }

    @Test
    void wrongKeyTypesFailAtStartup() throws Exception {
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate rsaCert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(new X500Name("CN=RSA"),
                BigInteger.ONE, Date.from(Instant.now().minusSeconds(60)), Date.from(Instant.now().plusSeconds(3600)), new X500Name("CN=RSA"),
                rsa.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(rsa.getPrivate())));
        TrustProperties.SigningKey k = new TrustProperties.SigningKey();
        k.setType("keystore");
        k.setKeystore(pkcs12("rsa", rsa, rsaCert, "pw").toString());
        k.setPassword("pw");
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(k, dir.resolve("x.jwk"))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("must be EC P-256");

        Path rsaJwk = dir.resolve("rsa.jwk");
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();
        Files.writeString(rsaJwk, rsaKey.toJSONString());
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(new TrustProperties.SigningKey(), rsaJwk)))
                .hasMessageContaining("must be a private EC P-256 JWK");

        Path p384 = dir.resolve("p384.jwk");
        Files.writeString(p384, new ECKeyGenerator(Curve.P_384).generate().toJSONString());
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(new TrustProperties.SigningKey(), p384)))
                .hasMessageContaining("P-384");

        TrustProperties.SigningKey prev = new TrustProperties.SigningKey();
        prev.setFile(dir.resolve("ok.jwk").toString());
        prev.setPreviousKeys(List.of(rsaKey.toPublicJWK().toJSONString()));
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(prev, dir.resolve("x.jwk"))))
                .hasMessageContaining("only EC P-256");

        TrustProperties.SigningKey bogus = new TrustProperties.SigningKey();
        bogus.setType("kms");
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(bogus, dir.resolve("x.jwk"))))
                .hasMessageContaining("jwk-file, keystore or pkcs11");

        TrustProperties.SigningKey hsm = new TrustProperties.SigningKey();
        hsm.setType("pkcs11");
        hsm.setPkcs11Config(dir.resolve("missing.cfg").toString());
        assertThatThrownBy(() -> ServiceKeyManager.fromConfig(service(hsm, dir.resolve("x.jwk"))))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("PKCS#11");
    }
}
