package io.vctrust.trust.server.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.config.TrustProperties;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

class ClientAuthenticatorTest {

    static final String AS = "https://as.test";
    static final String SERVICE = "https://trust.test";
    static ECKey asKey;
    static KeyPair edKey;
    static String edKid = "ed-1";
    static final TestPki.Issued CLIENT_CERT = TestPki.rootCa("CN=verifier backend,O=Test");
    static final TestPki.Issued OTHER_CERT = TestPki.rootCa("CN=someone else,O=Test");

    @TempDir
    static Path dir;

    @BeforeAll
    static void keys() throws Exception {
        asKey = new ECKeyGenerator(Curve.P_256).keyID("as-1").generate();
        edKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = edKey.getPublic().getEncoded();
        OctetKeyPair edJwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(Arrays.copyOfRange(spki, spki.length - 32, spki.length)))
                .keyID(edKid).build();
        Files.writeString(dir.resolve("jwks.json"), new JWKSet(List.of(asKey.toPublicJWK(), edJwk)).toString());
    }

    static TrustProperties props() {
        TrustProperties p = new TrustProperties();
        p.getService().setIssuer(SERVICE);
        TrustProperties.OAuth o = p.getAuth().getOauth();
        o.setEnabled(true);
        o.setIssuer(AS);
        o.setJwksUri(dir.resolve("jwks.json").toUri().toString());
        o.setAlgorithms(List.of("ES256", "EdDSA"));
        p.getAuth().getMtls().setEnabled(true);
        p.getAuth().getMtls().setCertificateHeader("X-SSL-Client-Cert");
        p.getAuth().getMtls().setTrustedProxies(List.of("10.0.0.0/8", "::1"));
        p.getAnonymous().setEnabled(false);
        p.getClients().add(client("wallet", c -> c.setApiKey("wallet-key")));
        p.getClients().add(client("verifier", c -> {
            c.setOauthClientId("verifier-at-as");
            c.setCertificateSha256(List.of(thumbprintB64(CLIENT_CERT.certificate())));
        }));
        p.getClients().add(client("ops", c -> {
            c.setApiKeySha256(HexFormat.of().formatHex(Hashes.sha256("ops-key".getBytes(StandardCharsets.UTF_8))));
            c.setAdmin(true);
        }));
        return p;
    }

    static TrustProperties.Client client(String id, java.util.function.Consumer<TrustProperties.Client> f) {
        TrustProperties.Client c = new TrustProperties.Client();
        c.setId(id);
        f.accept(c);
        return c;
    }

    static ClientAuthenticator authenticator(TrustProperties p) {
        return new ClientAuthenticator(new ClientRegistry(p), p.getAuth(), new AccessTokenVerifier(p.getAuth().getOauth(), SERVICE));
    }

    static String thumbprintB64(X509Certificate c) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(Hashes.sha256(c.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static JWTClaimsSet.Builder claims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder().issuer(AS).audience(SERVICE).subject("verifier-at-as").claim("client_id", "verifier-at-as")
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plus(Duration.ofMinutes(5)))).jwtID("j1");
    }

    static String token(JWTClaimsSet c) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("at+jwt")).keyID("as-1").build(), c);
        jwt.sign(new ECDSASigner(asKey));
        return jwt.serialize();
    }

    static MockHttpServletRequest bearer(String value) {
        MockHttpServletRequest r = new MockHttpServletRequest("GET", "/api/v1/issuers");
        r.addHeader("Authorization", "Bearer " + value);
        return r;
    }

    static ClientAuthenticator.Rejected rejected(ClientAuthenticator.Result r) {
        assertThat(r).isInstanceOf(ClientAuthenticator.Rejected.class);
        return (ClientAuthenticator.Rejected) r;
    }

    static ClientAuthenticator.Authenticated ok(ClientAuthenticator.Result r) {
        assertThat(r).isInstanceOf(ClientAuthenticator.Authenticated.class);
        return (ClientAuthenticator.Authenticated) r;
    }

    @Test
    void accessTokenAuthenticatesTheMappedClient() throws Exception {
        var a = ok(authenticator(props()).authenticate(bearer(token(claims().build()))));
        assertThat(a.client().clientId()).isEqualTo("verifier");
        assertThat(a.method()).isEqualTo("oauth2_jwt");
    }

    @Test
    void edDsaTokensVerifyThroughTheJdk() throws Exception {
        String header = Base64URL.encode(Json.write(Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", edKid))).toString();
        String payload = Base64URL.encode(claims().build().toString()).toString();
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(edKey.getPrivate());
        s.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        String jwt = header + "." + payload + "." + Base64URL.encode(s.sign());
        assertThat(ok(authenticator(props()).authenticate(bearer(jwt))).client().clientId()).isEqualTo("verifier");
        String tampered = header + "." + Base64URL.encode(claims().claim("client_id", "wallet").build().toString()) + "." + jwt.split("\\.")[2];
        assertThat(rejected(authenticator(props()).authenticate(bearer(tampered))).bearerError()).isEqualTo("invalid_token");
    }

    @Test
    void tokensAreCheckedForAudienceExpiryIssuerTypeAndClient() throws Exception {
        ClientAuthenticator auth = authenticator(props());
        var wrongAud = rejected(auth.authenticate(bearer(token(claims().audience("https://elsewhere.test").build()))));
        assertThat(wrongAud.status()).isEqualTo(401);
        assertThat(wrongAud.bearerError()).isEqualTo("invalid_token");
        assertThat(wrongAud.detail()).containsIgnoringCase("aud");

        Instant past = Instant.now().minus(Duration.ofHours(1));
        var expired = rejected(auth.authenticate(bearer(token(claims().expirationTime(Date.from(past)).build()))));
        assertThat(expired.detail()).containsIgnoringCase("expired");

        assertThat(rejected(auth.authenticate(bearer(token(claims().issuer("https://rogue.test").build())))).status()).isEqualTo(401);

        var unknown = rejected(auth.authenticate(bearer(token(claims().claim("client_id", "stranger").build()))));
        assertThat(unknown.detail()).contains("stranger");

        SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("id_token+jwt")).keyID("as-1").build(),
                claims().build());
        idToken.sign(new ECDSASigner(asKey));
        assertThat(rejected(auth.authenticate(bearer(idToken.serialize()))).detail()).contains("not accepted");

        ECKey rogue = new ECKeyGenerator(Curve.P_256).keyID("as-1").generate();
        SignedJWT forged = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("as-1").build(), claims().build());
        forged.sign(new ECDSASigner(rogue));
        assertThat(rejected(auth.authenticate(bearer(forged.serialize()))).bearerError()).isEqualTo("invalid_token");
    }

    @Test
    void requiredScopeIsEnforced() throws Exception {
        TrustProperties p = props();
        p.getAuth().getOauth().setRequiredScope("trust.read");
        ClientAuthenticator auth = authenticator(p);
        var missing = rejected(auth.authenticate(bearer(token(claims().claim("scope", "openid profile").build()))));
        assertThat(missing.status()).isEqualTo(403);
        assertThat(missing.bearerError()).isEqualTo("insufficient_scope");
        ok(auth.authenticate(bearer(token(claims().claim("scope", "openid trust.read").build()))));
        ok(auth.authenticate(bearer(token(claims().claim("scp", List.of("trust.read")).build()))));
    }

    @Test
    void certificateBoundTokensNeedThatCertificate() throws Exception {
        ClientAuthenticator auth = authenticator(props());
        String bound = token(claims().claim("cnf", Map.of("x5t#S256", thumbprintB64(CLIENT_CERT.certificate()))).build());
        assertThat(rejected(auth.authenticate(bearer(bound))).detail()).contains("none was presented");

        MockHttpServletRequest wrongCert = bearer(bound);
        wrongCert.setAttribute(ClientAuthenticator.CERT_ATTRIBUTE, new X509Certificate[] {OTHER_CERT.certificate()});
        assertThat(rejected(auth.authenticate(wrongCert)).detail()).contains("different client certificate");

        MockHttpServletRequest rightCert = bearer(bound);
        rightCert.setAttribute(ClientAuthenticator.CERT_ATTRIBUTE, new X509Certificate[] {CLIENT_CERT.certificate()});
        assertThat(ok(auth.authenticate(rightCert)).client().clientId()).isEqualTo("verifier");
    }

    @Test
    void tlsClientCertificateAuthenticatesByThumbprint() {
        ClientAuthenticator auth = authenticator(props());
        MockHttpServletRequest r = new MockHttpServletRequest("GET", "/api/v1/issuers");
        r.setAttribute(ClientAuthenticator.CERT_ATTRIBUTE, new X509Certificate[] {CLIENT_CERT.certificate()});
        var a = ok(auth.authenticate(r));
        assertThat(a.client().clientId()).isEqualTo("verifier");
        assertThat(a.method()).isEqualTo("mtls");

        MockHttpServletRequest other = new MockHttpServletRequest("GET", "/api/v1/issuers");
        other.setAttribute(ClientAuthenticator.CERT_ATTRIBUTE, new X509Certificate[] {OTHER_CERT.certificate()});
        assertThat(rejected(auth.authenticate(other)).detail()).isEqualTo("Unknown client certificate");
    }

    @Test
    void proxyCertificateHeaderIsBelievedOnlyFromTrustedPeers() throws Exception {
        ClientAuthenticator auth = authenticator(props());
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(CLIENT_CERT.certificate().getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        String header = URLEncoder.encode(pem, StandardCharsets.UTF_8).replace("+", "%20");

        MockHttpServletRequest fromProxy = new MockHttpServletRequest("GET", "/api/v1/issuers");
        fromProxy.setRemoteAddr("10.1.2.3");
        fromProxy.addHeader("X-SSL-Client-Cert", header);
        assertThat(ok(auth.authenticate(fromProxy)).client().clientId()).isEqualTo("verifier");

        MockHttpServletRequest direct = new MockHttpServletRequest("GET", "/api/v1/issuers");
        direct.setRemoteAddr("203.0.113.9");
        direct.addHeader("X-SSL-Client-Cert", header);
        assertThat(rejected(auth.authenticate(direct)).detail()).isEqualTo("Client authentication required");

        // A forwarded-header wrapper reporting a trusted address does not make the real peer trusted.
        HttpServletRequestWrapper spoofed = new HttpServletRequestWrapper(direct) {
            @Override
            public String getRemoteAddr() {
                return "10.0.0.1";
            }
        };
        assertThat(auth.authenticate(spoofed)).isInstanceOf(ClientAuthenticator.Rejected.class);
    }

    @Test
    void apiKeysInClearOrHashedAndTheirSwitch() {
        TrustProperties p = props();
        assertThat(ok(authenticator(p).authenticate(bearer("wallet-key"))).client().clientId()).isEqualTo("wallet");
        MockHttpServletRequest header = new MockHttpServletRequest("GET", "/admin/v1/sources");
        header.addHeader("X-API-Key", "ops-key");
        assertThat(ok(authenticator(p).authenticate(header)).client().admin()).isTrue();
        assertThat(rejected(authenticator(p).authenticate(bearer("nope"))).detail()).isEqualTo("Unknown API key");

        p.getAuth().setApiKeys(false);
        p.getClients().removeIf(c -> !c.getId().equals("verifier"));
        assertThat(rejected(authenticator(p).authenticate(bearer("wallet-key"))).bearerError()).isEqualTo("invalid_token");
    }

    @Test
    void filterAnswersWithProblemDetailsAndRateLimits() throws Exception {
        TrustProperties p = props();
        ClientRegistry clients = new ClientRegistry(p);
        AtomicLong now = new AtomicLong();
        ClientAuthenticationFilter filter = new ClientAuthenticationFilter(
                new ClientAuthenticator(clients, p.getAuth(), new AccessTokenVerifier(p.getAuth().getOauth(), SERVICE)),
                clients, new RateLimiter(60, 2, now::get), true);

        MockHttpServletResponse denied = run(filter, bearer(token(claims().audience("https://elsewhere.test").build())));
        assertThat(denied.getStatus()).isEqualTo(401);
        assertThat(denied.getContentType()).isEqualTo("application/problem+json");
        assertThat(denied.getHeader("WWW-Authenticate")).startsWith("Bearer realm=\"vc-trust-service\", error=\"invalid_token\"");
        assertThat(Json.parseObject(denied.getContentAsString())).containsEntry("code", "invalid_token");

        assertThat(run(filter, bearer("wallet-key")).getStatus()).isEqualTo(200);
        assertThat(run(filter, bearer("wallet-key")).getStatus()).isEqualTo(200);
        MockHttpServletResponse limited = run(filter, bearer("wallet-key"));
        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getHeader("Retry-After")).isEqualTo("1");
        assertThat(Json.parseObject(limited.getContentAsString())).containsEntry("code", "rate_limited");
        now.addAndGet(Duration.ofSeconds(1).toNanos());
        assertThat(run(filter, bearer("wallet-key")).getStatus()).isEqualTo(200);

        // Another client has its own bucket; admins are exempt.
        assertThat(run(filter, bearer(token(claims().build()))).getStatus()).isEqualTo(200);
        MockHttpServletRequest admin = bearer("ops-key");
        admin.setRequestURI("/admin/v1/sources");
        for (int i = 0; i < 5; i++) {
            assertThat(run(filter, admin).getStatus()).isEqualTo(200);
        }
        MockHttpServletRequest notAdmin = bearer("wallet-key");
        notAdmin.setRequestURI("/admin/v1/sources");
        now.addAndGet(Duration.ofSeconds(5).toNanos());
        assertThat(run(filter, notAdmin).getStatus()).isEqualTo(403);
    }

    static MockHttpServletResponse run(ClientAuthenticationFilter filter, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void registryRejectsClientsWithoutCredentialsAndDuplicates() {
        TrustProperties p = new TrustProperties();
        p.getClients().add(client("bare", c -> { }));
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> new ClientRegistry(p))).hasMessageContaining("no usable credential");
        TrustProperties dup = new TrustProperties();
        dup.getClients().add(client("a", c -> c.setApiKey("same")));
        dup.getClients().add(client("b", c -> c.setApiKey("same")));
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> new ClientRegistry(dup))).hasMessageContaining("share the same API key");
    }
}
