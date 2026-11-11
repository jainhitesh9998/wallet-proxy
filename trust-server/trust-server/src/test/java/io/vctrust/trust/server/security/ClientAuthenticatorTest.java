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
        c.setFrameworks(List.of("fw"));
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

    @Test
    void filterJudgesPathsAsSpringMvcRoutesThem() throws Exception {
        TrustProperties p = props();
        ClientRegistry clients = new ClientRegistry(p);
        ClientAuthenticationFilter filter = new ClientAuthenticationFilter(authenticator(p), clients, null, true);
        // Spellings that reached /admin controllers without credentials when the filter compared raw prefixes.
        for (String path : List.of("/admin;x=y/v1/registry", "/admin;x/v1/clients", "/admin/v1;x/registry", "/api/v1/../../admin/v1/registry",
                "/api/v1/%2e%2e/admin/v1/registry", "/admin%2Fv1/registry", "/admin%2fv1/registry", "/api\\..\\admin/v1/registry",
                "/api/%5c../admin", "//admin/v1/registry", "/admin/./v1/registry", "/api/v1/did/%ZZ", "/api/v1/did/%00")) {
            MockHttpServletResponse r = run(filter, request("GET", path, null));
            assertThat(r.getStatus()).as(path).isEqualTo(400);
            assertThat(Json.parseObject(r.getContentAsString())).as(path).containsEntry("code", "invalid_request");
        }
        assertThat(run(filter, request("PUT", "/admin;x/v1/managed/anchors/a1", "wallet-key")).getStatus()).isEqualTo(400);

        // Decoded spellings are recognised as the admin path they route to.
        assertThat(run(filter, request("GET", "/%61dmin/v1/registry", null)).getStatus()).isEqualTo(401);
        assertThat(run(filter, request("GET", "/%61dmin/v1/registry", "wallet-key")).getStatus()).isEqualTo(403);
        assertThat(passes(filter, request("GET", "/%61dmin/v1/registry", "ops-key"))).isTrue();
        assertThat(run(filter, request("GET", "/ADMIN/v1/registry", "wallet-key")).getStatus()).isEqualTo(403);
        assertThat(run(filter, request("GET", "/admin", "wallet-key")).getStatus()).isEqualTo(403);
        // A forwarded prefix moves the context path, not the path within the application.
        MockHttpServletRequest prefixed = request("GET", "/x/admin/v1/registry", "wallet-key");
        prefixed.setContextPath("/x");
        assertThat(run(filter, prefixed).getStatus()).isEqualTo(403);

        // Public paths need no client; everything else does, including unknown paths and operational endpoints.
        for (String path : List.of("/.well-known/trust-service", "/.well-known/jwks.json", "/actuator/health", "/actuator/health/liveness",
                "/v3/api-docs", "/swagger-ui/index.html")) {
            assertThat(passes(filter, request("GET", path, null))).as(path).isTrue();
        }
        assertThat(run(filter, request("GET", "/actuator/metrics", null)).getStatus()).isEqualTo(401);
        assertThat(run(filter, request("GET", "/actuator/metrics", "wallet-key")).getStatus()).isEqualTo(403);
        assertThat(passes(filter, request("GET", "/actuator/metrics", "ops-key"))).isTrue();
        assertThat(run(filter, request("GET", "/no-such-page", null)).getStatus()).isEqualTo(401);
        assertThat(run(filter, request("GET", "/api/v1/issuers", null)).getStatus()).isEqualTo(401);
        assertThat(passes(filter, request("GET", "/api/v1/did/did:web:example.com%3A8443", "wallet-key"))).isTrue();
        assertThat(passes(filter, request("GET", "/1.0/identifiers/did:web:example.com%253A8443", "wallet-key"))).isTrue();
        assertThat(passes(filter, request("OPTIONS", "/api/v1/issuers", null))).isTrue();
    }

    @Test
    void anonymousRateLimitKeyIgnoresForwardedHeadersExceptFromTrustedProxies() throws Exception {
        TrustProperties p = props();
        p.getAnonymous().setEnabled(true);
        p.getAuth().setTrustedProxies(List.of("10.0.0.0/8"));
        ClientRegistry clients = new ClientRegistry(p);
        ClientAuthenticator auth = authenticator(p);
        ClientAuthenticationFilter filter = new ClientAuthenticationFilter(auth, clients, new RateLimiter(60, 1, () -> 0L), true);

        MockHttpServletRequest first = anonymous("203.0.113.9", null);
        assertThat(run(filter, first).getStatus()).isEqualTo(200);
        // The same caller claiming another address, in the header or through a forwarded-header wrapper: same bucket.
        assertThat(run(filter, anonymous("203.0.113.9", "198.51.100.1")).getStatus()).isEqualTo(429);
        MockHttpServletRequest wrapped = anonymous("203.0.113.9", null);
        HttpServletRequestWrapper spoofed = new HttpServletRequestWrapper(wrapped) {
            @Override
            public String getRemoteAddr() {
                return "198.51.100.2";
            }
        };
        MockHttpServletResponse limited = new MockHttpServletResponse();
        filter.doFilter(spoofed, limited, new MockFilterChain());
        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(auth.clientAddress(spoofed)).isEqualTo("203.0.113.9");

        // Behind a trusted proxy the caller is the entry that proxy appended, not what the caller put in front of it.
        assertThat(auth.clientAddress(anonymous("10.1.1.1", "1.2.3.4, 198.51.100.7"))).isEqualTo("198.51.100.7");
        assertThat(auth.clientAddress(anonymous("10.1.1.1", "198.51.100.7, 10.2.2.2"))).isEqualTo("198.51.100.7");
        assertThat(auth.clientAddress(anonymous("10.1.1.1", null))).isEqualTo("10.1.1.1");
        assertThat(auth.clientAddress(anonymous("10.1.1.1", "unknown"))).isEqualTo("10.1.1.1");
        assertThat(run(filter, anonymous("10.1.1.1", "198.51.100.7")).getStatus()).isEqualTo(200);
        assertThat(run(filter, anonymous("10.1.1.1", "1.2.3.4, 198.51.100.7")).getStatus()).isEqualTo(429);
        assertThat(run(filter, anonymous("10.1.1.1", "198.51.100.8")).getStatus()).isEqualTo(200);
    }

    @Test
    void forwardedForDoesNotMakeAPeerATrustedCertificateProxy() throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(CLIENT_CERT.certificate().getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        MockHttpServletRequest r = anonymous("203.0.113.9", "10.0.0.1");
        r.addHeader("X-SSL-Client-Cert", URLEncoder.encode(pem, StandardCharsets.UTF_8));
        assertThat(rejected(authenticator(props()).authenticate(r)).detail()).isEqualTo("Client authentication required");
    }

    static MockHttpServletRequest request(String method, String uri, String apiKey) {
        MockHttpServletRequest r = new MockHttpServletRequest(method, uri);
        if (apiKey != null) {
            r.addHeader("Authorization", "Bearer " + apiKey);
        }
        return r;
    }

    static MockHttpServletRequest anonymous(String peer, String forwardedFor) {
        MockHttpServletRequest r = new MockHttpServletRequest("GET", "/api/v1/issuers");
        r.setRemoteAddr(peer);
        if (forwardedFor != null) {
            r.addHeader("X-Forwarded-For", forwardedFor);
        }
        return r;
    }

    /** Whether the filter let the request through to the controller. */
    static boolean passes(ClientAuthenticationFilter filter, MockHttpServletRequest request) throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        return chain.getRequest() != null;
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

    @Test
    void nothingIsGrantedByOmission() {
        // A client without frameworks used to see every framework; it is now a configuration error.
        TrustProperties p = new TrustProperties();
        p.getClients().add(client("wallet", c -> { c.setApiKey("k"); c.setFrameworks(List.of()); }));
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> new ClientRegistry(p))).hasMessageContaining("accepts no framework");
        TrustProperties ok = new TrustProperties();
        ok.getClients().add(client("wallet", c -> { c.setApiKey("k"); c.setFrameworks(List.of("*")); }));
        ok.getClients().add(client("ops", c -> { c.setApiKey("o"); c.setFrameworks(List.of()); c.setAdmin(true); }));
        ClientRegistry registry = new ClientRegistry(ok);
        assertThat(registry.byApiKey("k").orElseThrow().accepts("anything")).isTrue();
        assertThat(registry.byApiKey("o").orElseThrow().accepts("anything")).isTrue();
        // Without credentials there is no profile unless the operator enables anonymous access, and then only for the frameworks named.
        assertThat(registry.anonymous()).isEmpty();
        ok.getAnonymous().setEnabled(true);
        ok.getAnonymous().setFrameworks(List.of("public"));
        var anonymous = new ClientRegistry(ok).anonymous().orElseThrow();
        assertThat(anonymous.accepts("public")).isTrue();
        assertThat(anonymous.accepts("fw")).isFalse();
    }
}
