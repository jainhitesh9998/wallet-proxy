package io.vctrust.trust.server;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.server.config.SourceBootstrap;
import io.vctrust.trust.server.service.CrlService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustServerIntegrationTest {

    static final TestPki.Issued IACA = TestPki.rootCa("CN=Test IACA,C=UT");
    static final TestPki.Issued DS = TestPki.documentSigner("CN=Test DS,C=UT", IACA);
    static final TestPki.Issued ROGUE_IACA = TestPki.rootCa("CN=Rogue IACA,C=UT");
    static final TestPki.Issued ROGUE_DS = TestPki.documentSigner("CN=Rogue DS,C=UT", ROGUE_IACA);
    static final TestPki.Issued REVOKED_DS = TestPki.documentSigner("CN=Revoked DS,C=UT", IACA);
    static final TestPki.Issued PUSHED_IACA = TestPki.rootCa("CN=Pushed IACA,C=UT");
    static final com.nimbusds.jose.jwk.ECKey AS_KEY;
    static final HttpServer UPSTREAM;
    static final String UPSTREAM_BASE;
    static Path dataDir;

    static {
        try {
            AS_KEY = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("as-key").generate();
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new IllegalStateException(e);
        }
        try {
            UPSTREAM = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            UPSTREAM_BASE = "http://localhost:" + UPSTREAM.getAddress().getPort();
            route("/.well-known/openid-credential-issuer/issuer", """
                    {"credential_issuer":"%s/issuer","credential_endpoint":"%s/issuer/credential",
                     "authorization_servers":["%s/as"],
                     "display":[{"name":"Test Issuer","locale":"en"}],
                     "credential_configurations_supported":{"mdl":{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}}}"""
                    .formatted(UPSTREAM_BASE, UPSTREAM_BASE, UPSTREAM_BASE));
            route("/.well-known/oauth-authorization-server/as", "{\"issuer\":\"%s/as\",\"grant_types_supported\":[\"authorization_code\"]}".formatted(UPSTREAM_BASE));
            route("/.well-known/openid-credential-issuer/other", """
                    {"credential_issuer":"%s/other","credential_endpoint":"%s/other/credential",
                     "credential_configurations_supported":{}}""".formatted(UPSTREAM_BASE, UPSTREAM_BASE));
            route("/.well-known/openid-credential-issuer/liar", """
                    {"credential_issuer":"https://elsewhere.example","credential_endpoint":"x","credential_configurations_supported":{}}""");
            raw("/crl/iaca.crl", "application/pkix-crl", TestPki.crl(IACA, TestPki.Revoked.of(REVOKED_DS, 1)).getEncoded());
            raw("/status/token", "application/statuslist+jwt", "eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6e319.c2ln".getBytes(StandardCharsets.UTF_8));
            raw("/status/page", "text/html", "<html></html>".getBytes(StandardCharsets.UTF_8));
            UPSTREAM.start();
        } catch (IOException | java.security.cert.CRLException e) {
            throw new IllegalStateException(e);
        }
    }

    static void raw(String path, String type, byte[] body) {
        UPSTREAM.createContext(path, ex -> {
            ex.getResponseHeaders().add("Content-Type", type);
            ex.getResponseHeaders().add("Cache-Control", "max-age=60");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
    }

    static void route(String path, String json) {
        UPSTREAM.createContext(path, ex -> {
            byte[] b = json.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.getResponseHeaders().add("Cache-Control", "max-age=120");
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
    }

    @AfterAll
    static void stop() {
        UPSTREAM.stop(0);
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        dataDir = Files.createTempDirectory("trust-it");
        Path registry = dataDir.resolve("registry.yaml");
        Files.writeString(registry, """
                entities:
                  - id: test-issuer
                    framework: fw-a
                    roles: [CREDENTIAL_ISSUER]
                    name: Test Issuer
                    identifiers:
                      - {type: URL, value: "%s/issuer"}
                    authorizations:
                      - {format: mso_mdoc, type: org.iso.18013.5.1.mDL}
                    metadataPolicy:
                      oauth_authorization_server:
                        grant_types_supported: {add: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]}
                        token_endpoint: {default: "%s/issuer/token"}
                  - id: b-issuer
                    framework: fw-b
                    roles: [CREDENTIAL_ISSUER]
                    identifiers: [did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK]
                  - id: revoked-issuer
                    framework: fw-a
                    roles: [CREDENTIAL_ISSUER]
                    status: REVOKED
                    identifiers: [{type: URL, value: "https://revoked.example"}]
                anchors:
                  - domain: mdoc-iaca
                    framework: fw-a
                    entity: test-issuer
                    constraints:
                      crlUrls: ["%s/crl/iaca.crl"]
                    certificate: |
                %s
                """.formatted(UPSTREAM_BASE, UPSTREAM_BASE, UPSTREAM_BASE, Certificates.toPem(IACA.certificate()).indent(6)));
        r.add("spring.datasource.url", () -> "jdbc:h2:mem:trust-it;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        r.add("trust.service.signing-key-file", () -> dataDir.resolve("key.jwk").toString());
        r.add("trust.service.issuer", () -> "https://trust.test");
        r.add("trust.http.allow-private-networks", () -> "true");
        r.add("trust.http.http-allowed-hosts[0]", () -> "localhost");
        r.add("trust.did.universal-resolver-url", () -> "");
        r.add("trust.frameworks[0].id", () -> "fw-a");
        r.add("trust.frameworks[1].id", () -> "fw-b");
        r.add("trust.frameworks[1].attributes.recognizes", () -> "fw-a");
        r.add("trust.frameworks[2].id", () -> "local");
        r.add("trust.sources[0].id", () -> "reg");
        r.add("trust.sources[0].type", () -> "static");
        r.add("trust.sources[0].properties.location", () -> registry.toUri().toString());
        r.add("trust.sources[1].id", () -> "managed");
        r.add("trust.sources[1].type", () -> "managed");
        r.add("trust.sources[1].framework", () -> "local");
        r.add("trust.clients[0].id", () -> "wallet-a");
        r.add("trust.clients[0].api-key", () -> "key-a");
        r.add("trust.clients[0].frameworks[0]", () -> "fw-a");
        r.add("trust.clients[0].frameworks[1]", () -> "local");
        r.add("trust.clients[1].id", () -> "verifier-strict");
        r.add("trust.clients[1].api-key", () -> "key-strict");
        r.add("trust.clients[1].frameworks[0]", () -> "fw-a");
        r.add("trust.clients[1].allow-unregistered-metadata", () -> "false");
        r.add("trust.clients[1].require-revocation-status", () -> "true");
        r.add("trust.clients[2].id", () -> "admin");
        r.add("trust.clients[2].api-key", () -> "key-admin");
        r.add("trust.clients[2].admin", () -> "true");
        r.add("trust.anonymous.enabled", () -> "false");
        Path jwks = dataDir.resolve("as-jwks.json");
        Files.writeString(jwks, new JWKSet(AS_KEY.toPublicJWK()).toString());
        r.add("trust.auth.oauth.enabled", () -> "true");
        r.add("trust.auth.oauth.issuer", () -> "https://as.trust.test");
        r.add("trust.auth.oauth.jwks-uri", () -> jwks.toUri().toString());
        r.add("trust.service.snapshot-ttl", () -> "PT4S");
    }

    @Autowired
    Environment env;
    @Autowired
    SourceBootstrap bootstrap;
    @Autowired
    CrlService crls;

    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void awaitReady() throws InterruptedException {
        for (int i = 0; i < 100 && !bootstrap.isReady(); i++) {
            Thread.sleep(50);
        }
        assertThat(bootstrap.isReady()).isTrue();
        // Anchor CRLs load in the background after the registry; wait so snapshots are stable during tests.
        for (int i = 0; i < 100 && crls.heldFor(IACA.certificate()).isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(crls.heldFor(IACA.certificate())).isNotEmpty();
    }

    HttpResponse<byte[]> getBytes(String path, String key, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path)).GET().header("Authorization", "Bearer " + key);
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    String base() {
        return "http://localhost:" + env.getProperty("local.server.port");
    }

    HttpResponse<String> get(String path, String key, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path)).GET();
        if (key != null) b.header("Authorization", "Bearer " + key);
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> post(String path, String key, Object body, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path))
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).header("Content-Type", "application/json");
        if (key != null) b.header("Authorization", "Bearer " + key);
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> put(String path, String key, Object body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base() + path)).PUT(HttpRequest.BodyPublishers.ofString(Json.write(body)))
                .header("Content-Type", "application/json").header("Authorization", "Bearer " + key).build(), HttpResponse.BodyHandlers.ofString());
    }

    static Map<String, Object> json(HttpResponse<String> r) {
        return Json.parseObject(r.body());
    }

    @Test
    void discoveryAndAuthentication() throws Exception {
        var d = json(get("/.well-known/trust-service", null));
        assertThat(d.get("issuer")).isEqualTo("https://trust.test");
        assertThat(((Map<?, ?>) d.get("endpoints")).get("evaluate")).isEqualTo("https://trust.test/api/v1/evaluate");
        assertThat(get("/api/v1/issuers", null).statusCode()).isEqualTo(401);
        assertThat(get("/api/v1/issuers", "wrong").statusCode()).isEqualTo(401);
        assertThat(get("/admin/v1/sources", "key-a").statusCode()).isEqualTo(403);
        assertThat(get("/admin/v1/sources", "key-admin").statusCode()).isEqualTo(200);
    }

    @Test
    @SuppressWarnings("unchecked")
    void issuersAreFilteredByClientFrameworks() throws Exception {
        var page = json(get("/api/v1/issuers", "key-a"));
        List<Map<String, Object>> items = (List<Map<String, Object>>) page.get("items");
        assertThat(items).extracting(m -> m.get("id")).containsExactlyInAnyOrder("test-issuer", "revoked-issuer");
        var all = json(get("/api/v1/issuers", "key-admin"));
        assertThat((List<?>) all.get("items")).hasSize(3);
        var mdl = json(get("/api/v1/issuers?format=mso_mdoc&type=org.iso.18013.5.1.mDL", "key-a"));
        assertThat((List<?>) mdl.get("items")).hasSize(1);
        var r = get("/api/v1/issuers", "key-a");
        String etag = r.headers().firstValue("ETag").orElseThrow();
        assertThat(get("/api/v1/issuers", "key-a", "If-None-Match", etag).statusCode()).isEqualTo(304);
    }

    @Test
    @SuppressWarnings("unchecked")
    void metadataProxyAppliesPolicyAndAttachesDecision() throws Exception {
        var r = get("/api/v1/issuers/metadata?credential_issuer=" + UPSTREAM_BASE + "/issuer", "key-a");
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.headers().firstValue("X-Trust-Decision")).contains("TRUSTED");
        var env = json(r);
        assertThat(env.get("policyApplied")).isEqualTo(true);
        var as = (Map<String, Object>) ((Map<String, Object>) env.get("authorizationServers")).get(UPSTREAM_BASE + "/as");
        assertThat(as.get("token_endpoint")).isEqualTo(UPSTREAM_BASE + "/issuer/token");
        assertThat((List<String>) as.get("grant_types_supported")).contains("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        // unregistered issuer: UNKNOWN for permissive client, 403 for strict client
        var other = json(get("/api/v1/issuers/metadata?credential_issuer=" + UPSTREAM_BASE + "/other", "key-a"));
        assertThat(((Map<String, Object>) other.get("trust")).get("decision")).isEqualTo("UNKNOWN");
        assertThat(get("/api/v1/issuers/metadata?credential_issuer=" + UPSTREAM_BASE + "/other", "key-strict").statusCode()).isEqualTo(403);
        // credential_issuer mismatch is rejected
        var liar = get("/api/v1/issuers/metadata?credential_issuer=" + UPSTREAM_BASE + "/liar", "key-a");
        assertThat(liar.statusCode()).isEqualTo(422);
        assertThat(json(liar).get("code")).isEqualTo("issuer_mismatch");
    }

    @Test
    @SuppressWarnings("unchecked")
    void evaluateDecisionsAndSignedResponses() throws Exception {
        var trusted = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(Certificates.toBase64(DS.certificate()))),
                "context", Map.of("credentialFormat", "mso_mdoc", "credentialType", "org.iso.18013.5.1.mDL"))));
        assertThat(trusted.get("decision")).isEqualTo("TRUSTED");
        assertThat(((Map<String, Object>) trusted.get("entity")).get("id")).isEqualTo("test-issuer");

        var unknown = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(Certificates.toBase64(ROGUE_DS.certificate()))),
                "context", Map.of("credentialFormat", "mso_mdoc"))));
        assertThat(unknown.get("decision")).isEqualTo("UNKNOWN");

        var revoked = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer", "subject", Map.of("identifier", "https://revoked.example"))));
        assertThat(revoked.get("decision")).isEqualTo("NOT_TRUSTED");

        // other framework invisible to wallet-a
        var hidden = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("identifier", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"))));
        assertThat(hidden.get("decision")).isEqualTo("UNKNOWN");

        // signed response verifies with the published JWKS and is audience-bound
        var signed = post("/api/v1/evaluate", "key-a", Map.of("role", "issuer", "subject", Map.of("identifier", "https://revoked.example")),
                "Accept", "application/jwt");
        assertThat(signed.headers().firstValue("Content-Type").orElse("")).startsWith("application/jwt");
        SignedJWT jwt = SignedJWT.parse(signed.body());
        ECKey key = (ECKey) JWKSet.parse(get("/.well-known/jwks.json", null).body()).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new ECDSAVerifier(key))).isTrue();
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("trust-decision+jwt");
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("wallet-a");
        assertThat(((Map<String, Object>) jwt.getJWTClaimsSet().getClaim("data")).get("decision")).isEqualTo("NOT_TRUSTED");

        var batch = json(post("/api/v1/evaluate/batch", "key-a", Map.of("queries", List.of(
                Map.of("role", "issuer", "subject", Map.of("identifier", UPSTREAM_BASE + "/issuer")),
                Map.of("role", "issuer", "subject", Map.of("identifier", "https://nobody.example"))))));
        assertThat((List<Map<String, Object>>) batch.get("decisions")).extracting(m -> m.get("decision")).containsExactly("TRUSTED", "UNKNOWN");
    }

    @Test
    @SuppressWarnings("unchecked")
    void x509ValidateAndAnchors() throws Exception {
        var ok = json(post("/api/v1/x509/validate", "key-a", Map.of("chain", List.of(Certificates.toBase64(DS.certificate())),
                "domain", "mdoc-iaca", "docType", "org.iso.18013.5.1.mDL")));
        assertThat(((Map<String, Object>) ok.get("result")).get("valid")).isEqualTo(true);
        assertThat(((Map<String, Object>) ok.get("entity")).get("id")).isEqualTo("test-issuer");
        var bad = json(post("/api/v1/x509/validate", "key-a", Map.of("chain", List.of(Certificates.toBase64(ROGUE_DS.certificate())), "domain", "mdoc-iaca")));
        assertThat(((Map<String, Object>) bad.get("result")).get("valid")).isEqualTo(false);
        var pem = get("/api/v1/x509/anchors?domain=mdoc-iaca&format=pem", "key-a");
        assertThat(pem.body()).contains("BEGIN CERTIFICATE");
    }

    @Test
    @SuppressWarnings("unchecked")
    void didResolutionBindings() throws Exception {
        var r = json(get("/api/v1/did/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "key-a"));
        assertThat(((Map<String, Object>) r.get("didDocument")).get("id")).isEqualTo("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        var docOnly = get("/1.0/identifiers/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "key-a", "Accept", "application/did+ld+json");
        assertThat(json(docOnly)).containsKey("verificationMethod").doesNotContainKey("didDocument");
        var unsupported = get("/1.0/identifiers/did:example:123", "key-a");
        assertThat(unsupported.statusCode()).isEqualTo(501);
        assertThat(get("/1.0/identifiers/not-a-did", "key-a").statusCode()).isEqualTo(400);
    }

    @Test
    @SuppressWarnings("unchecked")
    void snapshotIsSignedScopedAndConditional() throws Exception {
        var r = get("/api/v1/snapshot", "key-a");
        SignedJWT jwt = SignedJWT.parse(r.body());
        ECKey key = (ECKey) JWKSet.parse(get("/.well-known/jwks.json", null).body()).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(jwt.verify(new ECDSAVerifier(key))).isTrue();
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("trust-snapshot+jwt");
        List<?> entities = (List<?>) jwt.getJWTClaimsSet().getClaim("entities");
        List<?> anchors = (List<?>) jwt.getJWTClaimsSet().getClaim("anchors");
        assertThat(entities).hasSize(2);
        assertThat(anchors).hasSize(1);
        String etag = r.headers().firstValue("ETag").orElseThrow();
        assertThat(get("/api/v1/snapshot", "key-a", "If-None-Match", etag).statusCode()).isEqualTo(304);

        // Everything a client needs to evaluate locally: its policy, anchor provenance, metadata policy.
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIntegerClaim("format")).isEqualTo(3);
        Map<String, Object> policy = claims.getJSONObjectClaim("policy");
        assertThat(policy).containsEntry("strictAuthorization", false);
        assertThat((List<Object>) policy.get("frameworks")).containsExactlyInAnyOrder("fw-a", "local");
        assertThat(((Map<String, Object>) anchors.getFirst()).get("provenance")).isInstanceOf(Map.class);
        Map<String, Object> issuer = entities.stream().map(e -> (Map<String, Object>) e)
                .filter(e -> "test-issuer".equals(e.get("id"))).findFirst().orElseThrow();
        assertThat(issuer.get("metadataPolicy")).isInstanceOf(Map.class);

        // DID documents of registered DID identifiers are embedded (admin sees every framework, incl. b-issuer).
        Map<String, Object> docs = SignedJWT.parse(get("/api/v1/snapshot", "key-admin").body()).getJWTClaimsSet().getJSONObjectClaim("didDocuments");
        assertThat(docs).containsKey("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

        // Re-signed after half its lifetime: a polling client gets a fresh snapshot, never keeps an expired one.
        Thread.sleep(2_100);
        var renewed = get("/api/v1/snapshot", "key-a", "If-None-Match", etag);
        assertThat(renewed.statusCode()).isEqualTo(200);
        assertThat(renewed.headers().firstValue("ETag").orElseThrow()).isNotEqualTo(etag);
        assertThat(SignedJWT.parse(renewed.body()).getJWTClaimsSet().getExpirationTime()).isAfter(claims.getExpirationTime());
    }

    @Test
    @SuppressWarnings("unchecked")
    void certificateRevocationFromAnchorCrls() throws Exception {
        String crlUrl = UPSTREAM_BASE + "/crl/iaca.crl";
        // The anchor's CRL ships in the snapshot, with the client's revocation policy.
        var claims = SignedJWT.parse(get("/api/v1/snapshot", "key-a").body()).getJWTClaimsSet();
        List<Map<String, Object>> crlClaims = (List<Map<String, Object>>) claims.getClaim("crls");
        assertThat(crlClaims).singleElement().satisfies(c -> {
            assertThat(c.get("issuer")).isEqualTo(Certificates.sha256Thumbprint(IACA.certificate()));
            assertThat(c.get("url")).isEqualTo(crlUrl);
            assertThat(c).containsKeys("thisUpdate", "nextUpdate", "crlNumber");
            var crl = RevocationChecker.Crl.parse(Base64.getDecoder().decode((String) c.get("crl")), crlUrl, Instant.now());
            assertThat(crl.issuedBy(IACA.certificate())).isTrue();
        });
        assertThat(claims.getJSONObjectClaim("policy")).containsEntry("requireRevocationStatus", false);
        assertThat(SignedJWT.parse(get("/api/v1/snapshot", "key-strict").body()).getJWTClaimsSet().getJSONObjectClaim("policy"))
                .containsEntry("requireRevocationStatus", true);

        // Server-side decisions apply the same CRL.
        var mdl = Map.of("credentialFormat", "mso_mdoc", "credentialType", "org.iso.18013.5.1.mDL");
        var revoked = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(Certificates.toBase64(REVOKED_DS.certificate()))), "context", mdl)));
        assertThat(revoked.get("decision")).isEqualTo("NOT_TRUSTED");
        assertThat((List<Map<String, Object>>) revoked.get("reasons")).extracting(m -> m.get("code")).contains("x509.revoked");
        var x509 = (Map<String, Object>) ((Map<String, Object>) revoked.get("evidence")).get("x509");
        assertThat((List<Map<String, Object>>) x509.get("revocation")).singleElement().satisfies(r -> {
            assertThat(r.get("status")).isEqualTo("REVOKED");
            assertThat(r.get("reason")).isEqualTo("keyCompromise");
            assertThat(r.get("method")).isEqualTo("crl");
            assertThat(r.get("source")).isEqualTo("trust-service");
        });
        var good = json(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(Certificates.toBase64(DS.certificate()))), "context", mdl)));
        assertThat(good.get("decision")).isEqualTo("TRUSTED");
        var goodX509 = (Map<String, Object>) ((Map<String, Object>) good.get("evidence")).get("x509");
        assertThat((List<Map<String, Object>>) goodX509.get("revocation")).extracting(m -> m.get("status")).containsExactly("GOOD");

        // Operator listing.
        List<Map<String, Object>> listing = Json.MAPPER.readValue(get("/api/v1/revocation/crls", "key-a").body(), List.class);
        assertThat(listing).singleElement().satisfies(m -> {
            assertThat(m.get("url")).isEqualTo(crlUrl);
            assertThat(m.get("revoked")).isEqualTo(1);
        });

        // A CRL pushed with a managed anchor: verified, held, and never echoed in anchor views.
        String pem = "-----BEGIN X509 CRL-----\n" + Base64.getMimeEncoder().encodeToString(TestPki.crl(PUSHED_IACA).getEncoded())
                + "\n-----END X509 CRL-----\n";
        assertThat(put("/admin/v1/managed/anchors/pushed-iaca", "key-admin", Map.of("domain", "mdoc-iaca",
                "certificate", Certificates.toPem(PUSHED_IACA.certificate()), "constraints", Map.of("crl", pem))).statusCode()).isEqualTo(200);
        for (int i = 0; i < 100 && crls.heldFor(PUSHED_IACA.certificate()).isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(crls.heldFor(PUSHED_IACA.certificate())).singleElement().satisfies(c -> assertThat(c.url()).isNull());
        assertThat(get("/api/v1/x509/anchors?domain=mdoc-iaca", "key-a").body()).contains("Pushed IACA").doesNotContain("X509 CRL");
        var snapAnchors = (List<Map<String, Object>>) SignedJWT.parse(get("/api/v1/snapshot", "key-a").body()).getJWTClaimsSet().getClaim("anchors");
        assertThat(snapAnchors).allSatisfy(a -> assertThat((Map<String, Object>) a.get("constraints")).doesNotContainKey("crl"));
        http.send(HttpRequest.newBuilder(URI.create(base() + "/admin/v1/managed/anchors/pushed-iaca")).DELETE()
                .header("Authorization", "Bearer key-admin").build(), HttpResponse.BodyHandlers.discarding());
        for (int i = 0; i < 100 && !crls.heldFor(PUSHED_IACA.certificate()).isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(crls.heldFor(PUSHED_IACA.certificate())).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void crlAndStatusListRelays() throws Exception {
        var crl = getBytes("/api/v1/revocation/crl?url=" + UPSTREAM_BASE + "/crl/iaca.crl", "key-a", "Accept", "application/pkix-crl");
        assertThat(crl.statusCode()).isEqualTo(200);
        assertThat(crl.headers().firstValue("Content-Type")).contains("application/pkix-crl");
        assertThat(crl.headers().firstValue("Cache-Control").orElse("")).contains("max-age=");
        assertThat(RevocationChecker.Crl.parse(crl.body(), null, Instant.now()).issuedBy(IACA.certificate())).isTrue();
        assertThat(getBytes("/api/v1/revocation/crl?url=" + UPSTREAM_BASE + "/status/page", "key-a").statusCode()).isEqualTo(502);
        var ftp = get("/api/v1/revocation/crl?url=ftp://crl.example/x.crl", "key-a");
        assertThat(ftp.statusCode()).isEqualTo(400);
        assertThat(json(ftp).get("code")).isEqualTo("invalid_request");
        // CRL distribution points are mostly http: allowed for CRLs (they are signed), still https-only for anything else.
        String plainHttpBase = UPSTREAM_BASE.replace("localhost", "127.0.0.1"); // not in http-allowed-hosts
        var plainHttp = getBytes("/api/v1/revocation/crl?url=" + plainHttpBase + "/crl/iaca.crl", "key-a");
        assertThat(plainHttp.statusCode()).isEqualTo(200);
        assertThat(RevocationChecker.Crl.parse(plainHttp.body(), null, Instant.now()).issuedBy(IACA.certificate())).isTrue();
        var httpStatusList = get("/api/v1/revocation/status-list?uri=" + plainHttpBase + "/status/token", "key-a");
        assertThat(httpStatusList.statusCode()).isEqualTo(400);
        assertThat(json(httpStatusList).get("detail").toString()).contains("Only https");
        assertThat(get("/api/v1/revocation/crl?url=" + UPSTREAM_BASE + "/crl/iaca.crl", null).statusCode()).isEqualTo(401);

        var token = getBytes("/api/v1/revocation/status-list?uri=" + UPSTREAM_BASE + "/status/token", "key-a",
                "Accept", "application/statuslist+jwt");
        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(token.headers().firstValue("Content-Type")).contains("application/statuslist+jwt");
        assertThat(new String(token.body(), StandardCharsets.UTF_8)).isEqualTo("eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6e319.c2ln");
        assertThat(token.headers().firstValue("Cache-Control").orElse("")).contains("private").contains("max-age=");
        var page = get("/api/v1/revocation/status-list?uri=" + UPSTREAM_BASE + "/status/page", "key-a");
        assertThat(page.statusCode()).isEqualTo(502);
        assertThat(json(page).get("code")).isEqualTo("invalid_status_list");

        var d = json(get("/.well-known/trust-service", null));
        assertThat(((Map<?, ?>) d.get("endpoints")).get("status_list_relay")).isEqualTo("https://trust.test/api/v1/revocation/status-list");
        assertThat((Map<String, Object>) d.get("revocation")).containsEntry("crl", true).containsEntry("ocsp", false)
                .containsEntry("crl_relay", true).containsEntry("status_list_relay", true);
        assertThat(d.get("snapshot_format")).isEqualTo(3);
    }

    @Test
    @SuppressWarnings("unchecked")
    void onDemandLookupIsOptInAndSigned() throws Exception {
        var plain = get("/api/v1/entities/lookup?identifier=https://revoked.example", "key-a");
        assertThat(plain.statusCode()).isEqualTo(200);
        var signed = get("/api/v1/entities/lookup?identifier=https://unknown.example&onDemand=true", "key-a", "Accept", "application/jwt");
        assertThat(signed.statusCode()).isEqualTo(200);
        SignedJWT jwt = SignedJWT.parse(signed.body());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("trust-registry+jwt");
        assertThat((List<?>) jwt.getJWTClaimsSet().getClaim("data")).isEmpty();
    }

    static String accessToken(String clientId, String audience) throws Exception {
        Instant now = Instant.now();
        com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType("at+jwt")).keyID("as-key").build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder().issuer("https://as.trust.test").audience(audience).claim("client_id", clientId)
                        .subject(clientId).issueTime(java.util.Date.from(now)).expirationTime(java.util.Date.from(now.plusSeconds(300))).build());
        jwt.sign(new com.nimbusds.jose.crypto.ECDSASigner(AS_KEY));
        return jwt.serialize();
    }

    @Test
    @SuppressWarnings("unchecked")
    void oauthAccessTokensAndPublishedAuthMethods() throws Exception {
        var issuers = get("/api/v1/issuers", accessToken("wallet-a", "https://trust.test"));
        assertThat(issuers.statusCode()).isEqualTo(200);
        assertThat(get("/admin/v1/sources", accessToken("wallet-a", "https://trust.test")).statusCode()).isEqualTo(403);
        assertThat(get("/admin/v1/sources", accessToken("admin", "https://trust.test")).statusCode()).isEqualTo(200);
        var wrongAudience = get("/api/v1/issuers", accessToken("wallet-a", "https://other.test"));
        assertThat(wrongAudience.statusCode()).isEqualTo(401);
        assertThat(wrongAudience.headers().firstValue("WWW-Authenticate").orElse("")).contains("error=\"invalid_token\"");
        assertThat(json(wrongAudience).get("code")).isEqualTo("invalid_token");
        assertThat(get("/api/v1/issuers", accessToken("nobody", "https://trust.test")).statusCode()).isEqualTo(401);

        var d = json(get("/.well-known/trust-service", null));
        assertThat((List<String>) d.get("auth_methods_supported")).containsExactly("api_key", "oauth2_jwt");
        assertThat(d.get("oauth_token_issuer")).isEqualTo("https://as.trust.test");
        assertThat((List<String>) d.get("signing_key_thumbprints")).containsExactly((String) d.get("signing_key_thumbprint"));
    }

    @Test
    void errorsAreProblemJsonWhateverTheRequestAccepts() throws Exception {
        var r = get("/api/v1/revocation/crl?url=" + UPSTREAM_BASE + "/status/page", "key-a", "Accept", "application/pkix-crl");
        assertThat(r.statusCode()).isEqualTo(502);
        assertThat(r.headers().firstValue("Content-Type").orElse("")).startsWith("application/problem+json");
        assertThat(json(r).get("code")).isEqualTo("invalid_crl");
        var missing = get("/api/v1/revocation/status-list", "key-a", "Accept", "application/statuslist+jwt");
        assertThat(missing.statusCode()).isEqualTo(400);
        assertThat(missing.headers().firstValue("Content-Type").orElse("")).startsWith("application/problem+json");
        assertThat(missing.body()).isNotBlank();
    }

    @Test
    void trqpBinding() throws Exception {
        var ok = json(post("/trqp/authorization", "key-a", Map.of("entity_id", UPSTREAM_BASE + "/issuer", "authority_id", "fw-a",
                "action", "issue", "resource", "mso_mdoc:org.iso.18013.5.1.mDL", "context", Map.of("time", "2026-10-01T00:00:00Z"))));
        assertThat(ok.get("authorized")).isEqualTo(true);
        assertThat(ok.get("time_requested")).isEqualTo("2026-10-01T00:00:00Z");
        var no = json(post("/trqp/authorization", "key-a", Map.of("entity_id", UPSTREAM_BASE + "/issuer", "authority_id", "fw-a",
                "action", "issue", "resource", "dc+sd-jwt:urn:eudi:pid:1")));
        assertThat(no.get("authorized")).isEqualTo(false);
        assertThat(post("/trqp/authorization", "key-a", Map.of("entity_id", "x", "authority_id", "nope", "action", "issue", "resource", "*"))
                .statusCode()).isEqualTo(404);
        assertThat(post("/trqp/authorization", "key-a", Map.of("entity_id", "x")).statusCode()).isEqualTo(400);
        var rec = json(post("/trqp/recognition", "key-admin", Map.of("entity_id", "fw-a", "authority_id", "fw-b", "action", "recognize", "resource", "listed")));
        assertThat(rec.get("recognized")).isEqualTo(true);
    }

    @Test
    void noSpellingOfAProtectedPathSkipsAuthentication() throws Exception {
        // Each of these reached the admin API without credentials when the filter compared raw path prefixes.
        assertThat(get("/admin;x=y/v1/registry", null).statusCode()).isEqualTo(400);
        assertThat(get("/admin;x/v1/clients", null).statusCode()).isEqualTo(400);
        assertThat(json(get("/admin;x/v1/clients", null)).get("code")).isEqualTo("invalid_request");
        assertThat(put("/admin;x/v1/managed/anchors/x1", "nobody", Map.of("domain", "mdoc-iaca")).statusCode()).isEqualTo(400);
        assertThat(get("/%61dmin/v1/registry", null).statusCode()).isEqualTo(401);
        assertThat(get("/%61dmin/v1/registry", "key-a").statusCode()).isEqualTo(403);
        assertThat(get("/%61dmin/v1/registry", "key-admin").statusCode()).isEqualTo(200);
        assertThat(get("/admin/v1/registry", null, "X-Forwarded-Prefix", "/x").statusCode()).isEqualTo(401);
        assertThat(get("/admin/v1/registry", "key-a", "X-Forwarded-Prefix", "/x").statusCode()).isEqualTo(403);
        assertThat(get("/admin/v1/registry", "key-admin").statusCode()).isEqualTo(200);
        // Authentication is the default; only discovery, keys, health and the API description are public.
        assertThat(get("/actuator/health", null).statusCode()).isEqualTo(200);
        assertThat(get("/.well-known/jwks.json", null).statusCode()).isEqualTo(200);
        assertThat(get("/actuator/metrics", null).statusCode()).isEqualTo(401);
        assertThat(get("/actuator/metrics", "key-a").statusCode()).isEqualTo(403);
        assertThat(get("/actuator/metrics", "key-admin").statusCode()).isEqualTo(200);
        assertThat(get("/no-such-page", null).statusCode()).isEqualTo(401);
        // Encoded characters that DIDs need still work.
        assertThat(get("/api/v1/did/did:web:example.com%3A8443", "key-a").statusCode()).isNotIn(400, 401, 403);
    }

    @Test
    void managedEntitiesThroughAdminApi() throws Exception {
        var put = put("/admin/v1/managed/entities/local-verifier", "key-admin", Map.of("roles", List.of("VERIFIER"),
                "name", "Local verifier", "identifiers", List.of(Map.of("type", "CLIENT_ID", "value", "x509_san_dns:rp.local"))));
        assertThat(put.statusCode()).isEqualTo(200);
        var d = json(post("/api/v1/evaluate", "key-a", Map.of("role", "verifier", "subject", Map.of("identifier", "redirect_uri:https://rp.local/cb"))));
        assertThat(d.get("decision")).isEqualTo("UNKNOWN");
        var lookup = get("/api/v1/entities/lookup?identifier=x509_san_dns:rp.local", "key-a");
        assertThat(lookup.body()).contains("local-verifier");
        assertThat(put("/admin/v1/managed/entities/broken", "key-admin", Map.of("roles", List.of("NOPE"))).statusCode()).isEqualTo(400);
        assertThat(http.send(HttpRequest.newBuilder(URI.create(base() + "/admin/v1/managed/entities/local-verifier")).DELETE()
                .header("Authorization", "Bearer key-admin").build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
        assertThat(get("/api/v1/entities/lookup?identifier=x509_san_dns:rp.local", "key-a").body()).doesNotContain("local-verifier");
    }
}
