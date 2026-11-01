package io.vctrust.trust.server;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.server.config.SourceBootstrap;
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
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustServerIntegrationTest {

    static final TestPki.Issued IACA = TestPki.rootCa("CN=Test IACA,C=UT");
    static final TestPki.Issued DS = TestPki.documentSigner("CN=Test DS,C=UT", IACA);
    static final TestPki.Issued ROGUE_IACA = TestPki.rootCa("CN=Rogue IACA,C=UT");
    static final TestPki.Issued ROGUE_DS = TestPki.documentSigner("CN=Rogue DS,C=UT", ROGUE_IACA);
    static final HttpServer UPSTREAM;
    static final String UPSTREAM_BASE;
    static Path dataDir;

    static {
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
            UPSTREAM.start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
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
                    certificate: |
                %s
                """.formatted(UPSTREAM_BASE, UPSTREAM_BASE, Certificates.toPem(IACA.certificate()).indent(6)));
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
        r.add("trust.clients[2].id", () -> "admin");
        r.add("trust.clients[2].api-key", () -> "key-admin");
        r.add("trust.clients[2].admin", () -> "true");
        r.add("trust.anonymous.enabled", () -> "false");
    }

    @Autowired
    Environment env;
    @Autowired
    SourceBootstrap bootstrap;

    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void awaitReady() throws InterruptedException {
        for (int i = 0; i < 100 && !bootstrap.isReady(); i++) {
            Thread.sleep(50);
        }
        assertThat(bootstrap.isReady()).isTrue();
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
        assertThat(get("/api/v1/snapshot", "key-a", "If-None-Match", r.headers().firstValue("ETag").orElseThrow()).statusCode()).isEqualTo(304);
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
