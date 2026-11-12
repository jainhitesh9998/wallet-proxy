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
import io.vctrust.trust.core.registry.TrustSourceManager;
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

    static final String CONTEXT = "{\"@context\":{\"degree\":\"https://vocab.example/degree\"}}";
    /** The URI the second registry is publicly known by: it is read from a file, and published under this name. */
    static final String REGISTRY_B_PUBLIC_URI = "https://lists.trust.test/registry-b.yaml";

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
            raw("/status/token", "application/statuslist+jwt", "eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6eyJiaXRzIjoxLCJsc3QiOiJlTnBqQUFBQUFRQUIifX0.c2ln".getBytes(StandardCharsets.UTF_8));
            raw("/status/page", "text/html", "<html></html>".getBytes(StandardCharsets.UTF_8));
            raw("/status/bitstring", "application/vc+ld+json", ("{\"type\":[\"VerifiableCredential\",\"BitstringStatusListCredential\"],"
                    + "\"credentialSubject\":{\"type\":\"BitstringStatusList\",\"statusPurpose\":\"revocation\",\"encodedList\":\"uH4sIAAAAAAAAA\"}}")
                    .getBytes(StandardCharsets.UTF_8));
            raw("/status/not-a-list.json", "application/json", "{\"internal\":\"what an admin console might say\"}".getBytes(StandardCharsets.UTF_8));
            raw("/contexts/degree/v1", "application/ld+json", CONTEXT.getBytes(StandardCharsets.UTF_8));
            raw("/contexts/pinned/v1", "application/ld+json", CONTEXT.getBytes(StandardCharsets.UTF_8));
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
                    roles: [CREDENTIAL_ISSUER]
                    name: Test Issuer
                    identifiers:
                      - {type: URL, value: "%s/issuer"}
                    authorizations:
                      - {format: mso_mdoc, type: org.iso.18013.5.1.mDL}
                    contexts:
                      - "%s/contexts/degree/v1"
                      - {url: "%s/contexts/pinned/v1", sha256: "not-the-digest-of-what-is-served"}
                    metadataPolicy:
                      oauth_authorization_server:
                        grant_types_supported: {add: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]}
                        token_endpoint: {default: "%s/issuer/token"}
                  - id: revoked-issuer
                    roles: [CREDENTIAL_ISSUER]
                    status: REVOKED
                    identifiers: [{type: URL, value: "https://revoked.example"}]
                anchors:
                  - domain: mdoc-iaca
                    entity: test-issuer
                    constraints:
                      crlUrls: ["%s/crl/iaca.crl"]
                    certificate: |
                %s
                """.formatted(UPSTREAM_BASE, UPSTREAM_BASE, UPSTREAM_BASE, UPSTREAM_BASE, UPSTREAM_BASE, Certificates.toPem(IACA.certificate()).indent(6)));
        // A source loads into one framework: the other framework's issuer comes from a list of its own.
        Path registryB = dataDir.resolve("registry-b.yaml");
        Files.writeString(registryB, """
                entities:
                  - id: b-issuer
                    roles: [CREDENTIAL_ISSUER]
                    identifiers: [did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK]
                """);
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
        r.add("trust.sources[0].framework", () -> "fw-a");
        r.add("trust.sources[0].properties.location", () -> registry.toUri().toString());
        r.add("trust.sources[2].id", () -> "reg-b");
        r.add("trust.sources[2].type", () -> "static");
        r.add("trust.sources[2].framework", () -> "fw-b");
        r.add("trust.sources[2].properties.location", () -> registryB.toUri().toString());
        r.add("trust.sources[2].properties.publicUri", () -> REGISTRY_B_PUBLIC_URI);
        r.add("trust.sources[1].id", () -> "managed");
        r.add("trust.sources[1].type", () -> "managed");
        r.add("trust.sources[1].framework", () -> "local");
        r.add("trust.clients[0].id", () -> "wallet-a");
        r.add("trust.clients[0].api-key", () -> "key-a");
        r.add("trust.clients[0].frameworks[0]", () -> "fw-a");
        r.add("trust.clients[0].frameworks[1]", () -> "local");
        r.add("trust.clients[0].allow-unregistered-metadata", () -> "true");
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
        r.add("trust.service.snapshot-recheck", () -> "PT0.2S");
        r.add("trust.auth.rate-limit.enabled", () -> "false");
    }

    @Autowired
    Environment env;
    @Autowired
    TrustSourceManager sources;
    @Autowired
    CrlService crls;

    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void awaitReady() throws InterruptedException {
        // Generous limits: a shared build machine may be several times slower than a developer's.
        for (int i = 0; i < 600 && !sources.ready(); i++) {
            Thread.sleep(50);
        }
        assertThat(sources.ready()).isTrue();
        // Anchor CRLs load in the background after the registry; wait so snapshots are stable during tests.
        for (int i = 0; i < 600 && crls.heldFor(IACA.certificate()).isEmpty(); i++) {
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

    static Map<String, Object> policy(com.nimbusds.jwt.JWTClaimsSet claims) throws java.text.ParseException {
        return claims.getJSONObjectClaim("policy");
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
        var r = get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/issuer", "key-a");
        assertThat(r.statusCode()).isEqualTo(200);
        var env = json(r);
        assertThat(((Map<String, Object>) env.get("trust")).get("decision")).isEqualTo("TRUSTED");
        assertThat(env.get("credentialIssuer")).isEqualTo(UPSTREAM_BASE + "/issuer");
        assertThat(env.get("policyApplied")).isEqualTo(true);
        var as = (Map<String, Object>) ((Map<String, Object>) env.get("authorizationServers")).get(UPSTREAM_BASE + "/as");
        assertThat(as.get("token_endpoint")).isEqualTo(UPSTREAM_BASE + "/issuer/token");
        assertThat((List<String>) as.get("grant_types_supported")).contains("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        // unregistered issuer: UNKNOWN for permissive client, 403 for strict client
        var other = json(get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/other", "key-a"));
        assertThat(((Map<String, Object>) other.get("trust")).get("decision")).isEqualTo("UNKNOWN");
        // By default the proxy fetches only for issuers the client's frameworks list: it is not an open relay.
        assertThat(get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/other", "key-strict").statusCode()).isEqualTo(403);
        // credential_issuer must be identical to the identifier asked for, and the answer is remembered
        var liar = get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/liar", "key-a");
        assertThat(liar.statusCode()).isEqualTo(422);
        assertThat(json(liar).get("code")).isEqualTo("issuer_mismatch");
        assertThat(get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/issuer/", "key-a").statusCode()).isNotEqualTo(200);
        // Signed on request, so a client can verify a proxied document as it verifies a snapshot.
        var signed = get("/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/issuer", "key-a", "Accept", "application/jwt");
        SignedJWT jwt = SignedJWT.parse(signed.body());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("trust-metadata+jwt");
        assertThat(((Map<String, Object>) jwt.getJWTClaimsSet().getClaim("data")).get("credentialIssuer")).isEqualTo(UPSTREAM_BASE + "/issuer");
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

    }

    @Test
    @SuppressWarnings("unchecked")
    void noLocationOnTheServicesHostReachesAClient() throws Exception {
        // Both static registries, the signing key and the OAuth JWKS are files in dataDir: its name is in their
        // locations, and must be in nothing a client receives.
        String directory = dataDir.getFileName().toString();
        assertThat(env.getProperty("trust.sources[0].properties.location")).contains(directory);
        List<String> received = new java.util.ArrayList<>();

        // The snapshot, decoded, for a wallet and for an operator (who sees every framework).
        for (String key : List.of("key-a", "key-admin")) {
            var claims = SignedJWT.parse(get("/api/v1/snapshot", key).body()).getJWTClaimsSet();
            received.add(claims.toString());
            for (String claim : List.of("entities", "anchors")) {
                for (Map<String, Object> record : (List<Map<String, Object>>) claims.getClaim(claim)) {
                    Map<String, Object> provenance = (Map<String, Object>) record.getOrDefault("provenance", Map.of());
                    if ("reg".equals(provenance.get("sourceId"))) {
                        assertThat(provenance).as(claim).doesNotContainKey("sourceUri");
                    } else if ("reg-b".equals(provenance.get("sourceId"))) {
                        assertThat(provenance).as(claim).containsEntry("sourceUri", REGISTRY_B_PUBLIC_URI);
                    }
                }
            }
        }

        // A decision about an entity of the registry read from a file, plain and signed.
        var trusted = post("/api/v1/evaluate", "key-a", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(Certificates.toBase64(DS.certificate()))),
                "context", Map.of("credentialFormat", "mso_mdoc", "credentialType", "org.iso.18013.5.1.mDL")));
        assertThat(json(trusted).get("decision")).isEqualTo("TRUSTED");
        assertThat((Map<String, Object>) ((Map<String, Object>) json(trusted).get("entity")).get("provenance")).doesNotContainKey("sourceUri");
        received.add(trusted.body());
        received.add(SignedJWT.parse(post("/api/v1/evaluate", "key-a", Map.of("role", "issuer", "subject", Map.of("identifier", UPSTREAM_BASE + "/issuer")),
                "Accept", "application/jwt").body()).getPayload().toString());

        // The registry as a client sees it, and what the proxy attaches to issuer metadata.
        for (String path : List.of("/api/v1/issuers", "/api/v1/verifiers", "/api/v1/frameworks",
                "/api/v1/entities/lookup?identifier=" + UPSTREAM_BASE + "/issuer", "/api/v1/proxy/issuer-metadata?issuer=" + UPSTREAM_BASE + "/issuer")) {
            for (String key : List.of("key-a", "key-admin")) {
                var r = get(path, key);
                assertThat(r.statusCode()).as(path).isEqualTo(200);
                received.add(r.body());
                received.add(SignedJWT.parse(get(path, key, "Accept", "application/jwt").body()).getPayload().toString());
            }
        }
        received.add(get("/.well-known/trust-service", null).body());
        // Problem documents.
        received.add(post("/api/v1/evaluate", "key-a", Map.of("role", "nonsense", "subject", Map.of("identifier", "x"))).body());
        received.add(get("/api/v1/entities/lookup?identifier=x&type=nonsense", "key-a").body());
        received.add(get("/api/v1/proxy/crl?url=" + UPSTREAM_BASE + "/status/page", "key-a").body());
        received.add(get("/api/v1/snapshot", "wrong-key").body());
        assertThat(received).allSatisfy(body -> assertThat(body).doesNotContain(directory));

        // DCQL trusted_authorities: the list read from a file is matched by the URI it is published under; the file's
        // own location matches nothing, so a query naming a path learns nothing about the service's files.
        var authorities = json(post("/api/v1/evaluate", "key-admin", Map.of("role", "issuer",
                "subject", Map.of("identifier", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
                "context", Map.of("trustedAuthorities", List.of(
                        Map.of("type", "etsi_tl", "values", List.of(REGISTRY_B_PUBLIC_URI)),
                        Map.of("type", "etsi_tl", "values", List.of(env.getProperty("trust.sources[2].properties.location"))))))));
        assertThat(((Map<String, Object>) authorities.get("entity")).get("id")).isEqualTo("b-issuer");
        assertThat((List<Map<String, Object>>) ((Map<String, Object>) authorities.get("evidence")).get("trustedAuthorities"))
                .extracting(m -> m.get("matched")).containsExactly(true, false);
    }

    @Test
    @SuppressWarnings("unchecked")
    void didProxy() throws Exception {
        String did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        var r = json(get("/api/v1/proxy/did/" + did, "key-a"));
        assertThat(((Map<String, Object>) r.get("didDocument")).get("id")).isEqualTo(did);
        var signed = SignedJWT.parse(get("/api/v1/proxy/did/" + did, "key-a", "Accept", "application/jwt").body());
        assertThat(signed.getHeader().getType().toString()).isEqualTo("trust-did-resolution+jwt");
        assertThat(get("/api/v1/proxy/did/did:example:123", "key-a").statusCode()).isEqualTo(501);
        assertThat(get("/api/v1/proxy/did/not-a-did", "key-a").statusCode()).isEqualTo(400);
        // The W3C DID resolver binding of earlier versions is gone; nothing answers there.
        assertThat(get("/1.0/identifiers/" + did, "key-a").statusCode()).isEqualTo(404);
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
        assertThat(claims.getIntegerClaim("format")).isEqualTo(4);
        assertThat(policy(claims)).doesNotContainKey("allowRelaxedProfiles");
        Map<String, Object> policy = policy(claims);
        assertThat(policy).containsEntry("strictAuthorization", false);
        assertThat((List<Object>) policy.get("frameworks")).containsExactlyInAnyOrder("fw-a", "local");
        assertThat(((Map<String, Object>) anchors.getFirst()).get("provenance")).isInstanceOf(Map.class);
        Map<String, Object> issuer = entities.stream().map(e -> (Map<String, Object>) e)
                .filter(e -> "test-issuer".equals(e.get("id"))).findFirst().orElseThrow();
        assertThat(issuer.get("metadataPolicy")).isInstanceOf(Map.class);

        // DID documents of registered DID identifiers are embedded (admin sees every framework, incl. b-issuer).
        Map<String, Object> docs = SignedJWT.parse(get("/api/v1/snapshot", "key-admin").body()).getJWTClaimsSet().getJSONObjectClaim("didDocuments");
        assertThat(docs).containsKey("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

        // JSON-LD contexts of the listed issuers travel with their digests; one that does not match its pin is not
        // shipped, only the pin is, so a wallet that fetches it elsewhere refuses it.
        Map<String, Object> contexts = claims.getJSONObjectClaim("contexts");
        Map<String, Object> degree = (Map<String, Object>) contexts.get(UPSTREAM_BASE + "/contexts/degree/v1");
        assertThat(degree.get("sha256")).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(
                java.security.MessageDigest.getInstance("SHA-256").digest(CONTEXT.getBytes(StandardCharsets.UTF_8))));
        assertThat((Map<String, Object>) degree.get("document")).containsKey("@context");
        Map<String, Object> pinned = (Map<String, Object>) contexts.get(UPSTREAM_BASE + "/contexts/pinned/v1");
        assertThat(pinned).containsEntry("sha256", "not-the-digest-of-what-is-served").doesNotContainKey("document");

        // The ETag names the content: a source reload that changes nothing still answers 304.
        assertThat(post("/admin/v1/sources/managed/refresh", "key-admin", Map.of()).statusCode()).isEqualTo(200);
        assertThat(post("/admin/v1/sources/reg/refresh", "key-admin", Map.of()).statusCode()).isEqualTo(200);
        Thread.sleep(300);
        assertThat(get("/api/v1/snapshot", "key-a", "If-None-Match", etag).statusCode()).isEqualTo(304);

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

        // A CRL pushed with a managed anchor: verified, held, and never echoed in anchor views.
        String pem = "-----BEGIN X509 CRL-----\n" + Base64.getMimeEncoder().encodeToString(TestPki.crl(PUSHED_IACA).getEncoded())
                + "\n-----END X509 CRL-----\n";
        assertThat(put("/admin/v1/managed/anchors/pushed-iaca", "key-admin", Map.of("domain", "mdoc-iaca",
                "certificate", Certificates.toPem(PUSHED_IACA.certificate()), "constraints", Map.of("crl", pem))).statusCode()).isEqualTo(200);
        for (int i = 0; i < 100 && crls.heldFor(PUSHED_IACA.certificate()).isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(crls.heldFor(PUSHED_IACA.certificate())).singleElement().satisfies(c -> assertThat(c.url()).isNull());
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
    void anOperatorSeesTheAnchorCrlsTheServiceHolds() throws Exception {
        var listed = TestPki.rootCa("CN=Listed IACA,C=UT");
        var crl = TestPki.crl(listed);
        String pem = "-----BEGIN X509 CRL-----\n" + Base64.getMimeEncoder().encodeToString(crl.getEncoded()) + "\n-----END X509 CRL-----\n";
        assertThat(put("/admin/v1/managed/anchors/listed-iaca", "key-admin", Map.of("domain", "mdoc-iaca",
                "certificate", Certificates.toPem(listed.certificate()), "constraints", Map.of("crl", pem))).statusCode()).isEqualTo(200);
        try {
            for (int i = 0; i < 100 && crls.heldFor(listed.certificate()).isEmpty(); i++) {
                Thread.sleep(50);
            }
            var r = get("/admin/v1/crls", "key-admin");
            assertThat(r.statusCode()).isEqualTo(200);
            List<Map<String, Object>> entries = Json.MAPPER.readValue(r.body(), List.class);
            // The CRL pushed with the managed anchor: no url, its dates as the CRL states them, carried in snapshots.
            assertThat(entries).filteredOn(e -> Certificates.sha256Thumbprint(listed.certificate()).equals(e.get("issuer"))).singleElement()
                    .satisfies(e -> {
                        assertThat(e).containsEntry("anchorIds", List.of("listed-iaca")).containsEntry("revoked", 0)
                                .containsEntry("current", true).containsEntry("inSnapshots", true)
                                .containsKeys("subject", "crlNumber", "bytes", "fetchedAt", "nextFetch").doesNotContainKeys("url", "error");
                        assertThat(Instant.parse((String) e.get("thisUpdate"))).isEqualTo(crl.getThisUpdate().toInstant());
                        assertThat(Instant.parse((String) e.get("nextUpdate"))).isEqualTo(crl.getNextUpdate().toInstant());
                    });
            // The CRL the service fetches for the registry's IACA, with where it fetches it from.
            assertThat(entries).filteredOn(e -> Certificates.sha256Thumbprint(IACA.certificate()).equals(e.get("issuer"))).singleElement()
                    .satisfies(e -> assertThat(e).containsEntry("url", UPSTREAM_BASE + "/crl/iaca.crl").containsEntry("revoked", 1)
                            .containsEntry("inSnapshots", true));

            assertThat(get("/admin/v1/crls", "key-a").statusCode()).isEqualTo(403);
            assertThat(get("/admin/v1/crls", null).statusCode()).isEqualTo(401);
        } finally {
            http.send(HttpRequest.newBuilder(URI.create(base() + "/admin/v1/managed/anchors/listed-iaca")).DELETE()
                    .header("Authorization", "Bearer key-admin").build(), HttpResponse.BodyHandlers.discarding());
            for (int i = 0; i < 100 && !crls.heldFor(listed.certificate()).isEmpty(); i++) {
                Thread.sleep(50);
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void crlAndStatusListRelays() throws Exception {
        var crl = getBytes("/api/v1/proxy/crl?url=" + UPSTREAM_BASE + "/crl/iaca.crl", "key-a", "Accept", "application/pkix-crl");
        assertThat(crl.statusCode()).isEqualTo(200);
        assertThat(crl.headers().firstValue("Content-Type")).contains("application/pkix-crl");
        assertThat(crl.headers().firstValue("Cache-Control").orElse("")).contains("max-age=");
        assertThat(RevocationChecker.Crl.parse(crl.body(), null, Instant.now()).issuedBy(IACA.certificate())).isTrue();
        assertThat(getBytes("/api/v1/proxy/crl?url=" + UPSTREAM_BASE + "/status/page", "key-a").statusCode()).isEqualTo(502);
        var ftp = get("/api/v1/proxy/crl?url=ftp://crl.example/x.crl", "key-a");
        assertThat(ftp.statusCode()).isEqualTo(400);
        assertThat(json(ftp).get("code")).isEqualTo("invalid_request");
        // CRL distribution points are mostly http: allowed for CRLs (they are signed), still https-only for anything else.
        String plainHttpBase = UPSTREAM_BASE.replace("localhost", "127.0.0.1"); // not in http-allowed-hosts
        var plainHttp = getBytes("/api/v1/proxy/crl?url=" + plainHttpBase + "/crl/iaca.crl", "key-a");
        assertThat(plainHttp.statusCode()).isEqualTo(200);
        assertThat(RevocationChecker.Crl.parse(plainHttp.body(), null, Instant.now()).issuedBy(IACA.certificate())).isTrue();
        var httpStatusList = get("/api/v1/proxy/status-list?uri=" + plainHttpBase + "/status/token", "key-a");
        assertThat(httpStatusList.statusCode()).isEqualTo(400);
        assertThat(json(httpStatusList).get("detail").toString()).contains("Only https");
        assertThat(get("/api/v1/proxy/crl?url=" + UPSTREAM_BASE + "/crl/iaca.crl", null).statusCode()).isEqualTo(401);

        var token = getBytes("/api/v1/proxy/status-list?uri=" + UPSTREAM_BASE + "/status/token", "key-a",
                "Accept", "application/statuslist+jwt");
        assertThat(token.statusCode()).isEqualTo(200);
        assertThat(token.headers().firstValue("Content-Type")).contains("application/statuslist+jwt");
        assertThat(new String(token.body(), StandardCharsets.UTF_8)).isEqualTo("eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6eyJiaXRzIjoxLCJsc3QiOiJlTnBqQUFBQUFRQUIifX0.c2ln");
        assertThat(token.headers().firstValue("Cache-Control").orElse("")).contains("private").contains("max-age=");
        var page = get("/api/v1/proxy/status-list?uri=" + UPSTREAM_BASE + "/status/page", "key-a");
        assertThat(page.statusCode()).isEqualTo(502);
        assertThat(json(page).get("code")).isEqualTo("invalid_status_list");
        assertThat(get("/api/v1/proxy/status-list?uri=" + UPSTREAM_BASE + "/status/bitstring", "key-a").statusCode()).isEqualTo(200);
        // JSON that is not a status list is not passed on, whatever its content type: the relay reads nothing else for a caller.
        var other = get("/api/v1/proxy/status-list?uri=" + UPSTREAM_BASE + "/status/not-a-list.json", "key-a");
        assertThat(other.statusCode()).isEqualTo(502);
        assertThat(json(other).get("code")).isEqualTo("invalid_status_list");
        assertThat(other.body()).doesNotContain("admin console");

        var d = json(get("/.well-known/trust-service", null));
        assertThat(((Map<?, ?>) d.get("endpoints")).get("proxy_status_list")).isEqualTo("https://trust.test/api/v1/proxy/status-list");
        assertThat((Map<String, Object>) d.get("revocation")).containsEntry("crl", true)
                .containsEntry("crl_proxy", true).containsEntry("status_list_proxy", true);
        assertThat(d.get("snapshot_format")).isEqualTo(4);
        assertThat(d.get("ready")).isEqualTo(true);
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
        var r = get("/api/v1/proxy/crl?url=" + UPSTREAM_BASE + "/status/page", "key-a", "Accept", "application/pkix-crl");
        assertThat(r.statusCode()).isEqualTo(502);
        assertThat(r.headers().firstValue("Content-Type").orElse("")).startsWith("application/problem+json");
        assertThat(json(r).get("code")).isEqualTo("invalid_crl");
        var missing = get("/api/v1/proxy/status-list", "key-a", "Accept", "application/statuslist+jwt");
        assertThat(missing.statusCode()).isEqualTo(400);
        assertThat(missing.headers().firstValue("Content-Type").orElse("")).startsWith("application/problem+json");
        assertThat(missing.body()).isNotBlank();
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
        assertThat(get("/api/v1/proxy/did/did:web:example.com%3A8443", "key-a").statusCode()).isNotIn(400, 401, 403);
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

    @Test
    void operatorEntriesAndRequestsAreHeldToTheirLimits() throws Exception {
        // Managed entries load into the managed source's framework ("local"); an entry cannot place itself elsewhere.
        var foreign = put("/admin/v1/managed/entities/sneaked", "key-admin", Map.of("framework", "fw-a", "roles", List.of("CREDENTIAL_ISSUER"),
                "identifiers", List.of("https://sneaked.example")));
        assertThat(foreign.statusCode()).isEqualTo(400);
        assertThat(json(foreign).get("detail").toString()).contains("cannot name another framework");
        // Nor can it make the service read its own files.
        for (String location : List.of("file:///etc/hosts", "/etc/hosts", "classpath:application.yml")) {
            var local = put("/admin/v1/managed/anchors/local-file", "key-admin", Map.of("domain", "mdoc-iaca", "certificateLocation", location));
            assertThat(local.statusCode()).as(location).isEqualTo(400);
            assertThat(json(local).get("detail").toString()).as(location).contains("Only an http(s) location");
        }
        assertThat(put("/admin/v1/managed/entities/" + "x".repeat(129), "key-admin", Map.of("roles", List.of("VERIFIER"))).statusCode()).isEqualTo(400);
        assertThat(put("/admin/v1/managed/entities/a%20b", "key-admin", Map.of("roles", List.of("VERIFIER"))).statusCode()).isEqualTo(400);
        // What is stored says which framework it was stored for.
        var stored = put("/admin/v1/managed/entities/limits-ok", "key-admin", Map.of("roles", List.of("VERIFIER"), "identifiers", List.of("https://limits.example")));
        assertThat(stored.statusCode()).isEqualTo(200);
        assertThat(json(stored)).containsEntry("framework", "local");
        http.send(HttpRequest.newBuilder(URI.create(base() + "/admin/v1/managed/entities/limits-ok")).DELETE()
                .header("Authorization", "Bearer key-admin").build(), HttpResponse.BodyHandlers.discarding());

        // Errors name what was wrong, not the classes of the service.
        var role = post("/api/v1/evaluate", "key-a", Map.of("role", "nonsense", "subject", Map.of("identifier", "https://x.example")));
        assertThat(role.statusCode()).isEqualTo(400);
        assertThat(role.body()).contains("Unknown role").doesNotContain("io.vctrust");
        var type = get("/api/v1/entities/lookup?identifier=x&type=nonsense", "key-a");
        assertThat(type.statusCode()).isEqualTo(400);
        assertThat(type.body()).contains("Unknown identifier type").doesNotContain("io.vctrust");
        assertThat(get("/api/v1/issuers?page=2147483647&size=1000", "key-a").statusCode()).isEqualTo(200);

        // A request body has a size limit, whoever sends it.
        var large = post("/api/v1/evaluate", "key-a", Map.of("role", "issuer", "subject", Map.of("x5c", List.of("A".repeat(3 * 1024 * 1024)))));
        assertThat(large.statusCode()).isEqualTo(413);
        // A chain of more certificates than any real one is not read.
        var long11 = post("/api/v1/evaluate", "key-a", Map.of("role", "issuer", "subject",
                Map.of("x5c", java.util.Collections.nCopies(11, Certificates.toBase64(IACA.certificate())))));
        assertThat(long11.statusCode()).isEqualTo(200);
        assertThat(long11.body()).contains("x509.chain_too_long");

        // The public health endpoint says UP or DOWN; what is behind it is for operators.
        var health = get("/actuator/health", null);
        assertThat(health.statusCode()).isEqualTo(200);
        assertThat(health.body()).contains("\"status\":\"UP\"").doesNotContain("components").doesNotContain("sources");
        assertThat(get("/admin/v1/sources", "key-admin").body()).contains("\"reg\"");
    }
}
