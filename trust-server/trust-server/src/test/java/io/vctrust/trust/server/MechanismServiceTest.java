package io.vctrust.trust.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A service with trust mechanisms carries them to every client in the {@code mechanisms} claim of a format 5 snapshot,
 * says so in its discovery document, lists them for an operator, and applies them in its own decisions. (Without
 * mechanisms it issues format 4 exactly as before: the first pair of evaluation vectors holds it to that.)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MechanismServiceTest {

    static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        Path dataDir = Files.createTempDirectory("trust-mechanism-service");
        r.add("spring.datasource.url", () -> "jdbc:h2:mem:trust-mechanism-service;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        r.add("trust.service.signing-key-file", () -> dataDir.resolve("key.jwk").toString());
        r.add("trust.frameworks[0].id", () -> "fw");
        r.add("trust.clients[0].id", () -> "wallet");
        r.add("trust.clients[0].api-key", () -> "key-wallet");
        r.add("trust.clients[0].frameworks[0]", () -> "fw");
        r.add("trust.clients[1].id", () -> "ops");
        r.add("trust.clients[1].api-key", () -> "key-ops");
        r.add("trust.clients[1].admin", () -> "true");
        r.add("trust.auth.rate-limit.enabled", () -> "false");
        r.add("trust.revocation.fetch-anchor-crls", () -> "false");
        r.add("trust.mechanisms[0].id", () -> "university");
        r.add("trust.mechanisms[0].for.role", () -> "issuer");
        r.add("trust.mechanisms[0].for.formats[0]", () -> "vc+sd-jwt");
        r.add("trust.mechanisms[0].keys[0]", () -> "did");
        r.add("trust.mechanisms[0].did.methods[0]", () -> "web");
        r.add("trust.mechanisms[1].id", () -> "verifiers");
        r.add("trust.mechanisms[1].for.role", () -> "verifier");
        r.add("trust.mechanisms[1].x509.revocation", () -> "required");
    }

    @Autowired
    Environment env;
    @Autowired
    TrustSourceManager sources;

    final HttpClient http = HttpClient.newHttpClient();

    HttpResponse<String> send(String method, String path, String key, String body, String accept) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + env.getProperty("local.server.port") + path))
                .header("Accept", accept).header("Content-Type", "application/json");
        if (key != null) {
            b.header("Authorization", "Bearer " + key);
        }
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theSnapshotCarriesTheMechanismsInFormat5() throws Exception {
        HttpResponse<String> r = send("GET", "/api/v1/snapshot", "key-wallet", null, "application/jwt");
        assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
        Map<String, Object> claims = SignedJWT.parse(r.body()).getJWTClaimsSet().toJSONObject();
        assertThat(claims.get("format")).isEqualTo(5L);
        // One canonical form: camelCase, the canonical spelling of a format, in the order the operator listed them.
        assertThat(JSON.readTree(JSON.writeValueAsString(claims.get("mechanisms")))).isEqualTo(JSON.readTree("""
                [{"id": "university", "for": {"role": "issuer", "formats": ["dc+sd-jwt"]}, "keys": ["did"], "did": {"methods": ["web"]}},
                 {"id": "verifiers", "for": {"role": "verifier"}, "x509": {"revocation": "required"}}]"""));
    }

    @Test
    void discoveryNamesTheFormatAndAnOperatorSeesTheMechanisms() throws Exception {
        Map<String, Object> discovery = JSON.readValue(send("GET", "/.well-known/trust-service", null, null, "application/json").body(),
                new TypeReference<>() { });
        assertThat(discovery.get("snapshot_format")).isEqualTo(5);
        HttpResponse<String> summary = send("GET", "/admin/v1/registry", "key-ops", null, "application/json");
        assertThat(summary.statusCode()).as(summary.body()).isEqualTo(200);
        assertThat(JSON.readValue(summary.body(), new TypeReference<Map<String, Object>>() { }).get("mechanisms"))
                .isEqualTo(List.of("university", "verifiers"));
    }

    @Test
    void theServicesOwnDecisionsApplyThemAndNameThem() throws Exception {
        for (int i = 0; i < 200 && !sources.ready(); i++) {
            Thread.sleep(50);
        }
        String did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        HttpResponse<String> r = send("POST", "/api/v1/evaluate", "key-wallet", """
                {"role": "issuer", "subject": {"kid": "%s#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
                 "context": {"credentialFormat": "dc+sd-jwt"}}""".formatted(did), "application/json");
        assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
        Map<String, Object> d = JSON.readValue(r.body(), new TypeReference<>() { });
        assertThat(d.get("decision")).isEqualTo("NOT_TRUSTED");
        assertThat(((Map<?, ?>) d.get("evidence")).get("mechanism")).isEqualTo("university");
        assertThat(JSON.writeValueAsString(d.get("reasons"))).contains("mechanism.did_method_not_accepted");

        // A question no mechanism governs has no such member.
        Map<String, Object> other = JSON.readValue(send("POST", "/api/v1/evaluate", "key-wallet", """
                {"role": "issuer", "subject": {"identifier": "https://nobody.example"}}""", "application/json").body(), new TypeReference<>() { });
        assertThat(other.get("decision")).isEqualTo("UNKNOWN");
        assertThat(((Map<?, ?>) other.get("evidence")).containsKey("mechanism")).isFalse();
    }
}
