package io.vctrust.trust.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A service with trust.revocation.enabled: false fetches no CRL, ships none and relays none. Its own decisions still
 * give every certificate below an anchor a revocation status, UNKNOWN because nothing is checked, and a client that
 * requires a known status is refused, as its devices would refuse it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RevocationSwitchedOffServiceTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final TestPki.Issued IACA = TestPki.rootCa("CN=Switched-off IACA,C=UT");
    static final TestPki.Issued DS = TestPki.documentSigner("CN=Switched-off DS,C=UT", IACA);

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        Path dataDir = Files.createTempDirectory("trust-revocation-off");
        Path registry = dataDir.resolve("registry.yaml");
        // The anchor comes with a CRL pushed with it: with revocation on, it would be held, listed and shipped.
        Files.writeString(registry, """
                anchors:
                  - domain: mdoc-iaca
                    constraints:
                      crl: "%s"
                    certificate: |
                %s
                """.formatted(Base64.getEncoder().encodeToString(der(IACA)), Certificates.toPem(IACA.certificate()).indent(6)));
        r.add("spring.datasource.url", () -> "jdbc:h2:mem:trust-revocation-off;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        r.add("trust.service.signing-key-file", () -> dataDir.resolve("key.jwk").toString());
        r.add("trust.did.universal-resolver-url", () -> "");
        r.add("trust.frameworks[0].id", () -> "fw");
        r.add("trust.sources[0].id", () -> "reg");
        r.add("trust.sources[0].type", () -> "static");
        r.add("trust.sources[0].framework", () -> "fw");
        r.add("trust.sources[0].properties.location", () -> registry.toUri().toString());
        r.add("trust.clients[0].id", () -> "wallet");
        r.add("trust.clients[0].api-key", () -> "key-wallet");
        r.add("trust.clients[0].frameworks[0]", () -> "fw");
        r.add("trust.clients[1].id", () -> "strict");
        r.add("trust.clients[1].api-key", () -> "key-strict");
        r.add("trust.clients[1].frameworks[0]", () -> "fw");
        r.add("trust.clients[1].require-revocation-status", () -> "true");
        r.add("trust.clients[2].id", () -> "ops");
        r.add("trust.clients[2].api-key", () -> "key-ops");
        r.add("trust.clients[2].admin", () -> "true");
        r.add("trust.auth.rate-limit.enabled", () -> "false");
        r.add("trust.revocation.enabled", () -> "false");
    }

    static byte[] der(TestPki.Issued issuer) {
        try {
            return TestPki.crl(issuer).getEncoded();
        } catch (java.security.cert.CRLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Autowired
    Environment env;
    @Autowired
    TrustSourceManager sources;

    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void awaitReady() throws InterruptedException {
        for (int i = 0; i < 600 && !sources.ready(); i++) {
            Thread.sleep(50);
        }
        assertThat(sources.ready()).isTrue();
    }

    HttpResponse<String> send(String method, String path, String key, String body, String accept) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + env.getProperty("local.server.port") + path))
                .header("Accept", accept).header("Content-Type", "application/json").header("Authorization", "Bearer " + key);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    Map<String, Object> evaluate(String key) throws Exception {
        HttpResponse<String> r = send("POST", "/api/v1/evaluate", key, """
                {"role": "issuer", "subject": {"x5c": ["%s"]},
                 "context": {"credentialFormat": "mso_mdoc", "credentialType": "org.iso.18013.5.1.mDL"}}"""
                .formatted(Certificates.toBase64(DS.certificate())), "application/json");
        assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
        return JSON.readValue(r.body(), new TypeReference<>() { });
    }

    static List<String> codes(Map<String, Object> decision, String severity) {
        return ((List<?>) decision.get("reasons")).stream().map(x -> (Map<?, ?>) x).filter(x -> severity.equals(x.get("severity")))
                .map(x -> (String) x.get("code")).toList();
    }

    static List<?> revocation(Map<String, Object> decision) {
        return (List<?>) ((Map<?, ?>) ((Map<?, ?>) decision.get("evidence")).get("x509")).get("revocation");
    }

    @Test
    void theServicesOwnDecisionsHoldAnUnknownStatusToTheClientsRule() throws Exception {
        Map<String, Object> strict = evaluate("key-strict");
        assertThat(strict.get("decision")).as(strict.toString()).isEqualTo("NOT_TRUSTED");
        assertThat(codes(strict, "ERROR")).containsExactly("x509.revocation_unknown");
        assertThat(revocation(strict)).singleElement().satisfies(s -> {
            assertThat(((Map<?, ?>) s).get("status")).isEqualTo("UNKNOWN");
            assertThat(((Map<?, ?>) s).get("reason")).isEqualTo("revocation checking is switched off on this service");
        });

        Map<String, Object> lenient = evaluate("key-wallet");
        assertThat(lenient.get("decision")).as(lenient.toString()).isEqualTo("TRUSTED");
        assertThat(codes(lenient, "ERROR")).isEmpty();
        assertThat(codes(lenient, "WARNING")).contains("x509.revocation_unknown");
    }

    @Test
    void nothingElseAboutRevocationIsSwitchedBackOn() throws Exception {
        HttpResponse<String> snapshot = send("GET", "/api/v1/snapshot", "key-wallet", null, "application/jwt");
        assertThat(snapshot.statusCode()).as(snapshot.body()).isEqualTo(200);
        Map<String, Object> claims = SignedJWT.parse(snapshot.body()).getJWTClaimsSet().toJSONObject();
        assertThat(claims).containsKey("anchors").doesNotContainKey("crls");

        HttpResponse<String> crls = send("GET", "/admin/v1/crls", "key-ops", null, "application/json");
        assertThat(crls.statusCode()).as(crls.body()).isEqualTo(200);
        assertThat(JSON.readTree(crls.body())).isEqualTo(JSON.readTree("[]"));

        // Both relays answer that they are off, before anything is fetched.
        assertThat(send("GET", "/api/v1/proxy/crl?url=https%3A%2F%2Fcrl.example%2Fca.crl", "key-wallet", null, "application/pkix-crl")
                .statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/v1/proxy/status-list?uri=https%3A%2F%2Fstatus.example%2F1", "key-wallet", null, "application/statuslist+jwt")
                .statusCode()).isEqualTo(404);
    }
}
