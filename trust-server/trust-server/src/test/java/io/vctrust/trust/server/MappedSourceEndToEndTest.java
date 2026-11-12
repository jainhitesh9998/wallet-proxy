package io.vctrust.trust.server;

import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ListInfo;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;
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
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A service configured through YAML ({@code application-mapped-it.yml}, with the mapping inline) whose only source is
 * a mapped one: a registry in someone else's shape, in two pages, behind a bearer token. The service serves the
 * mapped parties in its own snapshot and decides about them.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("mapped-it")
class MappedSourceEndToEndTest {

    static final String TOKEN = "e2e-" + Long.toHexString(System.nanoTime());
    static final HttpServer REGISTRY;
    static final String BASE;
    static final AtomicInteger REFUSED = new AtomicInteger();
    static final Path PKI = pki();

    static Path pki() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        if (p == null) {
            throw new IllegalStateException("conformance/ not found");
        }
        return p.resolve("conformance/pki");
    }

    static String pem(String name) {
        try {
            return Files.readString(PKI.resolve(name + ".pem"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String der(String name) {
        return pem(name).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    }

    static {
        try {
            REGISTRY = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            BASE = "http://localhost:" + REGISTRY.getAddress().getPort();
            Instant now = Instant.now();
            String page1 = Json.write(Map.of(
                    "publisher", "Partner Registry", "version", 7, "issued", now.minus(Duration.ofHours(1)).toString(),
                    "next_update", now.plus(Duration.ofDays(1)).toString(),
                    "issuers", List.of(
                            Map.of("id", "utopia-dmv", "enabled", true, "state", "active", "country", "UT",
                                    "display", Map.of("name", "Utopia DMV"), "credential_issuer", "https://issuer.utopia.example",
                                    "credentials", List.of(Map.of("format", "mso_mdoc", "type", "org.iso.18013.5.1.mDL"))),
                            Map.of("id", "sandbox", "enabled", true, "kind", "test", "state", "active",
                                    "credential_issuer", "https://sandbox.example"),
                            Map.of("id", "retired", "enabled", false, "state", "active", "credential_issuer", "https://retired.example")),
                    "authorities", List.of(Map.of("kid", "utopia-iaca", "kind", "https://partner.example/kinds/iaca",
                            "certificate", pem("iaca"), "issuer_id", "utopia-dmv", "doctypes", List.of("org.iso.18013.5.1.mDL"))),
                    "links", Map.of("next", "/v1/issuers?page=2")));
            // A page repeats the facts of its list: a page that does not is not a page of this list.
            String page2 = Json.write(Map.of(
                    "publisher", "Partner Registry", "version", 7, "issued", now.minus(Duration.ofHours(1)).toString(),
                    "next_update", now.plus(Duration.ofDays(1)).toString(),
                    "issuers", List.of(Map.of("id", "suspended-college", "enabled", true, "state", "suspended",
                            "display", Map.of("name", "Suspended College"), "credential_issuer", "https://college.example")),
                    "links", Map.of()));
            REGISTRY.createContext("/v1/issuers", ex -> {
                byte[] body;
                int status = 200;
                if (!("Bearer " + TOKEN).equals(ex.getRequestHeaders().getFirst("Authorization"))) {
                    REFUSED.incrementAndGet();
                    status = 401;
                    body = "{}".getBytes(StandardCharsets.UTF_8);
                } else {
                    String query = ex.getRequestURI().getQuery();
                    body = ("page=2".equals(query) ? page2 : page1).getBytes(StandardCharsets.UTF_8);
                }
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(status, body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            REGISTRY.start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @AfterAll
    static void stop() {
        REGISTRY.stop(0);
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        Path data = Files.createTempDirectory("mapped-it");
        r.add("mapped-it.base", () -> BASE);
        r.add("mapped-it.token", () -> TOKEN);
        r.add("spring.datasource.url", () -> "jdbc:h2:mem:mapped-it;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        r.add("trust.service.signing-key-file", () -> data.resolve("key.jwk").toString());
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
        SourceState st = sources.states().getFirst();
        assertThat(st.lastError()).as("the mapped source loads").isNull();
        assertThat(sources.ready()).isTrue();
    }

    HttpResponse<String> call(String path, Object body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + env.getProperty("local.server.port") + path))
                .header("Authorization", "Bearer mapped-wallet-key");
        if (body != null) {
            b.POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).header("Content-Type", "application/json");
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theInlineMappingSurvivesSpringConfiguration() {
        SourceState st = sources.states().getFirst();
        // Each member below came through Spring's binding of nested maps and lists: list facts, pages, a filter with
        // && and quotes, templates, a translation as a map and one as {when, then} pairs, a root path, the headers.
        assertThat(st.type()).isEqualTo("mapped");
        assertThat(st.listInfo().issuer()).isEqualTo("Partner Registry");
        assertThat(st.listInfo().sequence()).isEqualTo("7");
        assertThat(st.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.NOT_SIGNED);
        assertThat(st.listInfo().details()).containsEntry("pages", 2);
        assertThat(st.entityCount()).isEqualTo(2);
        assertThat(st.anchorCount()).isEqualTo(1);
        assertThat(st.warnings()).isEmpty();
        assertThat(REFUSED).hasValue(0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void theMappedPartiesAreInTheServicesOwnSnapshotAndRegistry() throws Exception {
        var snapshot = call("/api/v1/snapshot", null);
        assertThat(snapshot.statusCode()).isEqualTo(200);
        Map<String, Object> claims = SignedJWT.parse(snapshot.body()).getJWTClaimsSet().getClaims();
        List<Map<String, Object>> entities = (List<Map<String, Object>>) claims.get("entities");
        assertThat(entities).extracting(e -> e.get("id")).containsExactlyInAnyOrder("partner:utopia-dmv", "partner:suspended-college");
        Map<String, Object> dmv = entities.stream().filter(e -> e.get("id").equals("partner:utopia-dmv")).findFirst().orElseThrow();
        assertThat(dmv.get("frameworkId")).isEqualTo("partner");
        assertThat((List<Map<String, Object>>) dmv.get("identifiers")).containsExactly(Map.of("type", "URL", "value", "https://issuer.utopia.example"));
        assertThat((Map<String, Object>) dmv.get("attributes")).containsEntry("country", "UT").containsEntry("publisher", "Partner Registry");
        assertThat(((Map<String, Object>) dmv.get("provenance")).get("sourceUri")).isEqualTo(BASE + "/v1/issuers");
        List<Map<String, Object>> anchors = (List<Map<String, Object>>) claims.get("anchors");
        assertThat(anchors).singleElement().satisfies(a -> {
            assertThat(a.get("id")).isEqualTo("utopia-iaca");
            assertThat(a.get("domain")).isEqualTo("mdoc-iaca");
            assertThat(a.get("entityId")).isEqualTo("partner:utopia-dmv");
            assertThat(((Map<String, Object>) a.get("constraints")).get("docTypes")).isEqualTo(List.of("org.iso.18013.5.1.mDL"));
        });

        var issuers = Json.parseObject(call("/api/v1/issuers", null).body());
        assertThat((List<Map<String, Object>>) issuers.get("items")).extracting(i -> i.get("id"))
                .containsExactlyInAnyOrder("partner:utopia-dmv", "partner:suspended-college");
    }

    @Test
    @SuppressWarnings("unchecked")
    void theServiceDecidesAboutTheMappedParties() throws Exception {
        var bySigner = Json.parseObject(call("/api/v1/evaluate", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(der("ds"))),
                "context", Map.of("credentialFormat", "mso_mdoc", "credentialType", "org.iso.18013.5.1.mDL"))).body());
        assertThat(bySigner.get("decision")).isEqualTo("TRUSTED");
        assertThat(((Map<String, Object>) bySigner.get("entity")).get("id")).isEqualTo("partner:utopia-dmv");
        assertThat(bySigner.get("summary")).isEqualTo("Trusted credential issuer 'Utopia DMV' in framework 'partner'");

        var notAuthorized = Json.parseObject(call("/api/v1/evaluate", Map.of("role", "issuer",
                "subject", Map.of("x5c", List.of(der("ds"))),
                "context", Map.of("credentialFormat", "mso_mdoc", "credentialType", "eu.europa.ec.eudi.pid.1"))).body());
        assertThat(notAuthorized.get("decision")).isEqualTo("NOT_TRUSTED");

        var byIdentifier = Json.parseObject(call("/api/v1/evaluate", Map.of("role", "issuer",
                "subject", Map.of("identifier", "https://issuer.utopia.example"))).body());
        assertThat(byIdentifier.get("decision")).isEqualTo("TRUSTED");
        var suspended = Json.parseObject(call("/api/v1/evaluate", Map.of("role", "issuer",
                "subject", Map.of("identifier", "https://college.example"))).body());
        assertThat(suspended.get("decision")).isEqualTo("NOT_TRUSTED");
        // Left out by the mapping's filter: disabled, or a test entry.
        for (String left : List.of("https://retired.example", "https://sandbox.example")) {
            var d = Json.parseObject(call("/api/v1/evaluate", Map.of("role", "issuer", "subject", Map.of("identifier", left))).body());
            assertThat(d.get("decision")).as(left).isEqualTo("UNKNOWN");
        }
    }
}
