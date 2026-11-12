package io.vctrust.trust.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.x509.Certificates;
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The service is the reference for trust decisions; client libraries must reach the same ones from the snapshot.
 * A test of this kind turns a file of cases (a registry and queries) into evaluation vectors: the snapshot the service
 * signs for a lenient and a strict client, and for every query the outcome of {@code POST /api/v1/evaluate}. A client
 * library passes when it reaches the same outcomes from those snapshots (packages/trust-client/test/vectors.test.ts).
 * There are two pairs: {@link EvaluationVectorsTest} ({@code cases.json}, {@code vectors.json}: a service without trust
 * mechanisms) and {@link MechanismVectorsTest} ({@code mechanisms.cases.json}, {@code mechanisms.vectors.json}: the same
 * registry and one more anchor, under the operator's mechanisms).
 *
 * <p>The checked-in vectors must equal what the service produces now. After a deliberate change to the rules,
 * regenerate them with {@code mvn test -Dtest='*VectorsTest' -Dvectors.update=true -Dsurefire.failIfNoSpecifiedTests=false}
 * and review the diff: every changed line is a change in what clients are told to trust.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
abstract class EvaluationVectors {

    static final Path ROOT = repositoryRoot();
    static final Path PKI = ROOT.resolve("conformance/pki");
    /** The first pair, which the second's questions without a mechanism are held to. */
    static final Path FIRST_PAIR_VECTORS = ROOT.resolve("conformance/evaluation/vectors.json");
    static final List<String> PROFILES = List.of("lenient", "strict");
    static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    /** {@code pem:NAME}, {@code pki:NAME}, {@code crl:NAME}, {@code sha256:NAME}, {@code aki:NAME}, {@code subject:NAME} at the end of a string. */
    static final Pattern REFERENCE = Pattern.compile("^(|.*:)(pem|pki|crl|sha256|aki|subject):([a-z0-9-]+)$");

    static Path repositoryRoot() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        if (p == null) {
            throw new IllegalStateException("conformance/ not found above " + Path.of("").toAbsolutePath());
        }
        return p;
    }

    /** The file of cases this test reads. */
    abstract Path cases();

    /** The vectors it writes, and checks. */
    abstract Path vectors();

    /** The name of the test, written into the vectors it generates. */
    abstract String generatedBy();

    /** Whether the service runs with trust mechanisms: the outcome then names the one that governed each query. */
    abstract boolean withMechanisms();

    /**
     * The service of one pair: its own database (each pair loads a registry of its own into its own), the frameworks,
     * the managed source and the clients both pairs share.
     */
    static void service(DynamicPropertyRegistry r, String database) throws IOException {
        Path dataDir = Files.createTempDirectory(database);
        r.add("spring.datasource.url", () -> "jdbc:h2:mem:" + database + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        r.add("trust.service.signing-key-file", () -> dataDir.resolve("key.jwk").toString());
        r.add("trust.service.issuer", () -> "https://trust.test");
        r.add("trust.did.universal-resolver-url", () -> "");
        r.add("trust.frameworks[0].id", () -> "vectors");
        r.add("trust.frameworks[0].name", () -> "Conformance vectors");
        r.add("trust.sources[0].id", () -> "managed");
        r.add("trust.sources[0].type", () -> "managed");
        r.add("trust.sources[0].framework", () -> "vectors");
        r.add("trust.clients[0].id", () -> "lenient");
        r.add("trust.clients[0].api-key", () -> "key-lenient");
        r.add("trust.clients[0].frameworks[0]", () -> "vectors");
        r.add("trust.clients[1].id", () -> "strict");
        r.add("trust.clients[1].api-key", () -> "key-strict");
        r.add("trust.clients[1].frameworks[0]", () -> "vectors");
        r.add("trust.clients[1].strict-authorization", () -> "true");
        r.add("trust.clients[1].require-revocation-status", () -> "true");
        r.add("trust.clients[2].id", () -> "admin");
        r.add("trust.clients[2].api-key", () -> "key-admin");
        r.add("trust.clients[2].admin", () -> "true");
        r.add("trust.auth.rate-limit.enabled", () -> "false");
        // Nothing is fetched: the vectors must not depend on the network.
        r.add("trust.revocation.fetch-on-demand", () -> "false");
        // Nor the CRL of an anchor from its distribution point: one of the anchors is a real CA whose CRL can be
        // fetched, and whether it had arrived when a query was decided would decide the outcome.
        r.add("trust.revocation.fetch-anchor-crls", () -> "false");
    }

    @Autowired
    Environment env;
    @Autowired
    TrustSourceManager sources;

    final HttpClient http = HttpClient.newHttpClient();

    @Test
    void theServiceDecidesAsTheVectorsSay() throws Exception {
        for (int i = 0; i < 600 && !sources.ready(); i++) {
            Thread.sleep(50);
        }
        assertThat(sources.ready()).isTrue();
        Map<String, Object> input = resolve(JSON.readValue(cases().toFile(), new TypeReference<>() { }));
        Map<String, Map<String, Object>> registry = cast(input.get("registry"));
        for (String kind : List.of("entities", "anchors")) {
            for (Map.Entry<String, Object> e : registry.get(kind).entrySet()) {
                HttpResponse<String> put = send("PUT", "/admin/v1/managed/" + kind + "/" + e.getKey(), "key-admin", e.getValue());
                assertThat(put.statusCode()).as("%s %s: %s", kind, e.getKey(), put.body()).isLessThan(300);
            }
        }

        // CRLs pushed with an anchor are verified and held in the background, after the registry changed: the snapshot
        // and the decisions below are taken once they are there, however slow the machine.
        int pushedCrls = (int) registry.get("anchors").values().stream()
                .filter(a -> a instanceof Map<?, ?> anchor && anchor.get("constraints") instanceof Map<?, ?> c && c.get("crl") != null).count();
        Map<String, Object> snapshots = new LinkedHashMap<>();
        for (String profile : PROFILES) {
            snapshots.put(profile, snapshot(profile, registry.get("anchors").size(), pushedCrls));
        }
        List<Map<String, Object>> cases = new ArrayList<>();
        for (Map<String, Object> c : EvaluationVectors.<List<Map<String, Object>>>cast(input.get("cases"))) {
            Map<String, Object> expect = new LinkedHashMap<>();
            for (String profile : PROFILES) {
                HttpResponse<String> r = send("POST", "/api/v1/evaluate", "key-" + profile, c.get("query"));
                assertThat(r.statusCode()).as("%s: %s", c.get("name"), r.body()).isEqualTo(200);
                Map<String, Object> decision = JSON.readValue(r.body(), new TypeReference<>() { });
                if (!withMechanisms()) {
                    // Without mechanisms no decision names one: the evidence has no such member.
                    assertThat(EvaluationVectors.<Map<String, Object>>cast(decision.get("evidence"))).as("%s", c.get("name")).doesNotContainKey("mechanism");
                }
                expect.put(profile, outcome(decision, withMechanisms()));
            }
            Map<String, Object> out = new LinkedHashMap<>(c);
            out.put("expect", expect);
            cases.add(out);
        }
        heldToTheFirstPair(cases);
        Map<String, Object> vectors = new LinkedHashMap<>();
        vectors.put("description", "Generated by " + generatedBy() + " from " + cases().getFileName() + "; do not edit. 'snapshots' are the claims the service signs "
                + "for a lenient and a strict client, 'expect' the outcome of its own evaluation of each query for each of them.");
        vectors.put("snapshots", snapshots);
        vectors.put("cases", cases);

        if (Boolean.getBoolean("vectors.update")) {
            DefaultPrettyPrinter printer = new DefaultPrettyPrinter();
            printer.indentArraysWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE.withLinefeed("\n"));
            printer.indentObjectsWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE.withLinefeed("\n"));
            Files.writeString(vectors(), JSON.writer(printer).writeValueAsString(vectors) + "\n");
            return;
        }
        assertThat(Files.exists(vectors())).as("%s is missing: generate it with -Dvectors.update=true", vectors()).isTrue();
        Map<String, Object> checkedIn = JSON.readValue(vectors().toFile(), new TypeReference<>() { });
        List<Map<String, Object>> expected = cast(checkedIn.get("cases"));
        assertThat(cases).as("number of cases; regenerate with -Dvectors.update=true").hasSameSizeAs(expected);
        for (int i = 0; i < cases.size(); i++) {
            assertThat(tree(cases.get(i))).as("case '%s' (regenerate with -Dvectors.update=true after a deliberate change)", cases.get(i).get("name"))
                    .isEqualTo(tree(expected.get(i)));
        }
        assertThat(tree(snapshots)).as("snapshots (regenerate with -Dvectors.update=true after a deliberate change)").isEqualTo(tree(checkedIn.get("snapshots")));
    }

    /**
     * A case that asks a question of the first pair ({@code sameAsFirstPair}: its name there) must be decided as it is
     * there: a question no mechanism governs exactly so, and one a mechanism governs without adding a refusal too. The
     * mechanism the outcome names is all that may differ.
     */
    void heldToTheFirstPair(List<Map<String, Object>> cases) throws IOException {
        List<Map<String, Object>> firstPair = cast(JSON.readValue(FIRST_PAIR_VECTORS.toFile(), new TypeReference<Map<String, Object>>() { }).get("cases"));
        for (Map<String, Object> c : cases) {
            Object name = c.get("sameAsFirstPair");
            if (name == null) {
                continue;
            }
            Map<String, Object> there = firstPair.stream().filter(f -> name.equals(f.get("name"))).findFirst()
                    .orElseThrow(() -> new AssertionError("'" + c.get("name") + "' names a case the first pair does not have: " + name));
            assertThat(tree(c.get("query"))).as("'%s' asks the question of '%s'", c.get("name"), name).isEqualTo(tree(there.get("query")));
            Map<String, Map<String, Object>> expect = cast(c.get("expect"));
            for (String profile : PROFILES) {
                Map<String, Object> here = new LinkedHashMap<>(expect.get(profile));
                here.remove("mechanism");
                assertThat(tree(here)).as("'%s' (%s) is decided as '%s' is in the first pair", c.get("name"), profile, name)
                        .isEqualTo(tree(EvaluationVectors.<Map<String, Object>>cast(there.get("expect")).get(profile)));
            }
        }
    }

    /** The value as it reads back from JSON, so that 4 and 4L, or a list and an array, compare equal. */
    static JsonNode tree(Object value) throws IOException {
        return JSON.readTree(JSON.writeValueAsString(value));
    }

    /** The snapshot's content claims, without what differs between runs (issue time, when a source was read). */
    Map<String, Object> snapshot(String profile, int anchors, int crls) throws Exception {
        Map<String, Object> claims = Map.of();
        for (int i = 0; i < 300; i++) {
            HttpResponse<String> r = send("GET", "/api/v1/snapshot", "key-" + profile, null);
            assertThat(r.statusCode()).as(r.body()).isEqualTo(200);
            claims = new LinkedHashMap<>(SignedJWT.parse(r.body()).getJWTClaimsSet().toJSONObject());
            // The claim is there from the start, as an empty list: wait for the CRLs themselves.
            if (EvaluationVectors.<List<Object>>cast(claims.getOrDefault("anchors", List.of())).size() == anchors
                    && EvaluationVectors.<List<Object>>cast(claims.getOrDefault("crls", List.of())).size() >= crls) {
                break;
            }
            Thread.sleep(100);
        }
        assertThat(EvaluationVectors.<List<Object>>cast(claims.getOrDefault("crls", List.of()))).as("the snapshot carries the pushed CRLs").hasSizeGreaterThanOrEqualTo(crls);
        for (String volatileClaim : List.of("iss", "aud", "iat", "exp", "nbf", "jti", "client_id")) {
            claims.remove(volatileClaim);
        }
        for (String list : List.of("entities", "anchors", "frameworks")) {
            List<Map<String, Object>> sorted = new ArrayList<>(EvaluationVectors.<List<Map<String, Object>>>cast(claims.get(list)));
            sorted.sort(Comparator.comparing(m -> String.valueOf(m.get("id"))));
            claims.put(list, sorted);
        }
        // The anchors' CRLs follow the order the registry lists the anchors in, which the vectors do not fix either.
        if (claims.containsKey("crls")) {
            List<Map<String, Object>> held = new ArrayList<>(EvaluationVectors.<List<Map<String, Object>>>cast(claims.get("crls")));
            held.sort(Comparator.comparing(m -> m.get("issuer") + "|" + m.get("url")));
            claims.put("crls", held);
        }
        return cast(strip(claims));
    }

    static Object strip(Object o) {
        if (o instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> {
                if (!"retrievedAt".equals(k)) {
                    out.put(String.valueOf(k), strip(v));
                }
            });
            return out;
        }
        return o instanceof List<?> l ? l.stream().map(EvaluationVectors::strip).toList() : o;
    }

    /**
     * What a client library must reproduce: the decision, the error and warning reason codes, the entity and what it
     * was matched by, the path validation result with each certificate's revocation status, and which
     * trusted_authorities matched; under mechanisms ({@code withMechanism}), also the one that governed the query (null:
     * none). Reasons that describe where the decision was made rather than what it is are left out.
     */
    static Map<String, Object> outcome(Map<String, Object> d, boolean withMechanism) {
        List<Map<String, Object>> reasons = cast(d.getOrDefault("reasons", List.of()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("decision", d.get("decision"));
        out.put("errors", codes(reasons, "ERROR"));
        out.put("warnings", codes(reasons, "WARNING"));
        out.put("entity", d.get("entity") instanceof Map<?, ?> e ? e.get("id") : null);
        Map<String, Object> evidence = d.get("evidence") instanceof Map<?, ?> ? cast(d.get("evidence")) : Map.of();
        if (evidence.get("x509") instanceof Map<?, ?> x) {
            Map<String, Object> x509 = new LinkedHashMap<>();
            x509.put("valid", x.get("valid"));
            x509.put("anchorFound", x.get("anchorFound"));
            x509.put("revocation", x.get("revocation") instanceof List<?> l ? l.stream().map(s -> ((Map<?, ?>) s).get("status")).toList() : List.of());
            out.put("x509", x509);
        } else {
            out.put("x509", null);
        }
        // For each trusted_authorities query, the value that matched (null: none).
        out.put("trustedAuthorities", evidence.get("trustedAuthorities") instanceof List<?> l
                ? l.stream().map(t -> Boolean.TRUE.equals(((Map<?, ?>) t).get("matched")) ? ((Map<?, ?>) t).get("matchedValue") : null).toList() : List.of());
        out.put("framework", d.get("framework") instanceof Map<?, ?> f ? f.get("id") : null);
        out.put("matched", evidence.get("matchedIdentifiers") instanceof List<?> l ? l.stream().map(String::valueOf).sorted().toList() : List.of());
        if (withMechanism) {
            out.put("mechanism", evidence.get("mechanism"));
        }
        return out;
    }

    static List<String> codes(List<Map<String, Object>> reasons, String severity) {
        return new ArrayList<>(new TreeSet<>(reasons.stream().filter(r -> severity.equals(r.get("severity")))
                .map(r -> String.valueOf(r.get("code"))).filter(c -> !c.startsWith("local.") && !c.startsWith("snapshot.")).toList()));
    }

    /** Replaces references to the shared test PKI with the material they name. */
    @SuppressWarnings("unchecked")
    static <T> T resolve(T o) throws IOException {
        if (o instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), resolve(e.getValue()));
            }
            return (T) out;
        }
        if (o instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object x : l) {
                out.add(resolve(x));
            }
            return (T) out;
        }
        if (!(o instanceof String s)) {
            return o;
        }
        Matcher ref = REFERENCE.matcher(s);
        if (!ref.matches()) {
            return o;
        }
        String kind = ref.group(2);
        Path file = PKI.resolve(ref.group(3) + ("crl".equals(kind) ? ".crl" : ".pem"));
        if (!Files.exists(file)) {
            throw new IllegalArgumentException("cases.json refers to " + s + ", but there is no " + file);
        }
        if ("crl".equals(kind)) {
            return (T) (ref.group(1) + Base64.getEncoder().encodeToString(Files.readAllBytes(file)));
        }
        if ("pem".equals(kind)) {
            return (T) (ref.group(1) + Files.readString(file));
        }
        X509Certificate cert = Certificates.fromPemBundle(Files.readAllBytes(file)).get(0);
        return (T) (ref.group(1) + switch (kind) {
            case "pki" -> Certificates.toBase64(cert);
            case "sha256" -> Certificates.sha256Thumbprint(cert);
            case "subject" -> Certificates.subjectName(cert);
            default -> Certificates.subjectKeyIdentifier(cert).orElseThrow();
        });
    }

    HttpResponse<String> send(String method, String path, String key, Object body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + env.getProperty("local.server.port") + path))
                .header("Authorization", "Bearer " + key).header("Content-Type", "application/json")
                .header("Accept", path.endsWith("/snapshot") ? "application/jwt" : "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @SuppressWarnings("unchecked")
    static <T> T cast(Object o) {
        return (T) o;
    }
}
