package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.loadError;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.MDL;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a fifth validation of the mapped source found, each reproduced, and decided by the evaluator where a decision is
 * at stake. In a registry where a valid chain to a listed CA is trusted by itself, an entity entry is what restricts a
 * party: an entity record is listed as the document states it, listed as not in good standing, or the load fails; and a
 * party is listed under the name the other sources of its framework know it by.
 */
@SuppressWarnings("unchecked")
class MappedSourceRoundFiveTest {

    /** A decision about an issuer, with the source manager at hand for an on-demand lookup. */
    static TrustDecision decide(TrustRegistry registry, TrustSourceManager sources, String identifier, List<String> x5c, String type) {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(),
                Duration.ofHours(1)).evaluate(MappedSourceFixturesTest.issuer(identifier, x5c, x5c.isEmpty() ? null : "mso_mdoc", type),
                MappedSourceFixturesTest.CLIENT);
    }

    // 1: an id is kept as written whenever an entry can carry it ---------------------------------------------------------

    /** Ids as other sources write them: a URL, a name with a space. */
    static final List<String> IDS = List.of("https://dmv.utopia.example", "Utopia DMV");

    /** The operator's own static registry of the framework: the DMV withdrawn, under {@code id}. */
    static TrustSource withdrawnByTheOperator(TestContext ctx, String id) {
        ctx.put("mem:own.yaml", "entities:\n  - id: " + Json.write(id) + "\n    roles: [CREDENTIAL_ISSUER]\n    status: REVOKED\n");
        return new StaticTrustSourceFactory().create(new SourceDefinition("own", "static", "partner", null, true,
                Map.of("location", "mem:own.yaml")), ctx);
    }

    @Test
    void item1_aMappedCaIsTiedToTheEntityAnotherSourceListsUnderTheIdAsWritten() {
        for (boolean constant : List.of(false, true)) {
            for (String id : IDS) {
                Map<String, Object> mapping = Json.parseObject("""
                        {"anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate",
                           "entity": "$.issuer_id"}]}""");
                if (constant) {
                    ((Map<String, Object>) ((List<?>) mapping.get("anchors")).getFirst()).put("entity", id);
                }
                String as = id + (constant ? ", by a constant" : ", by $.issuer_id");
                TestContext ctx = ctx();
                TrustSource own = withdrawnByTheOperator(ctx, id);
                serveJson(ctx, Map.of("cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca"), "issuer_id", id))));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, own, source(ctx, props("mapping", mapping)))) {
                    assertThat(state(m, "partner").lastError()).as(as).isNull();
                    assertThat(state(m, "partner").warnings()).as(as).isEmpty();
                    assertThat(registry.snapshot().allAnchors()).as(as).singleElement()
                            .satisfies(a -> assertThat(a.entityId()).isEqualTo(id));
                    // Tied to sha256:..., the CA named nobody, and the chain to it decided alone: TRUSTED.
                    TrustDecision d = decide(registry, m, null, List.of(der("ds")), MDL);
                    assertThat(d.decision()).as(as).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(d.summary()).as(as).isEqualTo("Entity '" + id + "' is REVOKED");
                }
            }
        }
    }

    @Test
    void item1_aMappedPartyAndAnotherSourcesEntryOfItsIdAreOneEntry() {
        Map<String, Object> mapping = Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"], "certificates": "$.certificates[*]",
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate"}]}""");
        for (String id : IDS) {
            TestContext ctx = ctx();
            TrustSource own = withdrawnByTheOperator(ctx, id);
            serveJson(ctx, Map.of("issuers", List.of(Map.of("id", id, "state", "active", "certificates", List.of(der("ds"))),
                            Map.of("id", "college", "state", "active")),
                    "cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca")))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, own, source(ctx, props("mapping", mapping)))) {
                assertThat(state(m, "partner").warnings()).as(id).isEmpty();
                assertThat(registry.snapshot().entities()).as(id).extracting(e -> e.id() + " " + e.status())
                        .containsExactlyInAnyOrder(id + " REVOKED", "college ACTIVE");
                TrustedEntity one = registry.snapshot().entity(id).orElseThrow();
                assertThat(one.certificates()).as(id).hasSize(1);
                assertThat(one.attributes()).as(id).containsEntry("mergedFrom", List.of("own", "partner"));
                // Two entries before: the mapped one, under sha256:..., active and bound to the DS certificate: TRUSTED.
                TrustDecision d = decide(registry, m, null, List.of(der("ds")), MDL);
                assertThat(d.decision()).as(id).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.summary()).as(id).isEqualTo("Entity '" + id + "' is REVOKED");
            }
        }
    }

    /** The warning of a load that replaced one id: {@code quoted} is the first as a message quotes it. */
    static String replacedOne(String quoted, String derived) {
        return "1 id is listed under derived ids (sha256: and the SHA-256 of the id written), not being 1 to 512 characters free "
                + "of control, format and separator characters: the first, " + quoted + ", as '" + derived + "'";
    }

    @Test
    void item1_anIdAnEntryCannotCarryIsReplacedForTheEntityAndTheAnchorTieAlike() {
        Map<String, String> replaced = new LinkedHashMap<>();
        replaced.put("Utopia\nDMV", "'Utopia\\nDMV'");
        replaced.put("\u202EUtopia DMV", "'\\u202eUtopia DMV'");
        replaced.put("d".repeat(513), "'" + "d".repeat(40) + "…'");
        replaced.put(" ", "' '");   // blank: the registry format reads a blank id as none
        replaced.forEach((id, quoted) -> {
            String as = quoted;
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceProbesTest.tied(id, Map.of("state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
                String derived = MappedSourceProbesTest.derived(id);
                assertThat(state(m, "partner").lastError()).as(as).isNull();
                assertThat(registry.snapshot().entity(derived).orElseThrow().status()).as(as).isEqualTo(EntityStatus.REVOKED);
                assertThat(registry.snapshot().allAnchors()).as(as).singleElement()
                        .satisfies(a -> assertThat(a.entityId()).isEqualTo(derived));
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(as).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(state(m, "partner").warnings()).as(as).containsExactly(replacedOne(quoted, derived));
            }
        });
        // Half of a surrogate pair that stands alone (written as an escape in the JSON): replaced too.
        TestContext lone = ctx();
        serveJson(lone, Json.write(MappedSourceProbesTest.tied("dmv", Map.of("state", "revoked"))).replace("\"dmv\"", "\"\\ud800dmv\""));
        TrustRegistry r = new TrustRegistry();
        try (TrustSourceManager m = manager(r, source(lone, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
            String derived = MappedSourceProbesTest.derived("\ud800dmv");
            assertThat(r.snapshot().entity(derived)).isPresent();
            assertThat(r.snapshot().allAnchors()).singleElement().satisfies(a -> assertThat(a.entityId()).isEqualTo(derived));
            assertThat(MappedSourceValidationTest.decide(r, MDL)).isEqualTo(Decision.NOT_TRUSTED);
        }
        // Plain text of up to 512 characters is kept exactly as written: a DID with %3A, a name outside ASCII, an email
        // address, a base64 key identifier, text that only looks like a URL with a query, a name with spaces around it.
        for (String id : List.of("d".repeat(512), "did:web:x%3A8443", "名前", "issuer@example.com", "q83vEjRWeJ+/kQ==", " Utopia DMV ")) {
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceProbesTest.tied(id, Map.of("state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
                assertThat(state(m, "partner").warnings()).as(id).isEmpty();
                assertThat(registry.snapshot().entity(id).orElseThrow().status()).as(id).isEqualTo(EntityStatus.REVOKED);
                assertThat(registry.snapshot().allAnchors()).as(id).singleElement().satisfies(a -> assertThat(a.entityId()).isEqualTo(id));
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(id).isEqualTo(Decision.NOT_TRUSTED);
            }
        }
        // A message quotes an id as it quotes any text of the document, whatever the id: escaped, and cut at 40
        // characters. (It named the record by its number alone when the id broke the admin API's rule.)
        TestContext ctx = ctx();
        String url = "https://dmv.utopia.example/";
        Map<String, String> quotedAs = Map.of("Utopia\nDMV\u202E", "'Utopia\\nDMV\\u202e'", url + "d".repeat(100),
                "'" + url + "d".repeat(40 - url.length()) + "…'");
        quotedAs.forEach((id, quoted) -> {
            // Certificates written as one text, not a list: the record cannot be read before its id is given.
            serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("id", id, "certificates", der("ds"))));
            assertThat(loadError(source(ctx, props("mapping", MappedSourceRegistryTest.idsAsWritten())))).as(quoted)
                    .startsWith("mapping.entities[0]: record 1 (id " + quoted + ") cannot be read: certificates: the path "
                            + "$.certificates[*] finds text where [*] needs a list or an object");
        });
    }

    // 2: allowAnyType with a default on the type ----------------------------------------------------------------------

    /** The DS issuer authorized by {@code credentials} as {@code item} reads them, each credential of mso_mdoc without a type. */
    static TrustSourceManager authorizedBy(TrustRegistry registry, Map<String, Object> item) {
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials",
                List.of(Map.of("format", "mso_mdoc")))));
        return manager(registry, source(ctx, props("mapping", MappedSourceValidationTest.withAuthorizations(item))));
    }

    static Map<String, Object> typeItem(Object allowAnyType, Object type) {
        Map<String, Object> item = new LinkedHashMap<>(Map.of("each", "$.credentials[*]", "format", "$.format", "type", type));
        if (allowAnyType != null) {
            item.put("allowAnyType", allowAnyType);
        }
        return item;
    }

    @Test
    void item2_allowAnyTypeAndADefaultOnTheTypeAreAConfigurationError() {
        Map<String, Object> withDefault = Map.of("path", "$.type", "values", Map.of("mdl", MDL), "default", "none.at.all");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = authorizedBy(registry, typeItem(true, withDefault))) {
            // The default was ignored: the issuer was authorized for every type of mso_mdoc, and its PID was TRUSTED.
            assertThat(state(m, "partner").lastError()).isEqualTo("Source 'partner' (mapped): mapping.entities[0].authorizations[0]: "
                    + "allowAnyType and a default on type contradict each other: an item that states no type would get the default "
                    + "under one and cover every type of its format under the other; remove one");
            assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).isNotEqualTo(Decision.TRUSTED);
        }
        // Either alone reads as it did: the default (allowAnyType false or not said) authorizes the type it names;
        // allowAnyType without a default authorizes every type of the format.
        for (Object allowAnyType : java.util.Arrays.asList(false, null)) {
            TrustRegistry r = new TrustRegistry();
            try (TrustSourceManager m = authorizedBy(r, typeItem(allowAnyType, withDefault))) {
                assertThat(state(m, "partner").lastError()).as(String.valueOf(allowAnyType)).isNull();
                assertThat(r.snapshot().entity("partner:dmv").orElseThrow().authorizations()).as(String.valueOf(allowAnyType))
                        .singleElement().satisfies(a -> assertThat(a.type()).isEqualTo("none.at.all"));
                assertThat(MappedSourceValidationTest.decide(r, MappedSourceValidationTest.PID)).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(MappedSourceValidationTest.decide(r, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            }
        }
        TrustRegistry any = new TrustRegistry();
        try (TrustSourceManager m = authorizedBy(any, typeItem(true, Map.of("path", "$.type", "values", Map.of("mdl", MDL))))) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(MappedSourceValidationTest.decide(any, MappedSourceValidationTest.PID)).isEqualTo(Decision.TRUSTED);
        }
    }
}
