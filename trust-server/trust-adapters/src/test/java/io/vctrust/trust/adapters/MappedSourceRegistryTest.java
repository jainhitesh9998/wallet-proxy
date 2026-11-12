package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.doc;
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
 * The mapped source on the registry it runs on: the registry escapes and cuts what a source reports, places an entity
 * whose id is another framework's name under its own framework's, bounds an anchor's CRL locations, and an entry that
 * is not in good standing and names no role keeps its party out whatever is asked. Where the registry does so, the
 * mapped source leans on it rather than refuse an honest list.
 */
@SuppressWarnings("unchecked")
class MappedSourceRegistryTest {

    // 1: a source's messages are escaped and cut by the registry, once --------------------------------------------------

    @Test
    void item1_whatTheSourceEscapedIsNotEscapedAgainInTheStateOrTheWarnings() {
        // A right-to-left override from the document, in a failed load and in a warning: the source writes it as an
        // escape, and the registry, which escapes what a source reports, leaves that escape as it is.
        TestContext ctx = ctx();
        Map<String, Object> d = doc("a");
        d.put("next_update", "soon‮evil");
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
            assertThat(state(m, "partner").lastError()).contains("no date there: 'soon\\u202eevil'").doesNotContain("\\\\u202")
                    .doesNotContain("‮");
        }
        Map<String, Object> mapping = MappedSourceAttacksTest.entities("validUntil", "$.valid_until");
        d = doc();
        d.put("issuers", List.of(Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active", "valid_until", "soon‮evil"),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", "active")));
        serveJson(ctx, d);
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", mapping)))) {
            assertThat(state(m, "partner").warnings()).singleElement().asString().endsWith("validUntil is not a date: 'soon\\u202eevil'")
                    .doesNotContain("\\\\u202").doesNotContain("‮");
        }
    }

    // 2: a record that states no role ---------------------------------------------------------------------------------

    static final String DS_SUBJECT = "CN=Utopia DS,O=Utopia DMV,C=UT";

    /** Issuers and verifiers, their roles a list that may be empty ("none stated"); two CAs that no entity owns. */
    static Map<String, Object> rolesMapping(Object roles) {
        return Json.parseObject("""
                {"entities": [{"each": "$.parties[*]", "id": "$.id", "roles": %s,
                   "identifiers": [{"each": "$.names[*]", "type": "$.type", "value": "$.value"}],
                   "certificates": "$.certificates[*]",
                   "status": {"path": "$.state", "values": {"active": "ACTIVE", "revoked": "REVOKED"}}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.id", "domain": "$.domain", "certificate": "$.certificate"}]}"""
                .formatted(Json.write(roles)));
    }

    static final Object ROLES_NONE_STATED = Map.of("path", "$.roles[*]", "allowEmpty", true);

    /** The list: {@code party} (left out when null) and a verifier elsewhere, under the IACA and the RP access CA. */
    static Map<String, Object> parties(Map<String, Object> party) {
        List<Object> parties = new ArrayList<>();
        if (party != null) {
            parties.add(party);
        }
        parties.add(Map.of("id", "elsewhere", "roles", List.of("VERIFIER"), "state", "active",
                "names", List.of(Map.of("type", "DNS", "value", "elsewhere.example"))));
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("parties", parties);
        d.put("cas", List.of(Map.of("id", "iaca", "domain", "mdoc-iaca", "certificate", der("iaca")),
                Map.of("id", "rp-ca", "domain", "verifier-access", "certificate", der("rp-ca"))));
        return d;
    }

    static TrustDecision asIssuer(TrustRegistry registry) {
        return MappedSourceFixturesTest.decide(registry, MappedSourceFixturesTest.issuer(null, List.of(der("ds")), "mso_mdoc", MDL));
    }

    static TrustDecision asVerifier(TrustRegistry registry) {
        return MappedSourceFixturesTest.decide(registry, new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject(
                "x509_san_dns:verifier.example", List.of(der("rp")), null, null),
                new TrustQuery.Context("oid4vp", null, null, null, "https://verifier.example/cb", List.of())));
    }

    @Test
    void item2_aRecordWhoseRolesAreThereAndEmptyIsListedWithoutARoleUnderAllowEmpty() {
        // The party bound by its certificates, or by names in them; withdrawn, with "roles": [].
        Map<String, Map<String, Object>> bindings = new LinkedHashMap<>();
        bindings.put("by its certificates", Map.of("certificates", List.of(der("ds"), der("rp"))));
        bindings.put("by names", Map.of("names", List.of(Map.of("type", "X509_SUBJECT", "value", DS_SUBJECT),
                Map.of("type", "DNS", "value", "verifier.example"))));
        // What the chains decide when the list says nothing about the party.
        TestContext ctx = ctx();
        serveJson(ctx, parties(null));
        TrustRegistry baseline = new TrustRegistry();
        try (TrustSourceManager m = manager(baseline, source(ctx, props("mapping", rolesMapping(ROLES_NONE_STATED))))) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(asIssuer(baseline).decision()).isEqualTo(Decision.TRUSTED);
            assertThat(asVerifier(baseline).decision()).isEqualTo(Decision.TRUSTED);
        }
        bindings.forEach((how, binding) -> {
            for (String state : List.of("revoked", "active")) {
                Map<String, Object> party = new LinkedHashMap<>(Map.of("id", "withdrawn", "roles", List.of(), "state", state));
                party.putAll(binding);
                TestContext c = ctx();
                serveJson(c, parties(party));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, source(c, props("mapping", rolesMapping(ROLES_NONE_STATED))))) {
                    String what = how + ", " + state;
                    assertThat(state(m, "partner").lastError()).as(what).isNull();
                    var listed = registry.snapshot().entity("withdrawn").orElseThrow();
                    assertThat(listed.roles()).as(what).isEmpty();
                    assertThat(listed.status().name()).as(what).isEqualTo(state.toUpperCase());
                    if (state.equals("revoked")) {
                        // Not in good standing and no role: it keeps its party out whatever is asked.
                        for (TrustDecision d : List.of(asIssuer(registry), asVerifier(registry))) {
                            assertThat(d.decision()).as(what).isEqualTo(Decision.NOT_TRUSTED);
                            assertThat(d.reasons()).as(what).extracting(r -> r.code()).contains("entity.status");
                        }
                    } else {
                        // In good standing and no role: it authorizes nothing, and the chains decide as without it.
                        assertThat(asIssuer(registry).decision()).as(what).isEqualTo(asIssuer(baseline).decision());
                        assertThat(asVerifier(registry).decision()).as(what).isEqualTo(asVerifier(baseline).decision());
                        assertThat(asIssuer(registry).entity()).as(what).isNull();
                    }
                }
            }
        });
    }

    @Test
    void item2_withoutAllowEmptyOrWhenTheListCannotBeReadARecordWithoutARoleStillFailsTheLoad() {
        Map<String, Object> revoked = new LinkedHashMap<>(Map.of("id", "withdrawn", "roles", List.of(), "state", "revoked",
                "certificates", List.of(der("ds"))));
        TestContext ctx = ctx();
        serveJson(ctx, parties(revoked));
        assertThat(loadError(source(ctx, props("mapping", rolesMapping("$.roles[*]"))))).startsWith("mapping.entities[0]: record 1 (id "
                + "'withdrawn') cannot be read: it yields no role");
        // Under allowEmpty: items that are null, a list a filter emptied, a role the translation does not know.
        Map<String, Object> cases = new LinkedHashMap<>();
        cases.put("roles: [null]", java.util.Collections.singletonList(null));
        cases.put("roles: [\"\"]", List.of(""));
        cases.forEach((what, roles) -> {
            revoked.put("roles", roles);
            serveJson(ctx, parties(revoked));
            assertThat(loadError(source(ctx, props("mapping", rolesMapping(ROLES_NONE_STATED))))).as(what)
                    .startsWith("mapping.entities[0]: record 1 (id 'withdrawn') cannot be read: roles: $.roles[*] finds a list whose items "
                            + "hold nothing");
        });
        revoked.put("roles", List.of("TEST_ONLY"));
        serveJson(ctx, parties(revoked));
        assertThat(loadError(source(ctx, props("mapping", rolesMapping(Map.of("path", "$.roles[?@ != 'TEST_ONLY']", "allowEmpty", true))))))
                .startsWith("mapping.entities[0]: record 1 (id 'withdrawn') cannot be read: roles: $.roles[?@ != 'TEST_ONLY'] finds a list "
                        + "but nothing it holds");
        assertThat(loadError(source(ctx, props("mapping", rolesMapping(Map.of("path", "$.roles[*]", "values",
                Map.of("issuer", "CREDENTIAL_ISSUER"), "allowEmpty", true)))))).startsWith("mapping.entities[0]: record 1 (id 'withdrawn') "
                + "cannot be read: roles: the path $.roles[*] finds 'TEST_ONLY', which its translation does not know");
        // Not there at all is no list: no role stated, and the load fails as without allowEmpty.
        revoked.remove("roles");
        serveJson(ctx, parties(revoked));
        assertThat(loadError(source(ctx, props("mapping", rolesMapping(ROLES_NONE_STATED))))).startsWith("mapping.entities[0]: record 1 "
                + "(id 'withdrawn') cannot be read: it yields no role");
    }

    // 3: ids with @ -------------------------------------------------------------------------------------------------

    /** {@link MappedSourceValidationTest#boundMapping()} with each record's id as the document writes it. */
    static Map<String, Object> idsAsWritten() {
        Map<String, Object> m = MappedSourceValidationTest.boundMapping();
        ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).put("id", "$.id");
        return m;
    }

    @Test
    void item3_anIdWithAnAtThatTheIdRuleAcceptsIsKeptAsWritten() {
        // An email address is a common id: it was listed under a derived id, SUSPENDED, since the registry dropped a
        // name that ends in @ and a framework's id.
        for (String state : List.of("active", "revoked")) {
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("id", "issuer@example.com", "state", state)));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", idsAsWritten())))) {
                assertThat(state(m, "partner").warnings()).as(state).isEmpty();
                var listed = registry.snapshot().entity("issuer@example.com").orElseThrow();
                assertThat(listed.status().name()).isEqualTo(state.toUpperCase());
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(state)
                        .isEqualTo(state.equals("active") ? Decision.TRUSTED : Decision.NOT_TRUSTED);
            }
        }
    }

    @Test
    void item3_anIdThatIsAnotherFrameworksNameIsPlacedByTheRegistryAndKeepsItsPartyOut() {
        // acme@other in a list of framework "national": the registry lists it as acme@other@national, and keeps it.
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("id", "acme@other", "state", "revoked")));
        TrustRegistry registry = new TrustRegistry();
        var s = source(ctx, "national-list", "national", props("mapping", idsAsWritten()));
        try (TrustSourceManager m = new TrustSourceManager(registry, List.of(
                new io.vctrust.trust.core.model.TrustFramework("national", "National", null, null, null),
                new io.vctrust.trust.core.model.TrustFramework("other", "Other", null, null, null)), List.of(s), java.time.Clock.systemUTC())) {
            m.refresh(s.id());
            var listed = registry.snapshot().entity("acme@other@national").orElseThrow();
            assertThat(listed.status()).isEqualTo(EntityStatus.REVOKED);
            assertThat(listed.frameworkId()).isEqualTo("national");
            assertThat(listed.certificates()).hasSize(1);
            assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(state(m, "national-list").warnings()).singleElement().asString()
                    .startsWith("Entity 'acme@other' is listed as 'acme@other@national'");
        }
    }

    // 4: CRL locations ------------------------------------------------------------------------------------------

    @Test
    void item4_anAnchorWithMoreCrlLocationsThanTheRegistryCountsIsPlacedWithTheFirst8() {
        // An honest CA that names more locations was skipped, and every party under it refused.
        Map<String, Object> m = MappedSourceValidationTest.boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "crlUrls", "$.crl_urls[*]")));
        Map<String, Decision> decided = new LinkedHashMap<>();
        for (int n : List.of(20, 8)) {
            Map<String, Object> d = MappedSourceValidationTest.boundList(1, Map.of());
            d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"), "crl_urls",
                    MappedSourceEdgesTest.crlUrls(n))));
            TestContext ctx = ctx();
            serveJson(ctx, d);
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(state(manager, "partner").lastError()).isNull();
                assertThat(registry.snapshot().allAnchors()).singleElement()
                        .satisfies(a -> assertThat(a.crlUrls()).isEqualTo(MappedSourceEdgesTest.crlUrls(8)));
                if (n == 20) {
                    assertThat(state(manager, "partner").warnings()).singleElement().asString().startsWith("Anchor 'shared-iaca' names 20 "
                            + "CRL locations (crlUrls); an anchor counts with at most 8");
                } else {
                    assertThat(state(manager, "partner").warnings()).isEmpty();
                }
                decided.put(n + " locations", MappedSourceValidationTest.decide(registry, MDL));
            }
        }
        assertThat(decided.get("20 locations")).isEqualTo(Decision.TRUSTED).isEqualTo(decided.get("8 locations"));
    }

    // 5: what else assumed the old registry: this service's own snapshot -------------------------------------------------

    static Map<String, Object> withItem(Map<String, Object> item) {
        return MappedSourceValidationTest.withAuthorizations(item);
    }

    static Map<String, Object> credential(Object type, boolean typed) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("format", "mso_mdoc");
        if (typed) {
            m.put("type", type);
        }
        return m;
    }

    @Test
    void item5_anAuthorizationThatStatesNoTypeCoversEveryTypeOfItsFormatUnderAllowAnyType() {
        // This service's snapshot writes an authorization for every type of a format without "type" (the vectors hold
        // such entries since the registry fixes); round one made such an item unreadable, so fixture 3 suspended them.
        Map<String, Object> anyType = new LinkedHashMap<>(Map.of("each", "$.credentials[*]", "allowAnyType", true, "format", "$.format",
                "type", "$.type"));
        Map<String, Object> strict = new LinkedHashMap<>(anyType);
        strict.remove("allowAnyType");
        for (Map<String, Object> credential : List.of(credential(null, false), credential(null, true), credential("", true))) {
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials", List.of(credential))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", withItem(anyType))))) {
                assertThat(state(m, "partner").lastError()).as(credential.toString()).isNull();
                assertThat(state(m, "partner").warnings()).as(credential.toString()).isEmpty();
                var dmv = registry.snapshot().entity("partner:dmv").orElseThrow();
                assertThat(dmv.status()).isEqualTo(EntityStatus.ACTIVE);
                assertThat(dmv.authorizations()).singleElement().satisfies(a -> assertThat(a.type()).isNull());
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
                assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).isEqualTo(Decision.TRUSTED);
            }
            // Without it, as before: the item lacks its type, and the record is listed SUSPENDED.
            registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", withItem(strict))))) {
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).isEqualTo(EntityStatus.SUSPENDED);
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            }
        }
        // A type that is there but cannot be read is not "no type".
        Map<String, Object> translated = new LinkedHashMap<>(anyType);
        translated.put("type", Map.of("path", "$.type", "values", Map.of("mdl", MDL)));
        Map<String, Map.Entry<Map<String, Object>, Map<String, Object>>> unreadable = new LinkedHashMap<>();
        unreadable.put("an object", Map.entry(credential(Map.of("id", MDL), true), anyType));
        unreadable.put("a value its translation does not know", Map.entry(credential("photo-id", true), translated));
        unreadable.forEach((what, c) -> {
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials", List.of(c.getKey()))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", withItem(c.getValue()))))) {
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).as(what).isEqualTo(EntityStatus.SUSPENDED);
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
            }
        });
        // Only on an authorization item whose type is read from the document.
        Map<String, Object> constant = new LinkedHashMap<>(anyType);
        constant.put("type", MDL);
        assertThat(loadError(source(ctx(), props("mapping", withItem(constant))))).contains("mapping.entities[0].authorizations[0]: "
                + "allowAnyType applies to an item whose type is read from a member of the item");
        Map<String, Object> identifiers = MappedSourceValidationTest.boundMapping();
        ((Map<String, Object>) ((List<?>) identifiers.get("entities")).getFirst()).put("identifiers", List.of(Map.of("type", "URL",
                "value", "$.credential_issuer", "allowAnyType", true)));
        assertThat(loadError(source(ctx(), props("mapping", identifiers)))).contains("mapping.entities[0].identifiers[0]: unknown member "
                + "[allowAnyType]");
    }
}
