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
}
