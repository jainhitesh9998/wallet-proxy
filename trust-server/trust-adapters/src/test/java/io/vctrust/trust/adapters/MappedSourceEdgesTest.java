package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.BASE;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.NOW;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.loadError;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.lookupOnly;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.MDL;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.boundList;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.boundMapping;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.decide;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.members;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What a third validation of the mapped source confirmed at the edge of the rules of the first two rounds. In a
 * registry where a valid chain to a listed CA is trusted by itself, an entity entry is what restricts a party: an entity
 * record is listed as the document states it, listed as not in good standing, or the load fails; it is never left out,
 * nor listed without what ties it to the party's key and to the question. Decided by the evaluator where a decision is
 * at stake.
 */
@SuppressWarnings("unchecked")
class MappedSourceEdgesTest {

    static Map<String, Object> block(Map<String, Object> mapping) {
        return (Map<String, Object>) ((List<?>) mapping.get("entities")).getFirst();
    }

    /** {@link MappedSourceValidationTest#boundList} with the second issuer ("college") given a role. */
    static Map<String, Object> withRoles(int version, Map<String, Object> dmv) {
        Map<String, Object> d = boundList(version, dmv);
        List<Object> issuers = new ArrayList<>((List<?>) d.get("issuers"));
        Map<String, Object> college = new LinkedHashMap<>((Map<String, Object>) issuers.get(1));
        college.put("roles", List.of("CREDENTIAL_ISSUER"));
        issuers.set(1, college);
        d.put("issuers", issuers);
        return d;
    }

    // 1: a record that yields no role keeps nobody out ---------------------------------------------------------------

    @Test
    void item1_anEntityRecordThatYieldsNoRoleFailsTheLoadAndItsPartyIsNotTrustedThroughTheAnchor() {
        Map<String, Object> m = boundMapping();
        block(m).put("roles", "$.roles[*]");
        Map<String, Map<String, Object>> roleless = new LinkedHashMap<>();
        roleless.put("roles: []", members("roles", List.of(), "state", "revoked"));
        roleless.put("no roles member", members("state", "revoked"));
        roleless.put("roles: [null]", members("roles", Collections.singletonList(null), "state", "revoked"));
        roleless.put("no role, and a date that cannot be read", members("state", "revoked",
                "valid_until", NOW.plus(Duration.ofDays(365)).toEpochMilli()));
        roleless.forEach((what, dmv) -> {
            // Listed without a role, the revoked issuer's entry answers no question about it, and the shared IACA
            // alone decides: TRUSTED. Its record says whom it is about in a way that keeps nobody out: the load fails.
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, dmv));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(decide(registry, MDL)).as(what).isNotEqualTo(Decision.TRUSTED);
                assertThat(state(manager, "partner").lastError()).as(what).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') "
                        + "cannot be read: it yields no role; ");
            }
            // A source that holds the issuer revoked keeps it so.
            ctx = ctx();
            serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "state", "revoked")));
            registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
                serveJson(ctx, withRoles(2, dmv));
                assertThat(manager.refresh("partner").lastError()).as(what).contains("it yields no role");
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
            }
        });
    }

    @Test
    void item1_aBlockThatMapsNoRolesIsAConfigurationError() {
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, Map.of()));
        Map<String, Object> m = boundMapping();
        block(m).remove("roles");
        assertThat(loadError(source(ctx, props("mapping", m)))).isEqualTo("Source 'partner' (mapped): mapping.entities[0]: roles is "
                + "required: an entity that yields no role answers no question, and keeps nobody out");
        Map<String, Object> lookup = lookupOnly();
        Map<String, Object> l = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) lookup.get("mapping")).get("lookup"));
        l.put("entity", Map.of("id", "$.id", "identifiers", List.of(Map.of("type", "DID", "value", "$.did"))));
        lookup.put("mapping", Map.of("lookup", l));
        assertThat(loadError(source(ctx, lookup))).contains("mapping.lookup.entity: roles is required");
        // allowEmpty says nothing about roles: a record without one fails the load all the same.
        block(m).put("roles", Map.of("path", "$.roles[*]", "allowEmpty", true));
        assertThat(loadError(source(ctx, props("mapping", m)))).contains("mapping.entities[0].roles: allowEmpty");
        assertThat(ctx.http.requests).isEmpty();
    }

    @Test
    void item1_aLookupAnswerThatYieldsNoRoleIsAFailedLookup() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> p = lookupOnly();
        Map<String, Object> l = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) p.get("mapping")).get("lookup"));
        Map<String, Object> entity = new LinkedHashMap<>((Map<String, Object>) l.get("entity"));
        entity.put("roles", "$.roles[*]");
        l.put("entity", entity);
        p.put("mapping", Map.of("lookup", l));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b", "roles", List.of())));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("cannot be read: it yields no role");
        assertThat(r.resolve(Identifier.did("did:example:b"))).isEmpty();   // remembered as a failure
        ctx.http.json(BASE + "did%3Aexample%3Ac", Json.write(Map.of("id", "c", "did", "did:example:c", "roles", List.of("VERIFIER"))));
        assertThat(r.resolve(Identifier.did("did:example:c"))).hasValueSatisfying(e -> assertThat(e.roles()).hasSize(1));
    }
}
