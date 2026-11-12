package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.Reason;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * An answer fetched on demand (a mapped source's lookup, the federation and EBSI adapters) meets the registry's entry of
 * its id in the answering source's framework, and the two are merged as two entries of one id are. Taken as it was, the
 * answer stood beside the registry's entry: an operator's static file withdraws {@code Verifier Inc}, a partner's
 * registry answers a lookup about {@code verifier.example} with that id, active, and the verifier's chain to the
 * partner's CA was TRUSTED while the registry listed the id as REVOKED.
 */
class OnDemandAnswerMergeTest {

    /** The partner's verifiers, with the CA of their access certificates, and a lookup by DNS name. */
    static Map<String, Object> mapping() {
        return Json.parseObject("""
                {"list": {"sequence": "$.version"},
                 "entities": [{"each": "$.parties[*]", "id": "$.id", "roles": {"path": "$.roles[*]", "allowEmpty": true},
                   "identifiers": [{"each": "$.dns[*]", "type": "DNS", "value": "$"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "verifier-access", "certificate": "$.certificate"}],
                 "lookup": {"url": "https://registry.partner.example/v1/parties/{identifier}", "identifierTypes": ["DNS"],
                   "startsWith": ["verifier."],
                   "entity": {"id": "$.id", "roles": {"path": "$.roles[*]", "allowEmpty": true},
                     "identifiers": [{"each": "$.dns[*]", "type": "DNS", "value": "$"}],
                     "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}}}""");
    }

    /** The partner's list (another verifier, and the CA), and its answer about verifier.example: {@code id}, active, as {@code roles}. */
    static TrustSource partner(TestContext ctx, String id, List<String> roles) {
        serveJson(ctx, Map.of("version", 1,
                "parties", List.of(Map.of("id", "other-verifier", "roles", List.of("VERIFIER"), "dns", List.of("other.example"), "state", "active")),
                "cas", List.of(Map.of("kid", "rp-ca", "certificate", der("rp-ca")))));
        ctx.http.json("https://registry.partner.example/v1/parties/verifier.example", Json.write(Map.of("id", id, "roles", roles,
                "dns", List.of("verifier.example"), "state", "active")));
        return source(ctx, props("mapping", mapping()));
    }

    /** A static registry of {@code framework} with the entity {@code entity}, under source id {@code sourceId}. */
    static TrustSource registry(TestContext ctx, String sourceId, String framework, Map<String, Object> entity) {
        ctx.put("mem:" + sourceId + ".yaml", Json.write(Map.of("entities", List.of(entity))));
        return new StaticTrustSourceFactory().create(new SourceDefinition(sourceId, "static", framework, null, true,
                Map.of("location", "mem:" + sourceId + ".yaml")), ctx);
    }

    /** The operator's own registry of the framework: {@code id} withdrawn, as {@code roles}, with no identifier. */
    static TrustSource withdrawn(TestContext ctx, String id, List<String> roles) {
        return registry(ctx, "own", "partner", Map.of("id", id, "roles", roles, "status", "REVOKED"));
    }

    /** What a wallet is told about the verifier at verifier.example, which presents its access certificate. */
    static TrustDecision verifier(TrustRegistry registry, TrustSourceManager manager) {
        return new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example", List.of(der("rp")), null, null),
                        new TrustQuery.Context("oid4vp", null, null, null, "https://verifier.example/cb", List.of())), MappedSourceFixturesTest.CLIENT);
    }

    @Test
    void anAnswerOfAnIdAnotherSourceOfTheFrameworkWithdrawsIsNotTrusted() {
        for (String id : List.of("Verifier Inc", "verifier-inc")) {
            for (boolean ownFirst : List.of(true, false)) {
                String as = id + (ownFirst ? ", the operator's registry first" : ", the partner's registry first");
                TestContext ctx = ctx();
                TrustSource own = withdrawn(ctx, id, List.of("VERIFIER"));
                TrustSource partner = partner(ctx, id, List.of("VERIFIER"));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = ownFirst ? manager(registry, own, partner) : manager(registry, partner, own)) {
                    assertThat(state(m, "partner").lastError()).as(as).isNull();
                    assertThat(registry.snapshot().entity(id).orElseThrow().status()).as(as).isEqualTo(EntityStatus.REVOKED);
                    // The answer stood alone, active: TRUSTED through the partner's CA.
                    TrustDecision d = verifier(registry, m);
                    assertThat(d.decision()).as(as + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(d.entity().id()).as(as).isEqualTo(id);
                    assertThat(d.reasons()).as(as).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
                    assertThat(d.reasons()).as(as).extracting(Reason::code).contains("lookup.on_demand");
                }
            }
        }
    }

    @Test
    void aRoleLessWithdrawalHoldsAnAnswerThatNamesTheRoleAsked() {
        for (boolean ownFirst : List.of(true, false)) {
            TestContext ctx = ctx();
            TrustSource own = withdrawn(ctx, "Verifier Inc", List.of());
            TrustSource partner = partner(ctx, "Verifier Inc", List.of("VERIFIER"));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = ownFirst ? manager(registry, own, partner) : manager(registry, partner, own)) {
                TrustedEntity answer = m.resolveOnDemand(Identifier.of(io.vctrust.trust.core.model.IdentifierType.DNS, "verifier.example"),
                        f -> true).orElseThrow();
                // The withdrawal names no role, so the merged entry names none either, and is not left out of a question of one.
                assertThat(answer.roles()).isEmpty();
                assertThat(answer.status()).isEqualTo(EntityStatus.REVOKED);
                TrustDecision d = verifier(registry, m);
                assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
            }
        }
    }

    @Test
    void anAnswerMeetsTheEntryOfItsIdWhereTheRegistryListsIt() {
        // Framework "other" has "Verifier Inc" first, so the partner framework's "Verifier Inc" is listed as "Verifier Inc@partner".
        TestContext ctx = ctx();
        TrustSource elsewhere = registry(ctx, "elsewhere", "other", Map.of("id", "Verifier Inc", "roles", List.of("CREDENTIAL_ISSUER")));
        TrustSource own = withdrawn(ctx, "Verifier Inc", List.of("VERIFIER"));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, elsewhere, own, partner(ctx, "Verifier Inc", List.of("VERIFIER")))) {
            assertThat(registry.snapshot().entity("Verifier Inc@partner").orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
            TrustDecision d = verifier(registry, m);
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(d.entity().id()).isEqualTo("Verifier Inc@partner");
            assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
        }
    }

    @Test
    void anAnswerForAnIdTheRegistryDoesNotHoldInItsFrameworkIsUnchanged() throws Exception {
        // Another framework withdraws "Verifier Inc" for every role: that is no entry of the partner framework.
        TestContext ctx = ctx();
        TrustSource elsewhere = registry(ctx, "elsewhere", "other", Map.of("id", "Verifier Inc", "roles", List.of(), "status", "REVOKED"));
        TrustSource partner = partner(ctx, "Verifier Inc", List.of("VERIFIER"));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, elsewhere, partner)) {
            Identifier dns = Identifier.of(io.vctrust.trust.core.model.IdentifierType.DNS, "verifier.example");
            TrustedEntity answered = ((OnDemandResolver) partner).resolve(dns).orElseThrow();
            assertThat(m.resolveOnDemand(dns, f -> true)).contains(answered);
            assertThat(answered.status()).isEqualTo(EntityStatus.ACTIVE);
            assertThat(answered.attributes()).doesNotContainKey("mergedFrom");
            assertThat(verifier(registry, m).decision()).isEqualTo(Decision.TRUSTED);
        }
        // Nor does an answer of an id nobody else lists meet anything.
        TestContext alone = ctx();
        TrustSource own = withdrawn(alone, "Verifier Inc", List.of("VERIFIER"));
        TrustSource other = partner(alone, "Verifier Inc (new)", List.of("VERIFIER"));
        TrustRegistry r = new TrustRegistry();
        try (TrustSourceManager m = manager(r, own, other)) {
            Identifier dns = Identifier.of(io.vctrust.trust.core.model.IdentifierType.DNS, "verifier.example");
            assertThat(m.resolveOnDemand(dns, f -> true)).contains(((OnDemandResolver) other).resolve(dns).orElseThrow());
            assertThat(verifier(r, m).decision()).isEqualTo(Decision.TRUSTED);
        }
    }
}
