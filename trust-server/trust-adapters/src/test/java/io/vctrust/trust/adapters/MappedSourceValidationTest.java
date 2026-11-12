package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSource;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.BASE;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.NOW;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.lookupOnly;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a second, independent validation of the mapped source confirmed after the first round of fixes, each
 * reproduced against the source, and where it matters decided by the evaluator: the document an attacker (or a
 * careless publisher) controls, and what a wallet is then told.
 */
@SuppressWarnings("unchecked")
class MappedSourceValidationTest {

    static final String MDL = "org.iso.18013.5.1.mDL";
    static final String PID = "eu.europa.ec.eudi.pid.1";

    // A: a record that cannot be read leaves its party trusted through the anchor ------------------------------------

    /**
     * Issuers bound to their signing certificates, under an IACA that the list shares among them (no entity, no
     * doctypes): a chain to it is trusted also without an entity, so only an issuer's entry can keep it out.
     */
    static Map<String, Object> boundMapping() {
        return Json.parseObject("""
                {"list": {"sequence": "$.version", "issuedAt": "$.issued"},
                 "entities": [{"each": "$.issuers[*]", "id": {"template": "partner:{$.id}"}, "roles": ["CREDENTIAL_ISSUER"],
                   "name": "$.name", "identifiers": [{"type": "URL", "value": "$.credential_issuer"}],
                   "certificates": "$.certificates[*]",
                   "authorizations": [{"each": "$.credentials[*]", "format": "$.format", "type": "$.type"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE", "suspended": "SUSPENDED"}, "default": "REVOKED"},
                   "validUntil": "$.valid_until"}],
                 "anchors": [{"each": "$.authorities[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate"}]}""");
    }

    /** The issuer "dmv" (the DS certificate, authorized for the mDL), with {@code members} put over it, and a second issuer. */
    static Map<String, Object> boundList(int version, Map<String, Object> members) {
        Map<String, Object> dmv = new LinkedHashMap<>();
        dmv.put("id", "dmv");
        dmv.put("name", "Utopia DMV");
        dmv.put("credential_issuer", "https://issuer.utopia.example");
        dmv.put("state", "active");
        dmv.put("certificates", List.of(der("ds")));
        dmv.put("credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL)));
        dmv.put("valid_until", NOW.plus(Duration.ofDays(365)).toString());
        members.forEach((k, v) -> {
            if (v == null) {
                dmv.remove(k);
            } else {
                dmv.put(k, v);
            }
        });
        Map<String, Object> d = MappedSourceRulesTest.doc(version, NOW.plus(Duration.ofDays(7)));
        d.put("issuers", List.of(dmv, Map.of("id", "college", "name", "College", "credential_issuer", "https://college.example",
                "state", "active")));
        d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"))));
        return d;
    }

    static Map<String, Object> members(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    /** The decision about a credential the DS certificate signed, of the given doctype. */
    static Decision decide(TrustRegistry registry, String docType) {
        return MappedSourceFixturesTest.decide(registry, MappedSourceFixturesTest.issuer(null, List.of(der("ds")), "mso_mdoc", docType))
                .decision();
    }

    @Test
    void a_aRecordThatCannotBeReadCompletelyIsListedSuspendedAndItsPartyIsNotTrusted() {
        record Row(String what, Map<String, Object> members, String docType, EntityStatus status, String warning) {
        }
        List<Row> rows = List.of(
                new Row("revoked, valid_until in milliseconds", members("state", "revoked",
                        "valid_until", NOW.plus(Duration.ofDays(365)).toEpochMilli()), MDL, EntityStatus.REVOKED, "validUntil is not a date"),
                new Row("revoked, an authorization item without type", members("state", "revoked",
                        "credentials", List.of(Map.of("format", "mso_mdoc"))), MDL, EntityStatus.REVOKED, "authorizations: an item yields no type"),
                new Row("active for the mDL, an item without type, asked about another doctype", members("credentials",
                        List.of(Map.of("format", "mso_mdoc", "type", MDL), Map.of("format", "mso_mdoc"))), PID, EntityStatus.SUSPENDED,
                        "authorizations: an item yields no type"),
                new Row("valid_until empty", members("valid_until", ""), MDL, EntityStatus.SUSPENDED, "validUntil is not a date: ''"),
                new Row("a date written with a space", members("valid_until", "2025-01-01 00:00:00"), MDL, EntityStatus.SUSPENDED,
                        "validUntil is not a date: '2025-01-01 00:00:00'"));
        for (Row row : rows) {
            TestContext ctx = ctx();
            serveJson(ctx, boundList(1, row.members()));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(state(m, "partner").lastError()).as(row.what()).isNull();
                assertThat(decide(registry, row.docType())).as(row.what()).isEqualTo(Decision.NOT_TRUSTED);
                TrustedEntity dmv = registry.snapshot().entity("partner:dmv").orElseThrow();
                assertThat(dmv.status()).as(row.what()).isEqualTo(row.status());
                // Listed with what identifies it, so that its certificate finds it.
                assertThat(dmv.certificates()).as(row.what()).hasSize(1);
                assertThat(dmv.identifiers()).as(row.what()).containsExactly(Identifier.url("https://issuer.utopia.example"));
                assertThat(state(m, "partner").warnings()).as(row.what()).singleElement().asString()
                        .startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') is listed " + row.status() + ": ").contains(row.warning());
            }
        }
        // The same issuer, read completely: the anchor and its entry decide.
        TestContext ctx = ctx();
        serveJson(ctx, boundList(1, Map.of()));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", boundMapping())))) {
            assertThat(state(m, "partner").warnings()).isEmpty();
            assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            assertThat(decide(registry, PID)).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void a_aRecordWhoseIdentifyingMembersCannotBeReadFailsTheLoadAndTheSourceKeepsWhatItHas() {
        // Version 1 lists the issuer revoked. Version 2 lists it revoked too, but in a way that cannot be read: a
        // record left out would leave its certificate to the anchor alone.
        Map<String, Map<String, Object>> unreadable = new LinkedHashMap<>();
        unreadable.put("its certificates hold something that is not one", members("state", "revoked",
                "certificates", List.of(der("ds"), "not a certificate")));
        unreadable.put("its certificates are one text, not a list", members("state", "revoked", "certificates", der("ds")));
        unreadable.put("it yields no id", members("state", "revoked", "id", null, "identifier", "dmv"));
        unreadable.put("its id breaks the admin API's rule", members("state", "revoked", "id", "dmv two"));
        Map<String, String> messages = Map.of(
                "its certificates hold something that is not one", "mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: ",
                "its certificates are one text, not a list", "mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: "
                        + "the path $.certificates[*] finds text where [*] needs a list or an object",
                "it yields no id", "mapping.entities[0]: record 1 cannot be read: it yields no id",
                "its id breaks the admin API's rule", "mapping.entities[0]: record 1 cannot be read: its id is not 1 to 128 letters");
        unreadable.forEach((what, members) -> {
            TestContext ctx = ctx();
            serveJson(ctx, boundList(1, members("state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
                serveJson(ctx, boundList(2, members));
                String error = m.refresh("partner").lastError();
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(error).as(what).startsWith(messages.get(what))
                        .contains("a record whose id, roles, identifiers or certificates cannot be read fails the load");
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).as(what).isEqualTo(EntityStatus.REVOKED);
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.NOT_TRUSTED);
            }
        });
    }

    @Test
    void a_aRoleOrAnIdentifierTheDocumentStatesButTheMappingCannotReadFailsTheLoad() {
        // A kind the roles' translation does not know: listed without a role, the entry would answer no question about
        // the party, and the anchor alone would decide about it.
        Map<String, Object> m = boundMapping();
        Map<String, Object> block = (Map<String, Object>) ((List<?>) m.get("entities")).getFirst();
        block.put("roles", Map.of("path", "$.kind", "values", Map.of("issuer", "CREDENTIAL_ISSUER")));
        TestContext ctx = ctx();
        serveJson(ctx, boundList(1, members("kind", "issuer-v2", "state", "revoked")));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", m)))).startsWith("mapping.entities[0]: record 1 (id "
                + "'partner:dmv') cannot be read: roles: 'issuer-v2' is not one of the values its translation knows");
        // With a kind it knows, or a default, it loads; a record without a kind has no role from it (absent is absent:
        // required: [roles] is how an operator says that every record has one).
        try {
            serveJson(ctx, boundList(1, members("kind", "issuer")));
            assertThat(source(ctx, props("mapping", m)).load().entities()).extracting(e -> e.id() + " " + e.roles())
                    .containsExactly("partner:dmv [CREDENTIAL_ISSUER]", "partner:college []");
            block.put("roles", Map.of("path", "$.kind", "values", Map.of("issuer", "CREDENTIAL_ISSUER"), "default", "CREDENTIAL_ISSUER"));
            serveJson(ctx, boundList(1, members("kind", "issuer-v2")));
            assertThat(source(ctx, props("mapping", m)).load().entities()).hasSize(2);
        } catch (io.vctrust.trust.core.spi.TrustSourceException e) {
            throw new AssertionError(e.getMessage());
        }

        // An identifier whose value is there but whose type is not: left out, the party's key would find no entry.
        Map<String, Object> typed = boundMapping();
        ((Map<String, Object>) ((List<?>) typed.get("entities")).getFirst()).put("identifiers",
                List.of(Map.of("each", "$.ids[*]", "type", "$.type", "value", "$.value")));
        serveJson(ctx, boundList(1, members("ids", List.of(Map.of("type", "X509_SUBJECT", "value", "CN=Utopia DS,O=Utopia DMV,C=UT"),
                Map.of("kind", "DID", "value", "did:example:dmv")))));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", typed)))).startsWith("mapping.entities[0]: record 1 (id "
                + "'partner:dmv') cannot be read: identifiers: an item yields value but no type");
        // An item that finds nothing at all is absent, as is one whose only path finds nothing.
        try {
            serveJson(ctx, boundList(1, members("ids", List.of(Map.of("comment", "none yet")))));
            assertThat(source(ctx, props("mapping", typed)).load().entities()).hasSize(2);
            serveJson(ctx, boundList(1, members("credential_issuer", null)));   // {type: URL, value: $.credential_issuer}
            assertThat(source(ctx, props("mapping", boundMapping())).load().entities()).filteredOn(e -> e.id().equals("partner:dmv"))
                    .singleElement().satisfies(e -> assertThat(e.identifiers()).isEmpty());
        } catch (io.vctrust.trust.core.spi.TrustSourceException e) {
            throw new AssertionError(e.getMessage());
        }
    }

    @Test
    void a_aBlockNoneOfWhoseRecordsCanBeReadCompletelyFailsTheLoad() {
        TestContext ctx = ctx();
        Map<String, Object> d = boundList(1, members("valid_until", "soon"));
        d.put("issuers", List.of(((List<?>) d.get("issuers")).getFirst()));
        serveJson(ctx, d);
        TrustSource s = source(ctx, props("mapping", boundMapping()));
        assertThat(MappedSourceRulesTest.loadError(s)).contains("mapping.entities[0]: none of the 1 records at $.issuers[*] could be read "
                + "completely; record 1 (id 'partner:dmv') is listed SUSPENDED: validUntil is not a date: 'soon'");
    }

    @Test
    void a_aLookupAnswerThatCannotBeReadCompletelyIsASuspendedEntityNotAMiss() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> p = lookupOnly();
        Map<String, Object> lookup = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) p.get("mapping")).get("lookup"));
        Map<String, Object> entity = new LinkedHashMap<>((Map<String, Object>) lookup.get("entity"));
        entity.put("validUntil", "$.valid_until");
        entity.put("status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE")));
        lookup.put("entity", entity);
        p.put("mapping", Map.of("lookup", lookup));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b", "state", "active",
                "valid_until", NOW.toEpochMilli())));
        assertThat(r.resolve(Identifier.did("did:example:b"))).hasValueSatisfying(e -> assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED));
        ctx.http.json(BASE + "did%3Aexample%3Ac", Json.write(Map.of("id", "c", "did", "did:example:c", "state", "closed")));
        assertThat(r.resolve(Identifier.did("did:example:c"))).hasValueSatisfying(e -> assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED));
        // What says whom the answer is about cannot be read: the lookup fails, and is remembered as a failure.
        ctx.http.json(BASE + "did%3Aexample%3Ad", Json.write(Map.of("id", "d", "did", Map.of("value", "did:example:d"), "state", "active")));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:d")))
                .hasMessageContaining("cannot be read: identifiers");
        assertThat(r.resolve(Identifier.did("did:example:d"))).isEmpty();
        assertThat(new ArrayList<>(ctx.http.requests)).hasSize(3);
    }
}
