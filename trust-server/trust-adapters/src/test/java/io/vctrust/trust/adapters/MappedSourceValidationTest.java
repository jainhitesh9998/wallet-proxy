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
    void a_aRequiredMemberThatSaysWhomTheRecordIsAboutAndYieldsNothingFailsTheLoad() {
        // The partner renamed signing_certificates: listed without its certificate (and suspended), the issuer's key
        // would be tied to no entry, and the anchor alone would decide about it.
        Map<String, Object> m = boundMapping();
        ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).put("required", List.of("certificates"));
        Map<String, Object> d = boundList(1, members("state", "revoked", "certificates", null, "signing_certificates", List.of(der("ds"))));
        d.put("issuers", List.of(((List<?>) d.get("issuers")).getFirst(), Map.of("id", "college", "credential_issuer",
                "https://college.example", "state", "active", "certificates", List.of(der("ds-nl")))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(decide(registry, MDL)).isNotEqualTo(Decision.TRUSTED);
            assertThat(state(manager, "partner").lastError()).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be "
                    + "read: certificates is required and yields nothing");
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

    // B: what one record may weigh ---------------------------------------------------------------------------------

    /** The partner's list with {@code n} issuers, and {@code root} put into its root. */
    static Map<String, Object> issuers(int n, Map<String, Object> root) {
        Map<String, Object> d = MappedSourceRulesTest.doc();
        List<Object> issuers = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            issuers.add(Map.of("id", "p" + i, "credential_issuer", "https://p" + i + ".example", "state", "active"));
        }
        d.put("issuers", issuers);
        d.putAll(root);
        return d;
    }

    @Test
    void b_oneMappedTextValueIsAtMost8192Characters() throws Exception {
        // name: ^.publisher repeats the root's text into every record: 2,000 records of a 200 kB publisher were
        // 400,000,000 characters from a 350 kB document.
        TestContext ctx = ctx();
        serveJson(ctx, issuers(3, Map.of("publisher_name", "P".repeat(8_193))));
        Map<String, Object> m = MappedSourceAttacksTest.entities("name", "^.publisher_name");
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", m)))).contains("none of the 3 records at $.issuers[*] "
                + "could be read completely; record 1 (id 'partner:p0') is listed SUSPENDED: name: a value of 8193 characters, "
                + "more than 8192");
        serveJson(ctx, issuers(3, Map.of("publisher_name", "P".repeat(8_192))));
        assertThat(source(ctx, props("mapping", m)).load().entities()).hasSize(3).allSatisfy(e -> assertThat(e.status()).isEqualTo(EntityStatus.ACTIVE));
        // So inside an attribute that is an object, and for an anchor (skipped) and an identifier (the load fails).
        serveJson(ctx, issuers(1, Map.of("meta", Map.of("note", "N".repeat(8_193)))));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", MappedSourceAttacksTest.entities("attributes",
                Map.of("meta", "^.meta")))))).contains("is listed SUSPENDED: attributes.meta: a value of 8193 characters, more than 8192");
        Map<String, Object> d = issuers(1, Map.of());
        d.put("issuers", List.of(Map.of("id", "p0", "credential_issuer", "https://p0.example/" + "x".repeat(8_200), "state", "active")));
        serveJson(ctx, d);
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props()))).contains("record 1 (id 'partner:p0') cannot be read: "
                + "identifiers.value: a value of 8219 characters, more than 8192");
        // A list fact is held to the same bound; it goes into the source's state.
        serveJson(ctx, issuers(1, Map.of("publisher", "P".repeat(8_193))));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props()))).contains("mapping.list.issuer: a value of 8193 characters, more than 8192");
    }

    @Test
    void b_oneRecordYieldsAtMost65536CharactersOfMappedText() throws Exception {
        // contexts: ^.contexts[*] at the cap of 1,000 values made 5,000,000 entries; ten values of 8,000 characters
        // each are 80,000 characters for every record.
        List<Object> contexts = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            contexts.add("https://contexts.example/" + i + "/" + "c".repeat(7_970));
        }
        TestContext ctx = ctx();
        Map<String, Object> d = issuers(2, Map.of("contexts", contexts));
        d.put("issuers", List.of(Map.of("id", "p0", "credential_issuer", "https://p0.example", "state", "active", "ctx", contexts),
                Map.of("id", "p1", "credential_issuer", "https://p1.example", "state", "active", "ctx", contexts.subList(0, 8))));
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", MappedSourceAttacksTest.entities("contexts", "$.ctx[*]"))).load();
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status()).containsExactly("partner:p0 SUSPENDED", "partner:p1 ACTIVE");
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 1 (id 'partner:p0') is listed SUSPENDED: contexts: the record's "
                + "mapped text would be more than 65536 characters");
        assertThat(r.entities().getFirst().attributes()).doesNotContainKey(io.vctrust.trust.core.metadata.Oid4vciMetadataMapper.CONTEXTS);
    }

    @Test
    void b_aLoadYieldsAtMostLimitsTextCharactersOfMappedText() throws Exception {
        TestContext ctx = ctx();
        serveJson(ctx, issuers(40, Map.of()));
        // About 60 characters a record: id, role, URL identifier, status.
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("limits", Map.of("text", 1_000)))))
                .contains("The list's records yield more than 1000 characters of mapped text (limits.text)");
        assertThat(source(ctx, props("limits", Map.of("text", 10_000))).load().entities()).hasSize(40);
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("limits", Map.of("text", "lots")))))
                .contains("limits.text must be a positive whole number");
    }

    @Test
    void b_valuesAPathSelectsCountTowardTheThousandWhetherOrNotTheyBecomeValues() throws Exception {
        // A root path over 400,000 nulls took seconds for 2,000 records, because nulls were not counted.
        List<Object> nulls = new ArrayList<>(java.util.Collections.nCopies(1_001, null));
        List<Object> codes = new ArrayList<>(java.util.Collections.nCopies(1_001, "unknown"));
        TestContext ctx = ctx();
        serveJson(ctx, issuers(2, Map.of("nothing", nulls, "codes", codes)));
        Map<String, String> members = new LinkedHashMap<>();
        members.put("contexts", "^.nothing[*]");
        members.put("name", "^.nothing[*]");
        for (Map.Entry<String, String> e : members.entrySet()) {
            assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", MappedSourceAttacksTest.entities(e.getKey(), e.getValue())))))
                    .as(e.getKey()).contains("is listed SUSPENDED: " + e.getKey() + ": yields more than 1000 values for one record");
        }
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", MappedSourceAttacksTest.entities("attributes",
                Map.of("code", Map.of("path", "^.codes[*]", "values", Map.of("known", "yes")))))))).contains("is listed SUSPENDED: "
                + "attributes.code: yields more than 1000 values for one record");
        assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", MappedSourceAttacksTest.entities("name",
                Map.of("template", "x{^.nothing[*]}")))))).contains("is listed SUSPENDED: name: yields more than 1000 values for one record");
        // A thousand are read.
        serveJson(ctx, issuers(2, Map.of("nothing", nulls.subList(0, 1_000))));
        assertThat(source(ctx, props("mapping", MappedSourceAttacksTest.entities("contexts", "^.nothing[*]"))).load().warnings()).isEmpty();
    }

    // C: whoever serves the pages can leave one out ------------------------------------------------------------------

    static final String PAGE_2 = MappedSourceRulesTest.LOCATION + "?page=2";
    static final String PAGE_3 = MappedSourceRulesTest.LOCATION + "?page=3";

    /** Page {@code k} of 3 of the partner's signed list (version 5): page 2 revokes "b". */
    static Map<String, Object> page(int k, Integer number, Integer count) {
        Map<String, Object> d = MappedSourceRulesTest.doc(5, NOW.plus(Duration.ofDays(7)));
        d.put("issuers", List.of(switch (k) {
            case 1 -> Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active");
            case 2 -> Map.of("id", "b", "credential_issuer", "https://b.example", "state", "revoked");
            default -> Map.of("id", "c", "credential_issuer", "https://c.example", "state", "active");
        }));
        if (k < 3) {
            d.put("next", k == 1 ? PAGE_2 : PAGE_3);
        }
        if (number != null) {
            d.put("page", number);
        }
        if (count != null) {
            d.put("pages", count);
        }
        return d;
    }

    static Map<String, Object> signedPages(com.nimbusds.jose.jwk.ECKey key, Map<String, Object> pages) {
        Map<String, Object> m = MappedSourceAttacksTest.pagedMapping(Map.of("sequence", "$.version"));
        m.put("pages", pages);
        return props("format", "jws", "verify", Map.of("jwks", MappedTesting.jwks(key)), "mapping", m);
    }

    static void serve(TestContext ctx, com.nimbusds.jose.jwk.ECKey key, String url, Map<String, Object> page) {
        ctx.http.respond(url, 200, "application/jwt", MappedTesting.utf8(MappedTesting.sign(key, page)));
    }

    @Test
    void c_aPageServedInPlaceOfAnotherIsNoticedByItsNumberOrByTheCount() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        // Page 3 served at page 2's address: page 2, which revokes "b", is gone; the pages still agree on the list facts.
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, 1, 3));
        serve(ctx, k1, PAGE_2, page(3, 3, 3));
        Map<String, Object> numbered = signedPages(k1, Map.of("next", "$.next", "number", "$.page"));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, numbered))).contains("Page 2 of the list says it is page 3");
        Map<String, Object> counted = signedPages(k1, Map.of("next", "$.next", "count", "$.pages"));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("The list says it has 3 pages, and 2 were read");
        // Served as they are, they load.
        serve(ctx, k1, PAGE_2, page(2, 2, 3));
        serve(ctx, k1, PAGE_3, page(3, 3, 3));
        Map<String, Object> both = signedPages(k1, Map.of("next", "$.next", "number", "$.page", "count", "$.pages"));
        for (Map<String, Object> p : List.of(numbered, counted, both)) {
            var r = source(ctx, p).load();
            assertThat(r.entities()).extracting(e -> e.id() + " " + e.status())
                    .containsExactly("partner:a ACTIVE", "partner:b REVOKED", "partner:c ACTIVE");
            assertThat(r.warnings()).isEmpty();
        }
        // A first page may count from 0.
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, 0, 3));
        serve(ctx, k1, PAGE_2, page(2, 1, 3));
        serve(ctx, k1, PAGE_3, page(3, 2, 3));
        assertThat(source(ctx, numbered).load().entities()).hasSize(3);
        serve(ctx, k1, PAGE_3, page(3, 3, 3));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, numbered))).contains("Page 3 of the list says it is page 3, not 2");
    }

    @Test
    void c_theCountIsTheSameOnEveryPageAndThePagesReadAreThatMany() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        Map<String, Object> counted = signedPages(k1, Map.of("next", "$.next", "count", "$.pages"));
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, null, 3));
        serve(ctx, k1, PAGE_2, page(2, null, 2));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("Page 2 of the list says it has 2 pages where page 1 says 3");
        // More pages than it says.
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, null, 2));
        serve(ctx, k1, PAGE_2, page(2, null, 2));
        serve(ctx, k1, PAGE_3, page(3, null, 2));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("The list says it has 2 pages, and page 2 links to another");
        // A count, or a number, that is not one; one missing; more pages than pages.max.
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, null, null));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("mapping.pages.count: page 1 of the list has no number there");
        Map<String, Object> first = page(1, null, null);
        first.put("pages", "three");
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, first);
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("mapping.pages.count: page 1 of the list has no number "
                + "there: 'three'");
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, null, 51));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, counted))).contains("The list says it has 51 pages, more than 50 (mapping.pages.max)");
        assertThat(MappedSourceRulesTest.loadError(source(ctx, signedPages(k1, Map.of("next", "$.next", "number", "$.page")))))
                .contains("mapping.pages.number: page 1 of the list has no number there");
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, 2, null));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, signedPages(k1, Map.of("next", "$.next", "number", "$.page")))))
                .contains("Page 1 of the list says it is page 2; a first page is 0 or 1");
    }

    @Test
    void c_signedPagesWithoutNumberOrCountLoadWithAWarningOnEveryLoad() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        serve(ctx, k1, MappedSourceRulesTest.LOCATION, page(1, null, null));
        serve(ctx, k1, PAGE_2, page(3, null, null));   // page 3 in place of page 2: nothing can tell
        TrustSource s = source(ctx, signedPages(k1, Map.of("next", "$.next")));
        String warning = "The list comes in pages that are signed one by one and say neither their number nor their count "
                + "(mapping.pages.number, mapping.pages.count): whoever serves them can leave one out";
        for (int i = 0; i < 2; i++) {
            var r = s.load();
            assertThat(r.entities()).extracting(e -> e.id()).containsExactly("partner:a", "partner:c");
            assertThat(r.warnings()).containsExactly(warning);
        }
        // Not for a list in one page, nor for pages the transport alone vouches for.
        Map<String, Object> plain = MappedSourceAttacksTest.pagedMapping(Map.of("sequence", "$.version"));
        serveJson(ctx, page(1, null, null));
        ctx.http.json(PAGE_2, Json.write(page(3, null, null)));
        assertThat(source(ctx, props("mapping", plain)).load().warnings()).isEmpty();
    }

    // D: allowExpired reached signed lookup answers ---------------------------------------------------------------

    static Map<String, Object> signedLookup(com.nimbusds.jose.jwk.ECKey key, Object... extra) {
        Map<String, Object> p = lookupOnly(extra);
        p.put("format", "jws");
        p.put("verify", Map.of("jwks", MappedTesting.jwks(key)));
        return p;
    }

    @Test
    void d_aLookupAnswerIsNeverAcceptedPastItsExpWhateverAllowExpiredSays() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        Map<String, Object> p = signedLookup(k1);
        p.put("allowExpired", true);   // for a list the operator decides to keep using, not for answers
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        long now = NOW.getEpochSecond();
        serve(ctx, k1, BASE + "did%3Aexample%3Ab", Map.of("id", "b", "did", "did:example:b",
                "iat", now - Duration.ofDays(900).toSeconds(), "exp", now - Duration.ofDays(899).toSeconds()));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b")))
                .hasMessageContaining("The answer expired at").hasMessageContaining("allowExpired does not apply to lookup answers");
        serve(ctx, k1, BASE + "did%3Aexample%3Ac", Map.of("id", "c", "did", "did:example:c", "iat", now, "exp", now + 600));
        assertThat(r.resolve(Identifier.did("did:example:c"))).isPresent();
    }

    @Test
    void d_anAnswerIsRememberedNoLongerThanItIsGoodFor() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        MappedSourceRulesTest.MutableClock clock = new MappedSourceRulesTest.MutableClock(NOW);
        ctx.clock = clock;
        OnDemandResolver r = (OnDemandResolver) source(ctx, signedLookup(k1));
        long now = NOW.getEpochSecond();
        // Good for one more minute by its exp; then for one more minute by its iat and lookup.maxAge (24 hours).
        serve(ctx, k1, BASE + "did%3Aexample%3Ab", Map.of("id", "b", "did", "did:example:b", "iat", now, "exp", now + 60));
        serve(ctx, k1, BASE + "did%3Aexample%3Ac", Map.of("id", "c", "did", "did:example:c",
                "iat", now - Duration.ofHours(24).toSeconds() + 60));
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(r.resolve(Identifier.did("did:example:c"))).isPresent();
        assertThat(ctx.http.requests).hasSize(2);
        clock.now = NOW.plusSeconds(59);
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(r.resolve(Identifier.did("did:example:c"))).isPresent();
        assertThat(ctx.http.requests).hasSize(2);
        // Past what they are good for, they are asked again (and now refused), not served from memory for ten minutes.
        clock.now = NOW.plusSeconds(121);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).hasMessageContaining("expired");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:c")))
                .hasMessageContaining("(lookup.maxAge)");
        assertThat(ctx.http.requests).hasSize(4);
    }

    // E: messages ---------------------------------------------------------------------------------------------------

    static final String FORGED = "x\r\n2026-11-12 03:00:00 WARN Trust source 'partner' (mapped): all good";

    static String b64(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(MappedTesting.utf8(json));
    }

    /** A compact JWS with this header, whose signature is not checked before what the test is about. */
    static String withHeader(String header) {
        return b64(header) + "." + b64(Json.write(MappedSourceRulesTest.doc("a"))) + ".c2ln";
    }

    @Test
    void e_textFromOutsideReachesNoMessageUnescaped() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        String forged = Json.write(FORGED);   // as a JSON string, with its escapes
        Map<String, String> errors = new LinkedHashMap<>();
        MappedSourceRulesTest.serveJws(ctx, withHeader("{\"alg\":" + forged + ",\"kid\":\"k1\"}"));
        errors.put("alg", MappedSourceRulesTest.loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", MappedTesting.jwks(k1))))));
        MappedSourceRulesTest.serveJws(ctx, withHeader("{\"alg\":\"ES256\",\"typ\":" + forged + ",\"kid\":\"k1\"}"));
        errors.put("typ", MappedSourceRulesTest.loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", MappedTesting.jwks(k1),
                "typ", "partner-list+jwt")))));
        // The issuer of an x5c certificate, which the path validation names.
        var builder = new org.bouncycastle.asn1.x500.X500NameBuilder(org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
                .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "x\r\n2026-11-12 WARN Trust source forged");   // at most 64
        io.vctrust.trust.core.testing.TestPki.Issued stranger = MappedSourceAttacksTest.certificate(builder.build().toString(), null, false,
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature);
        io.vctrust.trust.core.testing.TestPki.Issued root = io.vctrust.trust.core.testing.TestPki.rootCa("CN=Partner List CA,C=UT");
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(stranger, stranger, MappedSourceRulesTest.doc("a")));
        errors.put("x5c", MappedSourceRulesTest.loadError(source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(root.certificate())))))));
        errors.forEach((what, error) -> assertThat(error).as(what).contains("WARN Trust source").doesNotContain("\r").doesNotContain("\n"));
        assertThat(errors.get("alg")).contains("The list is signed with x\\r\\n2026-11-12");
        assertThat(errors.get("typ")).contains("typ is 'x\\r\\n2026-11-12");
        assertThat(errors.get("x5c")).contains("does not validate to a pinned certificate").contains("x\\r\\n2026-11-12");
    }

    @Test
    void e_noMessageIsLongerThan2000Characters() {
        // A framework name the source does not load into, in every record: the first failure named all of it.
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc();
        d.put("issuers", List.of(Map.of("id", "a", "credential_issuer", "https://a.example", "framework", "f".repeat(8_000))));
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceAttacksTest.entities("framework", "$.framework"))))) {
            String error = state(m, "partner").lastError();
            assertThat(error).startsWith("mapping.entities[0]: none of the 1 records at $.issuers[*] could be read completely; record 1 "
                    + "(id 'partner:a') is skipped: Entity partner:a names framework 'ffff").hasSize(2_000).endsWith("…");
        }
    }

    @Test
    void e_theQueryOfAUrlIsCutUpToTheNextWhitespaceAndALookupUrlHoldsNoUserInformation() {
        TestContext ctx = ctx();
        String location = MappedSourceRulesTest.LOCATION + "?key=part1'part2";   // MappingLanguageTest: " and < too
        ctx.http.respond(location, 401, "application/json", MappedTesting.utf8("{}"));
        String error = MappedSourceRulesTest.loadError(source(ctx, props("location", location)));
        assertThat(error).contains("401").contains(MappedSourceRulesTest.LOCATION).doesNotContain("part1").doesNotContain("part2");
        // The lookup URL, like location, holds no credentials.
        Map<String, Object> lookup = lookupOnly();
        Map<String, Object> l = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) lookup.get("mapping")).get("lookup"));
        l.put("url", "https://user:s3cret@registry.partner.example/v1/issuers/{identifier}");
        lookup.put("mapping", Map.of("lookup", l));
        assertThat(MappedSourceRulesTest.loadError(source(ctx, lookup))).contains("mapping.lookup.url must not hold credentials")
                .doesNotContain("s3cret");
    }

    // F: the lookup memo ------------------------------------------------------------------------------------------

    @Test
    void f_anIdentifierLongerThan4096CharactersIsNotAskedAbout() throws Exception {
        TestContext ctx = ctx();
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        Identifier longest = Identifier.did("did:example:" + "a".repeat(4_096 - "did:example:".length()));
        Identifier tooLong = Identifier.did("did:example:" + "a".repeat(4_097 - "did:example:".length()));
        assertThat(r.canResolve(longest)).isTrue();
        assertThat(r.canResolve(tooLong)).isFalse();
        assertThat(r.resolve(tooLong)).isEmpty();
        assertThat(ctx.http.requests).isEmpty();
        assertThat(r.resolve(longest)).isEmpty();   // asked (FakeHttp: 404)
        assertThat(ctx.http.requests).hasSize(1);
    }

    @Test
    void f_aNumberWhoseScaleOverflowsIsTooLargeAndNoUncheckedExceptionLeavesTheSource() throws Exception {
        for (String number : List.of("100e2147483647", "-100e2147483647", "1e2147483648", "1e-2147483649", "10e-2147483648")) {
            TestContext ctx = ctx();
            ctx.http.json(MappedSourceRulesTest.LOCATION, MappedSourceAttacksTest.list("\"n\": " + number));
            TrustSource s = source(ctx, props());
            org.assertj.core.api.Assertions.assertThatThrownBy(s::load).as(number).isInstanceOf(io.vctrust.trust.core.spi.TrustSourceException.class)
                    .hasMessageContaining("holds a number with more than 40 significant digits or a decimal exponent outside -40 to 40");
            OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
            ctx.http.json(BASE + "did%3Aexample%3Ab", "{\"id\": \"b\", \"did\": \"did:example:b\", \"n\": " + number + "}");
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).as(number)
                    .isInstanceOf(io.vctrust.trust.core.spi.TrustSourceException.class).hasMessageContaining("holds a number");
            assertThat(r.resolve(Identifier.did("did:example:b"))).isEmpty();   // remembered as a failure
            assertThat(ctx.http.requests).as(number).hasSize(2);
        }
        // Whatever else goes wrong inside is a failure of the source, not an exception of another kind.
        TestContext ctx = ctx();
        io.vctrust.trust.core.spi.SourceContext broken = new io.vctrust.trust.core.spi.SourceContext() {
            @Override
            public io.vctrust.trust.core.spi.HttpFetcher http() {
                return request -> {
                    throw new IllegalStateException("the client is broken");
                };
            }

            @Override
            public io.vctrust.trust.core.spi.ResourceLoader resources() {
                return ctx.resources();
            }

            @Override
            public java.time.Clock clock() {
                return ctx.clock();
            }
        };
        TrustSource s = new io.vctrust.trust.adapters.mapped.MappedSourceFactory().create(
                new io.vctrust.trust.core.spi.SourceDefinition("partner", "mapped", "partner", null, true, props()), broken);
        org.assertj.core.api.Assertions.assertThatThrownBy(s::load).isInstanceOf(io.vctrust.trust.core.spi.TrustSourceException.class)
                .hasMessageContaining("the client is broken");
        OnDemandResolver r = (OnDemandResolver) new io.vctrust.trust.adapters.mapped.MappedSourceFactory().create(
                new io.vctrust.trust.core.spi.SourceDefinition("partner", "mapped", "partner", null, true, lookupOnly()), broken);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b")))
                .isInstanceOf(io.vctrust.trust.core.spi.TrustSourceException.class).hasMessageContaining("the client is broken");
        assertThat(r.resolve(Identifier.did("did:example:b"))).isEmpty();
    }

    // G: the same thing twice -----------------------------------------------------------------------------------

    @Test
    void g_aLookupAnswerWithSeveralRecordsAboutTheIdentifierHoldsTheStrictest() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> p = lookupOnly("entity", Map.of("each", "$.entries[*]", "id", "$.id", "roles", List.of("CREDENTIAL_ISSUER"),
                "identifiers", List.of(Map.of("type", "DID", "value", "$.did")),
                "status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE", "revoked", "REVOKED")),
                "validUntil", "$.valid_until"));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        java.time.Instant soon = NOW.plus(Duration.ofDays(1));
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("entries", List.of(
                Map.of("id", "b", "did", "did:example:b", "state", "active", "valid_until", NOW.plus(Duration.ofDays(30)).toString()),
                Map.of("id", "b", "did", "did:example:b", "state", "revoked", "valid_until", soon.toString()),
                Map.of("id", "x", "did", "did:example:x", "state", "active")))));
        assertThat(r.resolve(Identifier.did("did:example:b"))).hasValueSatisfying(e -> {
            assertThat(e.id()).isEqualTo("b");
            assertThat(e.status()).isEqualTo(EntityStatus.REVOKED);
            assertThat(e.validUntil()).isEqualTo(soon);
        });
    }

    @Test
    void g_oneCertificateUnderTwoAnchorIdsInOneDomainMustSayTheSameThing() {
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE"), "default", "REVOKED"))));
        Map<String, Object> d = boundList(1, members("certificates", null));   // the issuer bound by nothing but the anchor
        d.put("authorities", List.of(Map.of("kid", "row-1", "certificate", der("iaca"), "state", "active"),
                Map.of("kid", "row-7", "certificate", der("iaca"), "state", "withdrawn")));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(decide(registry, MDL)).isNotEqualTo(Decision.TRUSTED);
            assertThat(state(manager, "partner").lastError()).isEqualTo("Anchors 'row-1' and 'row-7' have the same certificate in domain "
                    + "mdoc-iaca and a different status: which one holds cannot be told");
        }
        // Records that agree are two anchors of one certificate; one in another domain is another anchor.
        d.put("authorities", List.of(Map.of("kid", "row-1", "certificate", der("iaca"), "state", "active"),
                Map.of("kid", "row-7", "certificate", der("iaca"), "state", "active")));
        serveJson(ctx, d);
        try {
            assertThat(source(ctx, props("mapping", m)).load().anchors()).extracting(a -> a.id()).containsExactly("row-1", "row-7");
            Map<String, Object> other = boundMapping();
            other.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "$.domain", "certificate", "$.certificate",
                    "status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE"), "default", "REVOKED"))));
            d.put("authorities", List.of(Map.of("kid", "row-1", "domain", "mdoc-iaca", "certificate", der("iaca"), "state", "active"),
                    Map.of("kid", "row-7", "domain", "status-list", "certificate", der("iaca"), "state", "withdrawn")));
            serveJson(ctx, d);
            assertThat(source(ctx, props("mapping", other)).load().anchors()).hasSize(2);
        } catch (io.vctrust.trust.core.spi.TrustSourceException e) {
            throw new AssertionError(e.getMessage());
        }
    }

    // H: ordering and shapes -------------------------------------------------------------------------------------

    @Test
    void h_aMappedSequenceIsAWholeNumberOfAtMost18Digits() throws Exception {
        TestContext ctx = ctx();
        for (Object sequence : List.of("v5", "1.2.3", "1234567890123456789", -1, 5.5, "5.0", Map.of("n", 5), "v5\r\nWARN forged")) {
            Map<String, Object> d = MappedSourceRulesTest.doc("a");
            d.put("version", sequence);
            serveJson(ctx, d);
            assertThat(MappedSourceRulesTest.loadError(source(ctx, props()))).as(String.valueOf(sequence)).contains("mapping.list.sequence: ")
                    .contains("is not a whole number of at most 18 digits, so it cannot order lists; map issuedAt instead")
                    .doesNotContain("\r").doesNotContain("\n");
        }
        for (Map.Entry<Object, String> ok : Map.<Object, String>of(5, "5", new java.math.BigDecimal("5.0"), "5", "0042", "42",
                "123456789012345678", "123456789012345678").entrySet()) {
            Map<String, Object> d = MappedSourceRulesTest.doc("a");
            d.put("version", ok.getKey());
            serveJson(ctx, d);
            assertThat(source(ctx, props()).load().listInfo().sequence()).as(String.valueOf(ok.getKey())).isEqualTo(ok.getValue());
        }
    }

    @Test
    void h_aRestrictingListThatIsThereAndYieldsNothingIsNoRestrictionLeftOpen() {
        // The issuer authorized for nothing (its list of credentials is there and empty) is not unconstrained.
        for (Object credentials : java.util.Arrays.asList(List.of(), java.util.Collections.singletonList(null), Map.of())) {
            TestContext ctx = ctx();
            serveJson(ctx, boundList(1, members("credentials", credentials)));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(decide(registry, PID)).as(String.valueOf(credentials)).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).isEqualTo(EntityStatus.SUSPENDED);
                assertThat(state(m, "partner").warnings()).singleElement().asString().contains("is listed SUSPENDED: authorizations: "
                        + "$.credentials[*] finds a list or an object that holds no value");
            }
        }
        // Not there, or null: absent, unconstrained for a lenient client.
        for (Object credentials : java.util.Arrays.asList(null, "absent")) {
            TestContext ctx = ctx();
            Map<String, Object> d = boundList(1, members("credentials", null));
            if (credentials == null) {
                ((Map<String, Object>) ((List<?>) d.get("issuers")).getFirst()).put("credentials", null);
            }
            serveJson(ctx, d);
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(decide(registry, PID)).isEqualTo(Decision.TRUSTED);
            }
        }
        // An IACA whose doctypes are there and empty is skipped, not free to sign any doctype.
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "docTypes", "$.doctypes[*]")));
        Map<String, Object> d = boundList(1, members("certificates", null));
        d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"), "doctypes", List.of()),
                Map.of("kid", "rp-ca", "certificate", der("rp-ca"))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(decide(registry, PID)).isNotEqualTo(Decision.TRUSTED);
            assertThat(registry.snapshot().allAnchors()).extracting(a -> a.id()).containsExactly("rp-ca");
            assertThat(state(manager, "partner").warnings()).containsExactly("mapping.anchors[0]: record 1 (id 'shared-iaca') is skipped: "
                    + "docTypes: $.doctypes[*] finds a list or an object that holds no value; a list that is there and empty restricts to "
                    + "nothing, it does not leave the record open");
        }
    }

    @Test
    void h_aPinnedContextWithoutItsDigestOrATranslationOfAnObjectMakesTheRecordUnreadable() throws Exception {
        Map<String, Object> m = MappedSourceAttacksTest.entities("contexts", List.of(Map.of("each", "$.ctx[*]", "url", "$.url", "sha256", "$.digest")));
        Map<String, Object> d = MappedSourceRulesTest.doc();
        d.put("issuers", List.of(
                Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active", "ctx", List.of(Map.of("url", "https://c.example/1"))),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", "active",
                        "ctx", List.of(Map.of("url", "https://c.example/1", "digest", "AAAA"))),
                Map.of("id", "c", "credential_issuer", "https://c.example", "state", "active", "ctx", List.of(Map.of("note", "none")))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", m)).load();
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:a SUSPENDED", "partner:b ACTIVE", "partner:c ACTIVE");
        assertThat(r.entities().getFirst().attributes()).doesNotContainKey(io.vctrust.trust.core.metadata.Oid4vciMetadataMapper.CONTEXTS);
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 1 (id 'partner:a') is listed SUSPENDED: contexts: an item "
                + "yields url but no sha256");

        // A translation applied to an object or a list is not its default: the state is there, in a shape not known.
        Map<String, Object> status = MappedSourceAttacksTest.entities("status", Map.of("path", "$.state", "values",
                Map.of("revoked", "REVOKED"), "default", "ACTIVE"));
        d.put("issuers", List.of(Map.of("id", "a", "credential_issuer", "https://a.example", "state", Map.of("code", "revoked")),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", List.of("revoked")),
                Map.of("id", "c", "credential_issuer", "https://c.example")));
        serveJson(ctx, d);
        r = source(ctx, props("mapping", status)).load();
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:a SUSPENDED", "partner:b SUSPENDED", "partner:c ACTIVE");
        assertThat(r.warnings()).containsExactly(
                "mapping.entities[0]: record 1 (id 'partner:a') is listed SUSPENDED: status: the path $.state finds an object where a value "
                        + "to translate belongs",
                "mapping.entities[0]: record 2 (id 'partner:b') is listed SUSPENDED: status: the path $.state finds a list where a value "
                        + "to translate belongs");
    }

    @Test
    void h_translationKeysAreComparedWithoutRegardToCaseAndSurroundingWhitespace() throws Exception {
        Map<String, Object> status = MappedSourceAttacksTest.entities("status", Map.of("path", "$.state", "values",
                Map.of("Revoked", "REVOKED", " active", "ACTIVE"), "default", "SUSPENDED"));
        Map<String, Object> d = MappedSourceRulesTest.doc();
        d.put("issuers", List.of(Map.of("id", "a", "credential_issuer", "https://a.example", "state", "revoked"),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", " REVOKED "),
                Map.of("id", "c", "credential_issuer", "https://c.example", "state", "ACTIVE")));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        assertThat(source(ctx, props("mapping", status)).load().entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:a REVOKED", "partner:b REVOKED", "partner:c ACTIVE");
        // Two keys that are one under that rule are a configuration error, as a map and as {when, then} pairs.
        for (Object values : List.of(Map.of("Revoked", "REVOKED", "revoked ", "ACTIVE"),
                List.of(Map.of("when", "revoked", "then", "REVOKED"), Map.of("when", " REVOKED", "then", "ACTIVE")))) {
            assertThat(MappedSourceRulesTest.loadError(source(ctx, props("mapping", MappedSourceAttacksTest.entities("status",
                    Map.of("path", "$.state", "values", values, "default", "SUSPENDED"))))))
                    .contains("mapping.entities[0].status: values names 'revoked' twice (keys are compared without regard to case and "
                            + "surrounding whitespace)");
        }
    }

    // I: signing certificates and unverified lists -------------------------------------------------------------------

    /** A certificate that {@code issuer} issued, allowed to sign, with the given extended key usages. */
    static io.vctrust.trust.core.testing.TestPki.Issued withEku(String dn, io.vctrust.trust.core.testing.TestPki.Issued issuer,
                                                                org.bouncycastle.asn1.x509.KeyPurposeId... purposes) throws Exception {
        java.security.KeyPair keys = io.vctrust.trust.core.testing.TestPki.ecKey();
        var b = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                org.bouncycastle.asn1.x500.X500Name.getInstance(issuer.certificate().getSubjectX500Principal().getEncoded()),
                java.math.BigInteger.valueOf(System.nanoTime()), java.util.Date.from(NOW.minus(Duration.ofDays(1))),
                java.util.Date.from(NOW.plus(Duration.ofDays(365))), new org.bouncycastle.asn1.x500.X500Name(dn), keys.getPublic());
        var ext = new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils();
        b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(keys.getPublic()));
        b.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuer.certificate()));
        b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature));
        b.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, new org.bouncycastle.asn1.x509.ExtendedKeyUsage(purposes));
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(issuer.keys().getPrivate());
        return new io.vctrust.trust.core.testing.TestPki.Issued(
                new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(b.build(signer)), keys);
    }

    @Test
    void i_aTlsServerCertificateDoesNotSignTheListUnlessItIsItselfPinned() throws Exception {
        int sign = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
        int caUsage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign | org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
        io.vctrust.trust.core.testing.TestPki.Issued root = MappedSourceAttacksTest.certificate("CN=Partner CA,C=UT", null, true, sign | caUsage);
        io.vctrust.trust.core.testing.TestPki.Issued tls = withEku("CN=www.partner.example,C=UT", root,
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth, org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth);
        io.vctrust.trust.core.testing.TestPki.Issued listSigner = withEku("CN=Partner List Signer,C=UT", root,
                org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning);
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(root.certificate())))));
        // A web server's certificate from the CA that issues the list signer's too: its key usage allows a signature.
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(tls, tls, MappedSourceRulesTest.doc("a", "evil")));
        assertThat(MappedSourceRulesTest.loadError(s)).contains("The list's signing certificate is a TLS server certificate "
                + "(extended key usage serverAuth) that is not pinned");
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(listSigner, listSigner, MappedSourceRulesTest.doc("a")));
        assertThat(s.load().entities()).hasSize(1);
        // Pinned itself, it may.
        TrustSource pinned = source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(tls.certificate())))));
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(tls, tls, MappedSourceRulesTest.doc("a")));
        assertThat(pinned.load().entities()).hasSize(1);
    }

    @Test
    void i_anUnverifiedListIsStillHeldToTheChecksThatNeedNoKey() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        Map<String, Object> verify = Map.of("typ", "partner-list+jwt", "issuer", "https://registry.partner.example",
                "audience", "wallet-proxy-b");
        TrustSource s = source(ctx, props("format", "jws", "allowUnverified", true, "verify", verify));
        Map<String, Object> claims = new LinkedHashMap<>(MappedSourceRulesTest.doc("a"));
        claims.put("iss", "https://registry.partner.example");
        claims.put("aud", "wallet-proxy-b");
        com.nimbusds.jose.JWSHeader typed = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256).keyID("k1")
                .type(new com.nimbusds.jose.JOSEObjectType("partner-list+jwt")).build();
        MappedSourceRulesTest.serveJws(ctx, MappedTesting.sign(typed, MappedTesting.signer(k1), claims));
        assertThat(s.load().entities()).hasSize(1);
        // Another document of the publisher (another typ), served in its place.
        MappedSourceRulesTest.serveJws(ctx, MappedTesting.sign(k1, claims));
        assertThat(MappedSourceRulesTest.loadError(s)).contains("typ is absent, not 'partner-list+jwt' (verify.typ)");
        // And the claims, as for a verified list.
        Map<String, Map<String, Object>> wrong = new LinkedHashMap<>();
        wrong.put("(verify.issuer)", Map.of("iss", "https://sandbox.partner.example"));
        wrong.put("not to 'wallet-proxy-b'", Map.of("aud", "someone-else"));
        wrong.put("expired at", Map.of("exp", NOW.minus(Duration.ofHours(1)).getEpochSecond()));
        wrong.put("not valid before", Map.of("nbf", NOW.plus(Duration.ofHours(1)).getEpochSecond()));
        for (Map.Entry<String, Map<String, Object>> w : wrong.entrySet()) {
            Map<String, Object> c = new LinkedHashMap<>(claims);
            c.putAll(w.getValue());
            MappedSourceRulesTest.serveJws(ctx, MappedTesting.sign(typed, MappedTesting.signer(k1), c));
            assertThat(MappedSourceRulesTest.loadError(s)).as(w.getKey()).contains(w.getKey());
        }
    }

    // J: a whole load has a deadline ---------------------------------------------------------------------------------

    @Test
    void j_aLoadStillFetchingPagesAfterLimitsDurationFails() throws Exception {
        TestContext ctx = ctx();
        MappedSourceRulesTest.MutableClock clock = new MappedSourceRulesTest.MutableClock(NOW);
        // A registry that takes two minutes for every page, and has four.
        io.vctrust.trust.core.spi.SourceContext slow = new io.vctrust.trust.core.spi.SourceContext() {
            @Override
            public io.vctrust.trust.core.spi.HttpFetcher http() {
                return request -> {
                    clock.now = clock.now.plus(Duration.ofMinutes(2));
                    return ctx.http.execute(request);
                };
            }

            @Override
            public io.vctrust.trust.core.spi.ResourceLoader resources() {
                return ctx.resources();
            }

            @Override
            public java.time.Clock clock() {
                return clock;
            }
        };
        List<String> urls = List.of(MappedSourceRulesTest.LOCATION, PAGE_2, PAGE_3, MappedSourceRulesTest.LOCATION + "?page=4");
        for (int i = 0; i < urls.size(); i++) {
            Map<String, Object> d = MappedSourceRulesTest.doc("p" + i);
            if (i + 1 < urls.size()) {
                d.put("next", urls.get(i + 1));
            }
            ctx.http.json(urls.get(i), Json.write(d));
        }
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        m.put("pages", Map.of("next", "$.next"));
        java.util.function.Function<Map<String, Object>, TrustSource> create = p -> new io.vctrust.trust.adapters.mapped.MappedSourceFactory()
                .create(new io.vctrust.trust.core.spi.SourceDefinition("partner", "mapped", "partner", null, true, p), slow);
        assertThat(MappedSourceRulesTest.loadError(create.apply(props("mapping", m)))).contains("The list is still being read after PT5M "
                + "(limits.duration)");
        assertThat(ctx.http.requests).hasSize(3);   // the fourth page is not asked for
        clock.now = NOW;
        assertThat(create.apply(props("mapping", m, "limits", Map.of("duration", "PT10M"))).load().entities()).hasSize(4);
        assertThat(MappedSourceRulesTest.loadError(create.apply(props("mapping", m, "limits", Map.of("duration", "soon")))))
                .contains("limits.duration must be a duration such as PT5M, longer than none");
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
