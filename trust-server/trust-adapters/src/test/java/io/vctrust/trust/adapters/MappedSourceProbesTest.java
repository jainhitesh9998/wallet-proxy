package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.NOW;
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
 * What a fourth validation of the mapped source found with some 420 probes against round three, each reproduced, on the
 * registry format that is now read strictly: what the source hands to that format's parser, ids as labels, the leniency
 * left in reading a type, an identifying member or an index, what a load may weigh for the bytes it read, and PEM.
 */
@SuppressWarnings("unchecked")
class MappedSourceProbesTest {

    // 0: what the source hands to the registry format, read strictly ------------------------------------------------------

    /** Every member an entity block can map, each from its own member of the record. */
    static Map<String, Object> everyMember() {
        return Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"],
                   "name": "$.name",
                   "display": [{"each": "$.display[*]", "locale": "$.locale", "name": "$.title", "description": "$.about",
                                "logoUri": "$.logo"}],
                   "identifiers": [{"type": "URL", "value": "$.url"}, {"each": "$.dids[*]", "type": "DID", "value": "$"}],
                   "certificates": "$.certificates[*]",
                   "authorizations": [{"each": "$.credentials[*]", "format": "$.format", "type": "$.type"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE", "revoked": "REVOKED"}, "default": "ACTIVE"},
                   "validFrom": "$.valid_from", "validUntil": "$.valid_until",
                   "contexts": ["$.contexts[*]", {"each": "$.pinned[*]", "url": "$.url", "sha256": "$.digest"}],
                   "attributes": {"country": "$.country", "meta": "$.meta"},
                   "metadataPolicy": "$.policy"}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.id", "domain": "mdoc-iaca", "certificate": "$.certificate"}]}""");
    }

    static Map<String, Object> list(List<Map<String, Object>> issuers) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("issuers", issuers);
        d.put("cas", List.of(Map.of("id", "shared-iaca", "certificate", der("iaca"))));
        return d;
    }

    /** A record with every member the mapping reads, the DS certificate its signing key. */
    static Map<String, Object> full(String id) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", id);
        r.put("name", "Utopia DMV");
        r.put("display", List.of(Map.of("locale", "en", "title", "Utopia DMV", "about", "Driving licences", "logo",
                "https://dmv.utopia.example/logo.png"), Map.of("locale", "de", "title", "Kraftfahrtamt Utopia")));
        r.put("url", "https://issuer.utopia.example");
        r.put("dids", List.of("did:web:dmv.utopia.example"));
        r.put("certificates", List.of(der("ds")));
        r.put("credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL)));
        r.put("state", "active");
        r.put("valid_from", NOW.minusSeconds(86_400).toString());
        r.put("valid_until", NOW.plusSeconds(86_400 * 365L).toString());
        r.put("contexts", List.of("https://contexts.example/v1"));
        r.put("pinned", List.of(Map.of("url", "https://contexts.example/v2", "digest", "AAAA")));
        r.put("country", "UT");
        r.put("meta", Map.of("tier", "gold"));
        r.put("policy", Map.of("openid_credential_issuer", Map.of("credential_issuer", Map.of("value", "https://issuer.utopia.example"))));
        return r;
    }

    @Test
    void item0_whatTheSourceHandsOverTheStrictRegistryFormatReadsWithEveryOptionalMemberAbsentOrLeftOut() {
        String long8193 = "L".repeat(8_193);
        Map<String, Map<String, Object>> records = new LinkedHashMap<>();
        // name and display both: the format reads one of them only, and refuses an entry with both.
        records.put("every member, name and display both", full("dmv"));
        Map<String, Object> bare = new LinkedHashMap<>(Map.of("id", "bare", "certificates", List.of(der("ds-nl"))));
        records.put("every optional member absent", bare);
        Map<String, Object> nulls = new LinkedHashMap<>(Map.of("id", "nulls", "certificates", List.of(der("ds-revoked"))));
        for (String k : List.of("name", "display", "url", "dids", "credentials", "state", "valid_from", "valid_until", "contexts",
                "pinned", "country", "meta", "policy")) {
            nulls.put(k, k.equals("display") || k.equals("credentials") || k.equals("dids") || k.equals("contexts") || k.equals("pinned")
                    ? List.of() : null);
        }
        nulls.put("credentials", null);   // a restricting list that is there and empty restricts to nothing: not this test
        records.put("every optional member null or an empty list", nulls);
        Map<String, Object> blank = new LinkedHashMap<>(Map.of("id", "blank", "certificates", List.of(der("ds-hold"))));
        for (String k : List.of("name", "url", "state", "valid_from", "valid_until", "country")) {
            blank.put(k, "");
        }
        records.put("every optional text member \"\"", blank);
        Map<String, Object> tooLong = full("long");
        tooLong.put("certificates", List.of(der("ds-crldp")));
        tooLong.put("name", long8193);
        tooLong.put("display", List.of(Map.of("locale", "en", "title", long8193, "about", long8193, "logo", long8193)));
        tooLong.put("country", long8193);
        tooLong.put("meta", Map.of("note", long8193));
        records.put("every descriptive member left out for being too long", tooLong);
        Map<String, Object> nullPolicy = full("policy-null");
        nullPolicy.put("certificates", List.of(der("ds-noeku")));
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("openid_credential_issuer", null);
        nullPolicy.put("policy", policy);
        records.put("a policy whose only member is null", nullPolicy);

        TestContext ctx = ctx();
        serveJson(ctx, list(new ArrayList<>(records.values())));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", everyMember())))) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(registry.snapshot().entities()).extracting(e -> e.id() + " " + e.status()).containsExactly(
                    "dmv ACTIVE", "bare ACTIVE", "nulls ACTIVE", "blank ACTIVE", "long ACTIVE", "policy-null ACTIVE");
            TrustedEntity dmv = registry.snapshot().entity("dmv").orElseThrow();
            assertThat(dmv.displayName("de")).isEqualTo("Kraftfahrtamt Utopia");
            assertThat(dmv.identifiers()).hasSize(2);
            assertThat(dmv.metadataPolicy()).containsKey("openid_credential_issuer");
            assertThat(registry.snapshot().entity("long").orElseThrow().display()).isEmpty();
            assertThat(registry.snapshot().entity("policy-null").orElseThrow().metadataPolicy()).isEmpty();
            assertThat(state(m, "partner").warnings()).singleElement().asString().startsWith("mapping.entities[0]: record 5 (id 'long') "
                    + "is listed without text too long to keep: name: a value of 8193 characters");
            assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
        }
    }

    @Test
    void item0_aRecordTheRegistryFormatRefusesIsSuspendedWhenWhatIdentifiesItCanBeRead() {
        // A policy whose member is not an object: the format refuses it; the record is listed, not in good standing.
        Map<String, Object> wrong = full("dmv");
        wrong.put("state", "revoked");
        wrong.put("policy", Map.of("openid_credential_issuer", "not an object"));
        TestContext ctx = ctx();
        serveJson(ctx, list(List.of(wrong, full("other"))));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", everyMember())))) {
            assertThat(registry.snapshot().entity("dmv").orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
            assertThat(state(m, "partner").warnings()).singleElement().asString().contains("record 1 (id 'dmv') is listed REVOKED: "
                    + "metadataPolicy: 'metadataPolicy.openid_credential_issuer' must be an object");
        }
        // An identifier the format cannot read: the load fails, naming it.
        Map<String, Object> m2 = everyMember();
        ((Map<String, Object>) ((List<?>) m2.get("entities")).getFirst()).put("identifiers", List.of(Map.of("type", "X509_SHA256",
                "value", "$.url")));
        serveJson(ctx, list(List.of(full("dmv"))));
        assertThat(loadError(source(ctx, props("mapping", m2)))).startsWith("mapping.entities[0]: record 1 (id 'dmv') cannot be read: "
                + "identifiers: identifiers[0]: 'value' is not a SHA-256 digest");
    }

    // 1: an id is a label ------------------------------------------------------------------------------------------

    /** An id as the source lists it when it cannot be one as written: {@code sha256:} and the whole SHA-256, in hexadecimal. */
    static String derived(String id) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "sha256:" + java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Issuers bound to nothing but their CA, which names its entity ({@code entity: $.issuer_id}); ids as written. */
    static Map<String, Object> tiedByTheCa() {
        return Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"],
                   "identifiers": [{"type": "URL", "value": "$.url"}],
                   "authorizations": [{"each": "$.credentials[*]", "format": "$.format", "type": "$.type"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE", "suspended": "SUSPENDED"}, "default": "REVOKED"},
                   "validUntil": "$.valid_until"}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate",
                   "entity": "$.issuer_id"}]}""");
    }

    static Map<String, Object> tied(String id, Map<String, Object> party) {
        Map<String, Object> dmv = new LinkedHashMap<>(Map.of("id", id, "url", "https://issuer.utopia.example", "state", "active",
                "credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL))));
        dmv.putAll(party);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("issuers", List.of(dmv, Map.of("id", "college", "url", "https://college.example", "state", "active")));
        d.put("cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca"), "issuer_id", id)));
        return d;
    }

    @Test
    void item1_aCaTiedToAnEntityWhoseIdIsReplacedIsTiedToWhatTheIdBecameAndTheEntityKeepsItsStatus() {
        for (String id : List.of("Utopia DMV", "https://dmv.utopia.example")) {
            Map<String, Map<String, Object>> cases = new LinkedHashMap<>();
            cases.put("revoked", Map.of("state", "revoked"));
            cases.put("active", Map.of());
            cases.put("suspended by a date that cannot be read", Map.of("valid_until", NOW.toEpochMilli()));
            cases.forEach((what, party) -> {
                TestContext ctx = ctx();
                serveJson(ctx, tied(id, party));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", tiedByTheCa())))) {
                    String as = id + ", " + what;
                    assertThat(state(m, "partner").lastError()).as(as).isNull();
                    TrustedEntity listed = registry.snapshot().entity(derived(id)).orElseThrow();
                    assertThat(listed.status()).as(as).isEqualTo(what.equals("revoked") ? EntityStatus.REVOKED
                            : what.equals("active") ? EntityStatus.ACTIVE : EntityStatus.SUSPENDED);
                    assertThat(registry.snapshot().allAnchors()).singleElement().satisfies(a -> assertThat(a.entityId()).isEqualTo(derived(id)));
                    // The chain to the CA is the entity's: revoked or suspended, kept out; active, as it is authorized.
                    assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).as(as).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(as)
                            .isEqualTo(what.equals("active") ? Decision.TRUSTED : Decision.NOT_TRUSTED);
                }
            });
        }
    }

    @Test
    void item1_aListWhoseIdsAreUrlsLoadsAsItStatesAndAnAnchorIdIsALabelToo() throws Exception {
        // A federation-style list: every party named by its URL, every one active. Each was suspended, and the block
        // failed the load ("none of the records could be read completely").
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("issuers", List.of(Map.of("id", "https://dmv.utopia.example", "url", "https://dmv.utopia.example", "state", "active",
                        "credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL))),
                Map.of("id", "https://college.example/issuer", "url", "https://college.example/issuer", "state", "active")));
        // A CA named by a base64 key identifier, tied to the first.
        d.put("cas", List.of(Map.of("kid", "q83vEjRWeJ+/kQ==", "certificate", der("iaca"), "issuer_id", "https://dmv.utopia.example")));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", tiedByTheCa())))) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(registry.snapshot().entities()).extracting(e -> e.id() + " " + e.status())
                    .containsExactlyInAnyOrder(derived("https://dmv.utopia.example") + " ACTIVE", derived("https://college.example/issuer") + " ACTIVE");
            assertThat(registry.snapshot().allAnchors()).singleElement().satisfies(a -> {
                assertThat(a.id()).isEqualTo(derived("q83vEjRWeJ+/kQ=="));
                assertThat(a.entityId()).isEqualTo(derived("https://dmv.utopia.example"));
            });
            assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).isEqualTo(Decision.NOT_TRUSTED);
            // One warning for the load, not one a record.
            assertThat(state(m, "partner").warnings()).containsExactly("3 ids are listed under derived ids (sha256: and the SHA-256 of the "
                    + "id written), not being 1 to 128 letters, digits or . _ : @ ~ - starting with a letter or digit: the first, "
                    + "'https://dmv.utopia.example', as '" + derived("https://dmv.utopia.example") + "'");
        }
    }

    @Test
    void item1_twoDifferentIdsNeverBecomeOneEntryAndOneIdTwiceIsOne() throws Exception {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("issuers", List.of(Map.of("id", "utopia dmv", "url", "https://a.example", "state", "active"),
                Map.of("id", "Utopia DMV", "url", "https://b.example", "state", "active"),
                // An id written as the derived id of another stays apart from it: such an id is derived again.
                Map.of("id", derived("utopia dmv"), "url", "https://c.example", "state", "active"),
                Map.of("id", "utopia dmv", "url", "https://d.example", "state", "revoked")));
        d.put("cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca"))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", tiedByTheCa())))) {
            assertThat(registry.snapshot().entities()).extracting(e -> e.id() + " " + e.status()).containsExactlyInAnyOrder(
                    derived("utopia dmv") + " REVOKED", derived("Utopia DMV") + " ACTIVE", derived(derived("utopia dmv")) + " ACTIVE");
            assertThat(registry.snapshot().entity(derived("utopia dmv")).orElseThrow().identifiers()).hasSize(2);
        }
    }

    // 2: allowAnyType reads the type's own path strictly ------------------------------------------------------------------

    static final String PID = MappedSourceValidationTest.PID;

    /** The decision about the DS certificate's PID, the issuer authorized by {@code credentials} under {@code allowAnyType}. */
    static Map.Entry<EntityStatus, Decision> anyType(String typePath, Object credential) {
        Map<String, Object> item = new LinkedHashMap<>(Map.of("each", "$.credentials[*]", "allowAnyType", true, "format", "$.format",
                "type", typePath));
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials", List.of(credential))));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceValidationTest.withAuthorizations(item))))) {
            return Map.entry(registry.snapshot().entity("partner:dmv").orElseThrow().status(), MappedSourceValidationTest.decide(registry, PID));
        }
    }

    static Map<String, Object> credential(String member, Object value) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("format", "mso_mdoc");
        c.put(member, value);
        return c;
    }

    @Test
    void item2_aTypeThatIsThereButLostOnTheWayIsNoReasonToCoverEveryType() {
        Map<String, List<Map<String, Object>>> lost = new LinkedHashMap<>();
        lost.put("$.types[0]", List.of(credential("types", List.of()), credential("types", java.util.Arrays.asList(null, PID))));
        lost.put("$.types[*]", List.of(credential("types", List.of()), credential("types", java.util.Collections.singletonList(null)),
                credential("types", Map.of())));
        lost.put("$.types[?@.primary == true].id", List.of(credential("types", List.of(Map.of("primary", false, "id", MDL))),
                credential("types", List.of(Map.of("primary", true)))));
        Map<String, Object> nullId = new LinkedHashMap<>();
        nullId.put("id", null);
        lost.put("$.type.id", List.of(credential("type", Map.of()), credential("type", Map.of("name", "mDL")), credential("type", nullId)));
        lost.forEach((path, credentials) -> {
            for (Map<String, Object> c : credentials) {
                // Authorized for every type of mso_mdoc, PID included, before.
                assertThat(anyType(path, c)).as(path + " over " + c).isEqualTo(Map.entry(EntityStatus.SUSPENDED, Decision.NOT_TRUSTED));
            }
        });
        // The first member the path names not there, null or "": no type stated, every type of the format.
        for (String path : lost.keySet()) {
            String first = path.substring(2).split("[.\\[]")[0];
            for (Object absent : java.util.Arrays.asList("not there", null, "")) {
                Map<String, Object> c = absent != null && absent.equals("not there") ? credential("other", 1) : credential(first, absent);
                assertThat(anyType(path, c)).as(path + " over " + c).isEqualTo(Map.entry(EntityStatus.ACTIVE, Decision.TRUSTED));
            }
        }
        // And one that is read: the type stated.
        assertThat(anyType("$.types[*].id", credential("types", List.of(Map.of("id", MDL))))).isEqualTo(Map.entry(EntityStatus.ACTIVE,
                Decision.NOT_TRUSTED));
        assertThat(anyType("$.types[*].id", credential("types", List.of(Map.of("id", PID), Map.of("name", "x")))))
                .isEqualTo(Map.entry(EntityStatus.SUSPENDED, Decision.NOT_TRUSTED));
    }

    // 3: an identifying member is read strictly past a list; an index is a list segment ------------------------------------

    /** The revoked issuer "dmv" with {@code members} put over it, under a mapping whose block has {@code block} put over it. */
    static Map.Entry<String, Decision> revokedDmv(Map<String, Object> block, Map<String, Object> members) {
        Map<String, Object> m = MappedSourceValidationTest.boundMapping();
        ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).putAll(block);
        Map<String, Object> dmv = new LinkedHashMap<>(Map.of("state", "revoked"));
        dmv.putAll(members);
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, dmv));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            String error = state(manager, "partner").lastError();
            return Map.entry(error == null ? "loaded" : error, MappedSourceValidationTest.decide(registry, MDL));
        }
    }

    @Test
    void item3_certificatesPastAListAreReadStrictly() {
        // As the documented snapshot mapping writes it: each certificate an object holding the certificate.
        Map<String, Object> pathOn = Map.of("certificates", "$.certificates[*].certificate");
        Map<String, Object> nullCertificate = new LinkedHashMap<>();
        nullCertificate.put("certificate", null);
        Map<String, Object> cases = new LinkedHashMap<>();
        cases.put("[{pem}]", List.of(Map.of("pem", der("ds"))));
        cases.put("[{certificate: null}]", List.of(nullCertificate));
        cases.put("[{}]", List.of(Map.of()));
        cases.put("[null]", java.util.Collections.singletonList(null));
        cases.put("[{certificate}, {cert}]", List.of(Map.of("certificate", der("ds-nl")), Map.of("cert", der("ds"))));
        cases.forEach((what, certificates) -> {
            // Listed REVOKED without the DS certificate, the chain decided alone: TRUSTED.
            var r = revokedDmv(pathOn, MappedSourceValidationTest.members("certificates", certificates));
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: ");
        });
        // There and empty: no certificate stated, which is not one that cannot be read; one there is read.
        assertThat(revokedDmv(pathOn, MappedSourceValidationTest.members("certificates", List.of()))).isEqualTo(Map.entry("loaded",
                Decision.TRUSTED));
        assertThat(revokedDmv(pathOn, MappedSourceValidationTest.members("certificates", List.of(Map.of("certificate", der("ds"))))))
                .isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
    }

    @Test
    void item3_identifierItemsAndRolesPastAListAreReadStrictly() {
        Map<String, Object> ids = Map.of("identifiers", List.of(Map.of("each", "$.ids[*]", "type", "$.type", "value", "$.value")));
        // Renamed members in an item of a list there: no identifier was read, and the record listed without one.
        assertThat(revokedDmv(ids, MappedSourceValidationTest.members("ids", List.of(Map.of("kind", "DNS", "val", "dmv.utopia.example")))).getKey())
                .startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: identifiers: ");
        assertThat(revokedDmv(ids, MappedSourceValidationTest.members("ids", List.of())).getKey()).isEqualTo("loaded");
        assertThat(revokedDmv(ids, MappedSourceValidationTest.members("ids", List.of(Map.of("type", "DNS", "value", "dmv.utopia.example"))))
                .getKey()).isEqualTo("loaded");
        // roles: { path: $.roles[*].name, allowEmpty: true } over [null]: listed without a role ("none stated").
        Map<String, Object> roles = Map.of("roles", Map.of("path", "$.roles[*].name", "allowEmpty", true));
        assertThat(revokedDmv(roles, MappedSourceValidationTest.members("roles", java.util.Collections.singletonList(null))).getKey())
                .startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: roles: ");
        assertThat(revokedDmv(roles, MappedSourceValidationTest.members("roles", List.of(Map.of("title", "issuer")))).getKey())
                .startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: roles: ");
    }

    @Test
    void item3_anIndexThatMeetsAListAndSelectsNothingIsThereAndEmpty() {
        // each: $.credentials[0] over []: the issuer was unconstrained, authorized for the PID.
        Map<String, Object> m = MappedSourceValidationTest.withAuthorizations(Map.of("each", "$.credentials[0]", "format", "$.format",
                "type", "$.type"));
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials", List.of())));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(MappedSourceValidationTest.decide(registry, PID)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).isEqualTo(EntityStatus.SUSPENDED);
        }
        // docTypes: $.doctypes[0] over [] or [null]: the IACA was free to sign any doctype.
        for (Object doctypes : List.of(List.of(), java.util.Collections.singletonList(null))) {
            Map<String, Object> anchored = MappedSourceValidationTest.boundMapping();
            anchored.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate",
                    "$.certificate", "docTypes", "$.doctypes[0]")));
            Map<String, Object> d = MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("certificates", null));
            d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"), "doctypes", doctypes),
                    Map.of("kid", "rp-ca", "certificate", der("rp-ca"))));
            TestContext c = ctx();
            serveJson(c, d);
            TrustRegistry r = new TrustRegistry();
            try (TrustSourceManager manager = manager(r, source(c, props("mapping", anchored)))) {
                assertThat(MappedSourceValidationTest.decide(r, PID)).as(String.valueOf(doctypes)).isNotEqualTo(Decision.TRUSTED);
                assertThat(r.snapshot().allAnchors()).as(String.valueOf(doctypes)).extracting(a -> a.id()).containsExactly("rp-ca");
            }
        }
    }

    // 4: what a load may yield for the bytes it read --------------------------------------------------------------------

    @Test
    void item4_aLoadYieldsAtMost32TimesTheBytesItReadAndAtLeastAMebibyteIsAllowed() throws Exception {
        // 4,000 nulls at the root, repeated into each of 1,000 records through an attribute: about 4 million nodes from
        // a document of about 90 kB, inside every bound of a record and of limits.text.
        Map<String, Object> d = MappedSourceRulesTest.doc();
        List<Object> issuers = new ArrayList<>();
        for (int i = 0; i < 1_000; i++) {
            issuers.add(Map.of("id", "p" + i, "credential_issuer", "https://p" + i + ".example", "state", "active"));
        }
        d.put("issuers", issuers);
        d.put("nulls", java.util.Collections.nCopies(4_000, null));
        String json = Json.write(d);
        TestContext ctx = ctx();
        serveJson(ctx, json);
        Map<String, Object> m = MappedSourceAttacksTest.entities("attributes", Map.of("flags", "^.nulls"));
        assertThat(loadError(source(ctx, props("mapping", m)))).contains("The list's records yield more than 32 times the "
                + json.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + " bytes read (limits: 32 times what is read, and at "
                + "least 1048576)");
        // The same list without what repeats: inside the factor by far.
        assertThat(source(ctx, props()).load().entities()).hasSize(1_000);
        // A small document may still yield a mebibyte: a text of 8,000 characters at the root, in eight attributes of
        // each record, is 64,000 characters a record from a document of about 9 kB. Ten records (640,000) load, more
        // than 32 times the bytes read but less than a mebibyte; twenty (1,280,000) do not.
        Map<String, Object> attributes = new LinkedHashMap<>();
        for (int i = 0; i < 8; i++) {
            attributes.put("a" + i, "^.text");
        }
        Map<String, Object> repeated = MappedSourceAttacksTest.entities("attributes", attributes);
        d.remove("nulls");
        d.put("text", "T".repeat(8_000));
        for (int n : List.of(10, 20)) {
            d.put("issuers", issuers.subList(0, n));
            serveJson(ctx, d);
            if (n == 10) {
                assertThat(source(ctx, props("mapping", repeated)).load().entities()).hasSize(10);
            } else {
                assertThat(loadError(source(ctx, props("mapping", repeated)))).contains("more than 32 times the");
            }
        }
    }
}
