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
}
