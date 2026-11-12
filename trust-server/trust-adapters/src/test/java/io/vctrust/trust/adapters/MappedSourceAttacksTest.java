package io.vctrust.trust.adapters;

import com.nimbusds.jose.jwk.ECKey;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.BASE;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.loadError;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.lookupOnly;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJws;
import static io.vctrust.trust.adapters.MappedTesting.jwks;
import static io.vctrust.trust.adapters.MappedTesting.key;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.sign;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static io.vctrust.trust.adapters.MappedTesting.utf8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Attacks on a mapped source that a security review confirmed, each reproduced against the source: the document an
 * attacker controls, and what the source must make of it.
 */
@SuppressWarnings("unchecked")
class MappedSourceAttacksTest {

    /** A list in the shape of {@link MappedSourceRulesTest#mapping()}, with one issuer whose members the test chooses. */
    static String list(String issuerMembers) {
        return """
                {"publisher": "Partner", "version": 1, "issued": "%s", "next_update": "%s",
                 "issuers": [{"id": "a", "credential_issuer": "https://a.example", "state": "active", %s}]}"""
                .formatted(MappedSourceRulesTest.NOW.minusSeconds(60), MappedSourceRulesTest.NOW.plusSeconds(86_400), issuerMembers);
    }

    // F1: a number such as 1e999999999 becomes a gigabyte of text --------------------------------------------------

    @Test
    void f1_aDocumentWithANumberTooLargeToWriteOutIsNotRead() {
        // 1e999999 would be a name of a million characters; 1e999999999 one of a gigabyte. Neither reaches the
        // registry: the document is refused where it is parsed, whatever member holds the number.
        for (String number : List.of("1e999999", "-1e999999", "1e-999999", "1e41", "1e-41",
                "12345678901234567890123456789012345678901", "1.2345678901234567890123456789012345678901")) {
            for (String members : List.of("\"name\": " + number, "\"unmapped\": [" + number + "]")) {
                TestContext ctx = ctx();
                ctx.http.json(MappedSourceRulesTest.LOCATION, list(members));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
                    SourceState st = state(m, "partner");
                    assertThat(st.lastError()).as(members).contains("holds a number with more than 40 significant digits "
                            + "or a decimal exponent outside -40 to 40");
                    assertThat(registry.snapshot().entities()).as(members).isEmpty();
                }
            }
        }
        // The bound itself is read.
        for (String number : List.of("1e40", "-1e40", "1e-40", "1234567890123456789012345678901234567890",
                "0.1234567890123456789012345678901234567890", "0e999999999")) {
            TestContext ctx = ctx();
            ctx.http.json(MappedSourceRulesTest.LOCATION, list("\"name\": " + number));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
                assertThat(state(m, "partner").lastError()).as(number).isNull();
                assertThat(registry.snapshot().entities()).singleElement()
                        .satisfies(e -> assertThat(e.displayName("en")).as(number).hasSizeLessThan(100));
            }
        }
    }

    @Test
    void f1_aLookupAnswerWithANumberTooLargeToWriteOutIsAFailure() {
        TestContext ctx = ctx();
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b")).replace("}", ", \"n\": 1e999999}"));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("holds a number with more than 40 significant digits");
    }

    // F2: with format jws and pages, the pages were not tied to each other -------------------------------------------

    static final String PAGE_2 = MappedSourceRulesTest.LOCATION + "?page=2";

    /** The partner's list as {@code version}, its issuers in two pages; {@code page} is 1 or 2. */
    static Map<String, Object> page(int version, int page, String... ids) {
        Map<String, Object> d = MappedSourceRulesTest.doc(version, MappedSourceRulesTest.NOW.plus(Duration.ofDays(7)), ids);
        if (page == 1) {
            d.put("next", PAGE_2);
        }
        return d;
    }

    static Map<String, Object> pagedMapping(Map<String, Object> list) {
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        m.put("pages", Map.of("next", "$.next"));
        if (list == null) {
            m.remove("list");
        } else {
            m.put("list", list);
        }
        return m;
    }

    @Test
    void f2_aPageOfAnOlderSignedListIsNotAPageOfTheCurrentOne() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        Map<String, Object> p = props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "mapping", pagedMapping(Map.of("sequence", "$.version")));
        // Version 5 of the list revoked "c"; version 4 had it active. Page 1 of version 5, page 2 of version 4.
        Map<String, Object> current2 = page(5, 2);
        current2.put("issuers", List.of(Map.of("id", "c", "credential_issuer", "https://c.example", "state", "revoked")));
        serveJws(ctx, sign(k1, page(5, 1, "a", "b")));
        ctx.http.respond(PAGE_2, 200, "application/jwt", utf8(sign(k1, current2)));
        assertThat(source(ctx, p).load().entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:a ACTIVE", "partner:b ACTIVE", "partner:c REVOKED");
        ctx.http.respond(PAGE_2, 200, "application/jwt", utf8(sign(k1, page(4, 2, "c"))));
        assertThat(loadError(source(ctx, p))).contains("Page 2 of the list says sequence '4' where page 1 says '5'");

        // Another document of the same signer in place of page 2 (here: a lookup answer) is not a page of the list.
        ctx.http.respond(PAGE_2, 200, "application/jwt", utf8(sign(k1, Map.of("id", "x", "did", "did:example:x"))));
        assertThat(loadError(source(ctx, p))).contains("Page 2 of the list: mapping.list.sequence: the document has no value for it");
    }

    @Test
    void f2_pagesOfAJsonListMustAgreeOnEveryMappedFact() {
        TestContext ctx = ctx();
        serveJson(ctx, page(5, 1, "a"));
        Map<String, Object> other = page(5, 2, "b");
        other.put("publisher", "Someone else");
        ctx.http.json(PAGE_2, Json.write(other));
        assertThat(loadError(source(ctx, props("mapping", pagedMapping((Map<String, Object>) MappedSourceRulesTest.mapping().get("list"))))))
                .contains("Page 2 of the list says issuer 'Someone else' where page 1 says 'Partner'");
        other = page(5, 2, "b");
        other.put("next_update", MappedSourceRulesTest.NOW.plus(Duration.ofDays(8)).toString());
        ctx.http.json(PAGE_2, Json.write(other));
        assertThat(loadError(source(ctx, props("mapping", pagedMapping((Map<String, Object>) MappedSourceRulesTest.mapping().get("list"))))))
                .contains("Page 2 of the list says nextUpdate");
    }

    @Test
    void f2_aSignedListInPagesNeedsAFactThatTiesThePagesTogether() {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        serveJws(ctx, sign(k1, page(5, 1, "a")));
        ctx.http.respond(PAGE_2, 200, "application/jwt", utf8(sign(k1, page(4, 2, "c"))));
        for (Map<String, Object> list : java.util.Arrays.asList(null, Map.<String, Object>of("issuer", "$.publisher", "nextUpdate", "$.next_update"))) {
            assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "mapping", pagedMapping(list)))))
                    .contains("format: jws with pages needs list.sequence or list.issuedAt mapped");
        }
        assertThat(ctx.http.requests).isEmpty();
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)),
                "mapping", pagedMapping(Map.of("issuedAt", "$.issued")))))).contains("Page 2 of the list says issuedAt");
    }

    // F3: nothing tied a signed document to what it should be; an empty document was a success -----------------------

    /** The partner's mapping without list facts: nothing in the document but its records and its signature counts. */
    static Map<String, Object> bare() {
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        m.remove("list");
        return m;
    }

    @Test
    void f3_anotherDocumentOfTheSameSignerDoesNotEmptyTheSource() {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "mapping", bare()));
        serveJws(ctx, sign(k1, MappedSourceRulesTest.doc("a", "b")));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, s)) {
            assertThat(registry.snapshot().entities()).hasSize(2);
            // A lookup answer the partner signed with the same key, served at the list's location.
            serveJws(ctx, sign(k1, Map.of("id", "x", "did", "did:example:x")));
            assertThat(m.refresh("partner").lastError())
                    .contains("mapping.entities[0]: the document has no record at $.issuers[*]").contains("allowEmpty");
            assertThat(registry.snapshot().entities()).hasSize(2);
            // Counted over all pages, a block that finds nothing loads when it says so.
            Map<String, Object> mapping = bare();
            ((Map<String, Object>) ((List<?>) mapping.get("entities")).getFirst()).put("allowEmpty", true);
            serveJws(ctx, sign(k1, MappedSourceRulesTest.doc()));
            try {
                assertThat(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "mapping", mapping)).load().entities())
                        .isEmpty();
            } catch (TrustSourceException e) {
                throw new AssertionError(e.getMessage());
            }
        }
    }

    @Test
    void f3_allowEmptyIsABlockMemberAndAFlag() {
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceRulesTest.doc("a"));
        Map<String, Object> mapping = MappedSourceRulesTest.mapping();
        ((Map<String, Object>) ((List<?>) mapping.get("entities")).getFirst()).put("allowEmpty", "sometimes");
        assertThat(loadError(source(ctx, props("mapping", mapping)))).contains("mapping.entities[0].allowEmpty must be true or false");
        Map<String, Object> lookup = lookupOnly();
        Map<String, Object> entity = new LinkedHashMap<>(Map.of("id", "$.id", "allowEmpty", true));
        lookup.put("mapping", Map.of("lookup", Map.of("url", BASE + "{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:example:"), "entity", entity)));
        assertThat(loadError(source(ctx, lookup))).contains("mapping.lookup.entity: allowEmpty applies to the blocks of entities and anchors");
    }

    @Test
    void f3_withVerifyIssuerTheDocumentMustNameThatIssuer() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "issuer", "https://registry.partner.example")));
        Map<String, Object> claims = new LinkedHashMap<>(MappedSourceRulesTest.doc("a"));
        claims.put("iss", "https://registry.partner.example");
        serveJws(ctx, sign(k1, claims));
        assertThat(s.load().entities()).hasSize(1);
        claims.put("iss", "https://sandbox.partner.example");
        serveJws(ctx, sign(k1, claims));
        assertThat(loadError(s)).contains("The document's issuer (iss) is 'https://sandbox.partner.example', "
                + "not 'https://registry.partner.example' (verify.issuer)");
        claims.remove("iss");
        serveJws(ctx, sign(k1, claims));
        assertThat(loadError(s)).contains("The document names no issuer (iss); verify.issuer is 'https://registry.partner.example'");
        // A lookup answer too.
        Map<String, Object> p = lookupOnly();
        p.put("format", "jws");
        p.put("verify", Map.of("jwks", jwks(k1), "issuer", "https://registry.partner.example"));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        long iat = MappedSourceRulesTest.NOW.getEpochSecond();
        ctx.http.respond(BASE + "did%3Aexample%3Ab", 200, "application/jwt", utf8(sign(k1, Map.of("id", "b", "did", "did:example:b",
                "iat", iat, "iss", "https://sandbox.partner.example"))));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).hasMessageContaining("verify.issuer");
        ctx.http.respond(BASE + "did%3Aexample%3Ac", 200, "application/jwt", utf8(sign(k1, Map.of("id", "c", "did", "did:example:c",
                "iat", iat, "iss", "https://registry.partner.example"))));
        assertThat(r.resolve(Identifier.did("did:example:c"))).isPresent();
    }

    @Test
    void f3_aSignedListsIatIsItsIssueTimeWhenTheMappingNamesNone() {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "mapping", bare()));
        Map<String, Object> current = new LinkedHashMap<>(MappedSourceRulesTest.doc("a"));
        current.put("iat", MappedSourceRulesTest.NOW.minus(Duration.ofHours(1)).getEpochSecond());
        Map<String, Object> older = new LinkedHashMap<>(MappedSourceRulesTest.doc("a", "withdrawn"));
        older.put("iat", MappedSourceRulesTest.NOW.minus(Duration.ofDays(3)).getEpochSecond());
        serveJws(ctx, sign(k1, current));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, s)) {
            assertThat(state(m, "partner").listInfo().issuedAt()).isEqualTo(MappedSourceRulesTest.NOW.minus(Duration.ofHours(1)));
            // The list from before "withdrawn" was taken off, signed by the same key, served again.
            serveJws(ctx, sign(k1, older));
            assertThat(m.refresh("partner").lastError()).contains("older than the one already loaded");
            assertThat(registry.snapshot().entities()).extracting(e -> e.id()).containsExactly("partner:a");
        }
        current.put("iat", MappedSourceRulesTest.NOW.plus(Duration.ofDays(1)).getEpochSecond());
        serveJws(ctx, sign(k1, current));
        assertThat(loadError(s)).contains("in the future");
        current.put("iat", "yesterday");
        serveJws(ctx, sign(k1, current));
        assertThat(loadError(s)).contains("The list's iat is not a NumericDate");
    }

    @Test
    void f3_aSignedLookupAnswerMustSayWhenItWasMade() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        Map<String, Object> p = lookupOnly();
        p.put("format", "jws");
        p.put("verify", Map.of("jwks", jwks(k1)));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        long now = MappedSourceRulesTest.NOW.getEpochSecond();
        // An answer recorded once, and replayed for as long as the key is pinned.
        ctx.http.respond(BASE + "did%3Aexample%3Aa", 200, "application/jwt", utf8(sign(k1, Map.of("id", "a", "did", "did:example:a"))));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:a"))).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("The answer states neither exp nor iat");
        ctx.http.respond(BASE + "did%3Aexample%3Ab", 200, "application/jwt", utf8(sign(k1, Map.of("id", "b", "did", "did:example:b",
                "iat", now - Duration.ofHours(25).toSeconds()))));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).hasMessageContaining("more than PT24H ago (lookup.maxAge)");
        ctx.http.respond(BASE + "did%3Aexample%3Ac", 200, "application/jwt", utf8(sign(k1, Map.of("id", "c", "did", "did:example:c",
                "iat", now - Duration.ofHours(23).toSeconds()))));
        assertThat(r.resolve(Identifier.did("did:example:c"))).isPresent();
        // With exp, exp decides.
        ctx.http.respond(BASE + "did%3Aexample%3Ad", 200, "application/jwt", utf8(sign(k1, Map.of("id", "d", "did", "did:example:d",
                "iat", now - Duration.ofDays(30).toSeconds(), "exp", now + 60))));
        assertThat(r.resolve(Identifier.did("did:example:d"))).isPresent();
        ctx.http.respond(BASE + "did%3Aexample%3Ae", 200, "application/jwt", utf8(sign(k1, Map.of("id", "e", "did", "did:example:e",
                "iat", now + Duration.ofDays(1).toSeconds()))));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:e"))).hasMessageContaining("in the future");

        // lookup.maxAge sets the bound; it applies to signed answers only.
        Map<String, Object> hour = lookupOnly("maxAge", "PT1H");
        hour.put("format", "jws");
        hour.put("verify", Map.of("jwks", jwks(k1)));
        assertThatThrownBy(() -> ((OnDemandResolver) source(ctx, hour)).resolve(Identifier.did("did:example:c")))
                .hasMessageContaining("more than PT1H ago (lookup.maxAge)");
        assertThat(loadError(source(ctx, lookupOnly("maxAge", "PT1H")))).contains("mapping.lookup.maxAge applies to format: jws");
        assertThat(loadError(source(ctx, lookupOnly("maxAge", "a day")))).contains("mapping.lookup.maxAge must be a duration such as PT24H");
    }

    // F4: a restriction in an unexpected shape was dropped, and the entry was wider than the document says -------------

    /** The partner's mapping with these members added to (or, for a null value, removed from) its entities block. */
    static Map<String, Object> entities(Object... kv) {
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        Map<String, Object> block = (Map<String, Object>) ((List<?>) m.get("entities")).getFirst();
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) {
                block.remove((String) kv[i]);
            } else {
                block.put((String) kv[i], kv[i + 1]);
            }
        }
        return m;
    }

    /** The warnings of a load of {@code issuers} (each with an id, an issuer URL and an active state added) under {@code mapping}. */
    static SourceLoadResultView load(Map<String, Object> mapping, List<Map<String, Object>> issuers) throws TrustSourceException {
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc();
        List<Object> all = new java.util.ArrayList<>();
        int n = 0;
        for (Map<String, Object> issuer : issuers) {
            Map<String, Object> i = new LinkedHashMap<>(Map.of("id", "p" + n++, "credential_issuer", "https://p.example", "state", "active"));
            i.putAll(issuer);
            all.add(i);
        }
        all.add(Map.of("id", "fine", "credential_issuer", "https://fine.example", "state", "active"));   // so that the load succeeds
        d.put("issuers", all);
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", mapping)).load();
        return new SourceLoadResultView(r.entities().stream().map(e -> e.id()).toList(), r.entities(), r.warnings());
    }

    record SourceLoadResultView(List<String> ids, List<io.vctrust.trust.core.model.TrustedEntity> entities, List<String> warnings) {
    }

    static final Map<String, Object> AUTHORIZATIONS = Map.of("each", "$.credentials[*]", "format", "$.format", "type", "$.type");

    @Test
    void f4_anAuthorizationThatLacksAConfiguredMemberSkipsTheRecordAndIsNoWildcard() throws Exception {
        Map<String, Object> m = entities("authorizations", List.of(AUTHORIZATIONS));
        var r = load(m, List.of(
                Map.of("credentials", List.of(Map.of("format", "mso_mdoc"))),                                 // type missing
                Map.of("credentials", List.of(Map.of("fmt", "mso_mdoc", "vct", "org.iso.18013.5.1.mDL"))),    // members renamed
                Map.of("credentials", List.of(Map.of("format", "mso_mdoc", "type", "org.iso.18013.5.1.mDL"))),
                Map.of("credentials", List.of())));                                                         // none: absent
        assertThat(r.ids()).containsExactly("partner:p2", "partner:p3", "partner:fine");
        assertThat(r.warnings()).containsExactly(
                "mapping.entities[0]: record 1 is skipped: authorizations: an item yields no type; "
                        + "an authorization is never left open where the document does not say so",
                "mapping.entities[0]: record 2 is skipped: authorizations: an item yields no format; "
                        + "an authorization is never left open where the document does not say so");
    }

    @Test
    void f4_aDateThatIsNotOneSkipsTheRecordAndANumberIsSecondsInTheRangeOfTwelveDigits() throws Exception {
        Map<String, Object> m = entities("validUntil", "$.valid_until");
        long millis = MappedSourceRulesTest.NOW.toEpochMilli();
        var r = load(m, List.of(Map.of("valid_until", millis), Map.of("valid_until", -1), Map.of("valid_until", 1.5),
                Map.of("valid_until", Map.of("seconds", 1)), Map.of("valid_until", 999_999_999_999L)));
        assertThat(r.ids()).containsExactly("partner:p4", "partner:fine");
        assertThat(r.entities().getFirst().validUntil()).isEqualTo(java.time.Instant.ofEpochSecond(999_999_999_999L));
        assertThat(r.warnings()).containsExactly(
                "mapping.entities[0]: record 1 is skipped: validUntil is not a date: '" + millis + "'",
                "mapping.entities[0]: record 2 is skipped: validUntil is not a date: '-1'",
                "mapping.entities[0]: record 3 is skipped: validUntil is not a date: '1.5'",
                "mapping.entities[0]: record 4 is skipped: validUntil is not a date: '{...}'");
        // A list fact that is not a date fails the load.
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("next_update", MappedSourceRulesTest.NOW.plus(Duration.ofDays(1)).toEpochMilli());
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props()))).contains("mapping.list.nextUpdate: the document has no date there");
    }

    @Test
    void f4_aListPathOverSomethingThatIsNoListSkipsTheRecordAndConstrainsNothingAway() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "docTypes", "$.doctypes[*]")));
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("authorities", List.of(
                Map.of("kid", "free-iaca", "certificate", MappedTesting.der("iaca"), "doctypes", "org.iso.18013.5.1.mDL"),
                Map.of("kid", "bound-iaca", "certificate", MappedTesting.der("iaca"), "doctypes", List.of("org.iso.18013.5.1.mDL"))));
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", m)).load();
        assertThat(r.anchors()).singleElement().satisfies(a -> {
            assertThat(a.id()).isEqualTo("bound-iaca");
            assertThat(a.docTypes()).containsExactly("org.iso.18013.5.1.mDL");
        });
        assertThat(r.warnings()).containsExactly("mapping.anchors[0]: record 1 is skipped: "
                + "docTypes: the path $.doctypes[*] finds text where [*] needs a list or an object");

        // The same for a member under something that is not an object, and for a template.
        var e = load(entities("name", "$.display.name", "attributes", Map.of("region", Map.of("template", "UT-{$.region}"))),
                List.of(Map.of("display", "Alpha"), Map.of("region", Map.of("code", "N")), Map.of("display", Map.of("name", "Gamma"))));
        assertThat(e.ids()).containsExactly("partner:p2", "partner:fine");
        assertThat(e.warnings()).containsExactly(
                "mapping.entities[0]: record 1 is skipped: name: the path $.display.name finds text where .name needs an object",
                "mapping.entities[0]: record 2 is skipped: attributes.region: the path $.region finds an object where text belongs");
    }

    @Test
    void f4_aStatusTheMappingCannotReadSkipsTheRecordAndDefaultCoversBoth() throws Exception {
        Map<String, Object> translated = entities("status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE", "suspended", "SUSPENDED")));
        var r = load(translated, List.of(Map.of("state", "withdrawn"), Map.of("state", "suspended")));
        Map<String, Object> without = new LinkedHashMap<>(Map.of("id", "nostate", "credential_issuer", "https://n.example"));
        assertThat(r.ids()).containsExactly("partner:p1", "partner:fine");
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 1 is skipped: status yields nothing "
                + "(no value at its path, or one its translation does not know); give status a default to say what such a record is");
        // No value at the path is the same.
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("issuers", List.of(without, Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active")));
        serveJson(ctx, d);
        assertThat(source(ctx, props("mapping", translated)).load().entities()).extracting(e -> e.id()).containsExactly("partner:a");
        assertThat(source(ctx, props("mapping", entities("status", "$.state"))).load().entities()).extracting(e -> e.id())
                .containsExactly("partner:a");
        // A default says what both are: "no status is active" is written default: ACTIVE.
        Map<String, Object> active = entities("status", Map.of("path", "$.state", "values", Map.of("suspended", "SUSPENDED"), "default", "ACTIVE"));
        assertThat(source(ctx, props("mapping", active)).load().entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:nostate ACTIVE", "partner:a ACTIVE");
    }

    @Test
    void f4_requiredNamesTheMembersARecordMustYield() throws Exception {
        // The partner renamed valid_until to validUntil: without required, the record would read as "no expiry".
        Map<String, Object> m = entities("validUntil", "$.valid_until", "required", List.of("validUntil", "name"));
        var r = load(m, List.of(Map.of("validUntil", "2020-01-01T00:00:00Z", "name", "Renamed"),
                Map.of("valid_until", "2030-01-01T00:00:00Z", "name", "Kept"),
                Map.of("valid_until", "2030-01-01T00:00:00Z")));
        assertThat(r.ids()).containsExactly("partner:p1");
        assertThat(r.warnings()).containsExactly(
                "mapping.entities[0]: record 1 is skipped: validUntil is required and yields nothing",
                "mapping.entities[0]: record 3 is skipped: name is required and yields nothing",
                "mapping.entities[0]: record 4 is skipped: validUntil is required and yields nothing");
        // Anchors too, constraints included.
        TestContext ctx = ctx();
        Map<String, Object> anchors = MappedSourceRulesTest.mapping();
        anchors.put("anchors", List.of(Map.of("each", "$.authorities[*]", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "docTypes", "$.doctypes[*]", "required", "docTypes")));
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("authorities", List.of(Map.of("certificate", MappedTesting.der("iaca"), "docTypes", List.of("org.iso.18013.5.1.mDL"))));
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props("mapping", anchors)))).contains("none of the 1 records at $.authorities[*] could be mapped; "
                + "record 1 is skipped: docTypes is required and yields nothing");
        // A name that is no member of the block, or one the block does not map, is a configuration error.
        assertThat(loadError(source(ctx, props("mapping", entities("required", List.of("valid_until"))))))
                .contains("mapping.entities[0].required: 'valid_until' is not a member of the block");
        assertThat(loadError(source(ctx, props("mapping", entities("required", List.of("validUntil"))))))
                .contains("mapping.entities[0].required: names validUntil, which the block does not map");
    }

    // F5: a root path in a list member cost records times root size ------------------------------------------------

    static Map<String, Object> withContexts(int records, int contexts) {
        Map<String, Object> d = MappedSourceRulesTest.doc();
        List<Object> issuers = new java.util.ArrayList<>();
        for (int i = 0; i < records; i++) {
            issuers.add(Map.of("id", "p" + i, "credential_issuer", "https://p.example", "state", "active"));
        }
        List<Object> urls = new java.util.ArrayList<>();
        for (int i = 0; i < contexts; i++) {
            urls.add("https://contexts.example/" + i);
        }
        d.put("issuers", issuers);
        d.put("contexts", urls);
        return d;
    }

    @Test
    void f5_aMemberYieldsAtMostAThousandValuesForOneRecord() throws Exception {
        // 200 records that each take the document's 2,000 contexts: 400,000 entries in the registry before.
        TestContext ctx = ctx();
        serveJson(ctx, withContexts(200, 2_000));
        Map<String, Object> m = entities("contexts", "^.contexts[*]");
        assertThat(loadError(source(ctx, props("mapping", m)))).contains("none of the 200 records at $.issuers[*] could be mapped; "
                + "record 1 is skipped: contexts: yields more than 1000 values for one record");
        serveJson(ctx, withContexts(200, 1_000));
        assertThat(source(ctx, props("mapping", m)).load().entities()).hasSize(200)
                .allSatisfy(e -> assertThat((List<?>) e.attributes().get(io.vctrust.trust.core.metadata.Oid4vciMetadataMapper.CONTEXTS))
                        .hasSize(1_000));
        // Several forms of one member count together, and so do the items of a nested each.
        m = entities("certificates", List.of("$.a[*]", "$.b[*]"), "identifiers", List.of(Map.of("each", "^.contexts[*]", "type", "URL", "value", "$")));
        var r = load(m, List.of(Map.of("a", java.util.Collections.nCopies(600, MappedTesting.der("ds")), "b",
                java.util.Collections.nCopies(600, MappedTesting.der("ds")))));
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 1 is skipped: certificates: yields more than 1000 values for one record");
        TestContext many = ctx();
        serveJson(many, withContexts(3, 1_001));
        assertThat(loadError(source(many, props("mapping", m)))).contains("identifiers: yields more than 1000 values for one record");
    }

    // F6: the same id twice in one document: the first record won, also over a later REVOKED -------------------------

    static Map<String, Object> withAuthorities(List<Map<String, Object>> authorities) {
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("authorities", authorities);
        return d;
    }

    static Map<String, Object> anchorMapping() {
        Map<String, Object> m = MappedSourceRulesTest.mapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE"), "default", "REVOKED"), "docTypes", "$.doctypes[*]")));
        return m;
    }

    @Test
    void f6_twoRecordsOfOneAnchorIdMustSayTheSameThing() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> iaca = Map.of("kid", "iaca", "certificate", MappedTesting.der("iaca"), "state", "active",
                "doctypes", List.of("org.iso.18013.5.1.mDL"));
        // The CA withdrawn further down the list: the first record does not win.
        Map<String, Object> withdrawn = new LinkedHashMap<>(iaca);
        withdrawn.put("state", "withdrawn");
        serveJson(ctx, withAuthorities(List.of(iaca, withdrawn)));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", anchorMapping())))) {
            assertThat(state(m, "partner").lastError()).isEqualTo("Anchor 'iaca' is given twice in the list with a different status: "
                    + "which one holds cannot be told");
            assertThat(registry.snapshot().allAnchors()).isEmpty();
        }
        Map<String, Object> other = new LinkedHashMap<>(iaca);
        other.put("certificate", MappedTesting.der("rp-ca"));
        other.put("doctypes", List.of("eu.europa.ec.eudi.pid.1"));
        serveJson(ctx, withAuthorities(List.of(iaca, other)));
        assertThat(loadError(source(ctx, props("mapping", anchorMapping()))))
                .isEqualTo("Anchor 'iaca' is given twice in the list with a different certificate and constraints: which one holds cannot be told");
        // The same record twice is one anchor.
        serveJson(ctx, withAuthorities(List.of(iaca, iaca)));
        assertThat(source(ctx, props("mapping", anchorMapping())).load().anchors()).extracting(a -> a.id()).containsExactly("iaca");
    }

    @Test
    void f6_recordsOfOneEntityIdCannotRelaxOrHideWhatAnotherStates() {
        TestContext ctx = ctx();
        Map<String, Object> m = entities("validUntil", "$.valid_until", "validFrom", "$.valid_from");
        java.time.Instant soon = MappedSourceRulesTest.NOW.plus(Duration.ofDays(1));
        java.time.Instant later = MappedSourceRulesTest.NOW.plus(Duration.ofDays(30));
        java.time.Instant before = MappedSourceRulesTest.NOW.minus(Duration.ofDays(30));
        Map<String, Object> d = MappedSourceRulesTest.doc();
        d.put("issuers", List.of(
                Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active", "valid_from", before.toString()),
                Map.of("id", "a", "credential_issuer", "https://a2.example", "state", "suspended", "valid_until", soon.toString()),
                Map.of("id", "a", "credential_issuer", "https://a3.example", "state", "active", "valid_until", later.toString(),
                        "valid_from", MappedSourceRulesTest.NOW.minus(Duration.ofDays(1)).toString()),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", "active")));
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            var a = registry.snapshot().entity("partner:a").orElseThrow();
            assertThat(a.status()).isEqualTo(io.vctrust.trust.core.model.EntityStatus.SUSPENDED);
            assertThat(a.validUntil()).isEqualTo(soon);
            assertThat(a.validFrom()).isEqualTo(MappedSourceRulesTest.NOW.minus(Duration.ofDays(1)));
            assertThat(a.identifiers()).hasSize(3);
            assertThat(state(manager, "partner").warnings()).containsExactly("Entity 'partner:a' has 3 records that disagree on its "
                    + "status or validity; each keeps the strictest: status SUSPENDED, valid from " + MappedSourceRulesTest.NOW.minus(Duration.ofDays(1))
                    + ", valid until " + soon);
        }
    }
}
