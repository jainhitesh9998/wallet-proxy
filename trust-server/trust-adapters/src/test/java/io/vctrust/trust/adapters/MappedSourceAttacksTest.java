package io.vctrust.trust.adapters;

import com.nimbusds.jose.jwk.ECKey;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
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
import static io.vctrust.trust.adapters.MappedTesting.utf8;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
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
}
