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

    // 2: a mapped document decides how many CRL locations the service fetches -------------------------------------------

    static List<String> crlUrls(int n) {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            urls.add("https://pki.partner.example/crl/" + i + ".crl");
        }
        return urls;
    }

    @Test
    void item2_aMappedAnchorYieldsAtMostFourCrlLocations() throws Exception {
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "$.domain", "certificate", "$.certificate",
                "crlUrls", "$.crl_urls[*]")));
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER")));
        d.put("authorities", List.of(
                Map.of("kid", "shared-iaca", "domain", "mdoc-iaca", "certificate", der("iaca"), "crl_urls", crlUrls(5)),
                Map.of("kid", "rp-ca", "domain", "verifier-access", "certificate", der("rp-ca"), "crl_urls", crlUrls(4))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", m)).load();
        assertThat(r.anchors()).singleElement().satisfies(a -> {
            assertThat(a.id()).isEqualTo("rp-ca");
            assertThat((List<?>) a.constraints().get("crlUrls")).hasSize(4);
        });
        assertThat(r.warnings()).containsExactly("mapping.anchors[0]: record 1 (id 'shared-iaca') is skipped: crlUrls: 5 CRL locations, "
                + "more than 4 for one anchor");
        // Twenty anchors that each take the document's thousand CRL locations (a 41 kB document) made the service
        // fetch 20,000 of them in one refresh: none is listed with more than four.
        Map<String, Object> many = new LinkedHashMap<>(m);
        many.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "crlUrls", "^.crl_urls[*]")));
        List<Object> authorities = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            authorities.add(Map.of("kid", "iaca-" + i, "certificate", der("iaca")));
        }
        d.put("authorities", authorities);
        d.put("crl_urls", crlUrls(1_000));
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", many)))) {
            assertThat(registry.snapshot().allAnchors()).isEmpty();
            assertThat(state(manager, "partner").lastError()).contains("none of the 20 records at $.authorities[*] could be mapped; "
                    + "record 1 (id 'iaca-0') is skipped: crlUrls: 1000 CRL locations, more than 4 for one anchor");
        }
    }

    // 3: nodes that weigh nothing ------------------------------------------------------------------------------------

    @Test
    void item3_aNullOrAnEmptyListOrObjectWeighsOneNodeAndARecordYieldsAtMost4096() throws Exception {
        // attributes: {country: ^.country} over a list of 200,000 nulls in 1,000 records loaded with no warning, and
        // referenced 200 million entries.
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.issuers(1_000, Map.of("country", Collections.nCopies(200_000, null))));
        Map<String, Object> country = MappedSourceAttacksTest.entities("attributes", Map.of("country", "^.country"));
        assertThat(loadError(source(ctx, props("mapping", country)))).contains("none of the 1000 records at $.issuers[*] could be read "
                + "completely; record 1 (id 'partner:p0') is listed SUSPENDED: attributes.country: the record would yield more than 4096 "
                + "nodes (values, nulls, lists and objects)");
        serveJson(ctx, MappedSourceValidationTest.issuers(1_000, Map.of("country", "UT")));
        assertThat(source(ctx, props("mapping", country)).load().entities()).hasSize(1_000)
                .allSatisfy(e -> assertThat(e.attributes()).containsEntry("country", "UT"));
        // The same through metadataPolicy, of empty objects.
        Map<String, Object> heavy = Map.of("openid_credential_issuer", Map.of("display", Map.of("one_of", Collections.nCopies(5_000, Map.of()))));
        Map<String, Object> light = Map.of("openid_credential_issuer", Map.of("display", Map.of("one_of", Collections.nCopies(5, Map.of()))));
        var r = MappedSourceAttacksTest.load(MappedSourceAttacksTest.entities("metadataPolicy", "$.policy"),
                List.of(Map.of("policy", heavy), Map.of("policy", light)));
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:p0 SUSPENDED", "partner:p1 ACTIVE", "partner:fine ACTIVE");
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 1 (id 'partner:p0') is listed SUSPENDED: metadataPolicy: the "
                + "record would yield more than 4096 nodes (values, nulls, lists and objects)");
        assertThat(r.entities().getFirst().metadataPolicy()).isEmpty();
    }

    @Test
    void item3_nodesCountTowardTheLoadsBudget() throws Exception {
        // 50 records of a hundred nulls each: about 3,400 characters of mapped text, and 5,000 nodes more.
        Map<String, Object> d = MappedSourceRulesTest.doc();
        List<Object> issuers = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            issuers.add(Map.of("id", "p" + i, "credential_issuer", "https://p" + i + ".example", "state", "active",
                    "flags", Collections.nCopies(100, null)));
        }
        d.put("issuers", issuers);
        TestContext ctx = ctx();
        serveJson(ctx, d);
        Map<String, Object> m = MappedSourceAttacksTest.entities("attributes", Map.of("flags", "$.flags"));
        assertThat(loadError(source(ctx, props("mapping", m, "limits", Map.of("text", 5_000)))))
                .contains("The list's records yield more than 5000 characters and nodes of mapped text (limits.text)");
        assertThat(source(ctx, props("mapping", m, "limits", Map.of("text", 10_000))).load().entities()).hasSize(50);
    }

    // 4: pages ---------------------------------------------------------------------------------------------------

    static final String LOCATION = MappedSourceRulesTest.LOCATION;
    static final String PAGE_2 = MappedSourceValidationTest.PAGE_2;
    static final String PAGE_3 = MappedSourceValidationTest.PAGE_3;

    /** A list of three pages numbered from {@code first}; its first page revokes "b". */
    static Map<String, Object> page(int k, int first) {
        Map<String, Object> d = MappedSourceValidationTest.page(k == 1 ? 2 : k == 2 ? 1 : 3, k - 1 + first, 3);
        d.put("next", k == 1 ? PAGE_2 : PAGE_3);
        if (k == 3) {
            d.remove("next");
        }
        return d;
    }

    static io.vctrust.trust.core.evaluation.Decision decideAbout(TrustRegistry registry, String identifier) {
        return MappedSourceFixturesTest.decide(registry, MappedSourceFixturesTest.issuer(identifier, List.of(), null, null)).decision();
    }

    @Test
    void item4_theFirstPageSaysExactlyTheNumberPagesFirstNames() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        MappedSourceValidationTest.serve(ctx, k1, LOCATION, page(1, 0));
        MappedSourceValidationTest.serve(ctx, k1, PAGE_2, page(2, 0));
        MappedSourceValidationTest.serve(ctx, k1, PAGE_3, page(3, 0));
        // A list that counts from 0 says so: page 0 first. Without first: 0, its first page is not one.
        Map<String, Object> fromZero = MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "number", "$.page", "first", 0));
        Map<String, Object> fromOne = MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "number", "$.page"));
        assertThat(loadError(source(ctx, fromOne))).contains("Page 1 of the list says it is page 0, not 1 (mapping.pages.first)");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, fromZero))) {
            assertThat(registry.snapshot().entities()).extracting(e -> e.id() + " " + e.status())
                    .containsExactly("partner:b REVOKED", "partner:a ACTIVE", "partner:c ACTIVE");
            assertThat(decideAbout(registry, "https://b.example")).isEqualTo(Decision.NOT_TRUSTED);
            // The page that says 1, served at location as the first: page 0, which revokes "b", would be left out.
            MappedSourceValidationTest.serve(ctx, k1, LOCATION, page(2, 0));
            assertThat(manager.refresh("partner").lastError()).contains("Page 1 of the list says it is page 1, not 0 (mapping.pages.first)");
            assertThat(decideAbout(registry, "https://b.example")).isEqualTo(Decision.NOT_TRUSTED);
        }
        // Only 0 or 1, and only with a page number to compare it with.
        assertThat(loadError(source(ctx, MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "number", "$.page", "first", 2)))))
                .contains("mapping.pages.first must be 0 or 1");
        assertThat(loadError(source(ctx, MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "count", "$.pages", "first", 0)))))
                .contains("mapping.pages.first applies with mapping.pages.number");
    }

    /** {@code ctx}'s responses, as if each URL of {@code redirects} had been redirected to the other address given. */
    static io.vctrust.trust.core.spi.SourceContext redirecting(TestContext ctx, Map<String, String> redirects) {
        return new io.vctrust.trust.core.spi.SourceContext() {
            @Override
            public io.vctrust.trust.core.spi.HttpFetcher http() {
                return request -> {
                    String to = redirects.get(request.uri().toString());
                    if (to == null) {
                        return ctx.http.execute(request);
                    }
                    var r = ctx.http.execute(new io.vctrust.trust.core.spi.HttpFetcher.Request("GET", java.net.URI.create(to),
                            request.headers(), null, null));
                    return new io.vctrust.trust.core.spi.HttpFetcher.Response(r.status(), r.headers(), r.body(), java.net.URI.create(to));
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
    }

    @Test
    void item4_theAddressAPageWasFinallyReadFromCountsAsRead() throws Exception {
        // Pages with relative next links ("page2"), counted. Location is redirected to ".../issuers/", whose page 2 is
        // ".../issuers/page2"; that one is redirected back to location, which serves page 1 again, whose "page2" now
        // resolves to ".../v1/page2": page 3 is served there, and the three pages read are the count. Page 2 is gone.
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        String slash = LOCATION + "/";
        Map<String, Object> first = MappedSourceValidationTest.page(1, null, 3);
        first.put("next", "page2");
        Map<String, Object> third = MappedSourceValidationTest.page(3, null, 3);
        MappedSourceValidationTest.serve(ctx, k1, slash, first);
        MappedSourceValidationTest.serve(ctx, k1, "https://registry.partner.example/v1/page2", third);
        MappedSourceValidationTest.serve(ctx, k1, LOCATION, first);
        Map<String, Object> counted = MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "count", "$.pages"));
        java.util.function.Function<Map<String, String>, io.vctrust.trust.core.spi.TrustSource> create = redirects ->
                new io.vctrust.trust.adapters.mapped.MappedSourceFactory().create(new io.vctrust.trust.core.spi.SourceDefinition("partner",
                        "mapped", "partner", null, true, counted), redirecting(ctx, redirects));
        assertThat(loadError(create.apply(Map.of(LOCATION, slash, slash + "page2", LOCATION))))
                .contains("Page 2 of the list was read from an address already read");
        // Served as it should be, the redirect of location is no reason to refuse it.
        Map<String, Object> second = MappedSourceValidationTest.page(2, null, 3);
        second.put("next", "https://registry.partner.example/v1/page2");
        MappedSourceValidationTest.serve(ctx, k1, slash + "page2", second);
        assertThat(create.apply(Map.of(LOCATION, slash)).load().entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly("partner:a ACTIVE", "partner:b REVOKED", "partner:c ACTIVE");
    }

    @Test
    void item4_signedPagesWarnUnlessTheySayBothTheirNumberAndTheirCount() throws Exception {
        com.nimbusds.jose.jwk.ECKey k1 = MappedTesting.key("k1");
        TestContext ctx = ctx();
        MappedSourceValidationTest.serve(ctx, k1, LOCATION, MappedSourceValidationTest.page(1, 1, 3));
        MappedSourceValidationTest.serve(ctx, k1, PAGE_2, MappedSourceValidationTest.page(2, 2, 3));
        MappedSourceValidationTest.serve(ctx, k1, PAGE_3, MappedSourceValidationTest.page(3, 3, 3));
        String warning = "The list comes in pages that are signed one by one and do not say both their number and their count "
                + "(mapping.pages.number, mapping.pages.count): whoever serves them can leave one out";
        for (Map<String, Object> pages : List.<Map<String, Object>>of(Map.of("next", "$.next"), Map.of("next", "$.next", "number", "$.page"),
                Map.of("next", "$.next", "count", "$.pages"))) {
            assertThat(source(ctx, MappedSourceValidationTest.signedPages(k1, pages)).load().warnings()).as(pages.toString())
                    .containsExactly(warning);
        }
        assertThat(source(ctx, MappedSourceValidationTest.signedPages(k1, Map.of("next", "$.next", "number", "$.page", "count", "$.pages")))
                .load().warnings()).isEmpty();
    }
}
