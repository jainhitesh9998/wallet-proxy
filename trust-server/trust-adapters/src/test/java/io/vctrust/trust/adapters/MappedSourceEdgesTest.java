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

    // 1: a record that yields no role -----------------------------------------------------------------------------

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
            // Listed without a role, the revoked issuer's entry answered no question about it, and the shared IACA
            // alone decided: TRUSTED. (The evaluator now holds a roleless entry not in good standing against its party;
            // but a record that yields no role may be one whose roles were renamed upstream: the load fails, unless the
            // mapping says that an empty list means none stated, MappedSourceRegistryTest.item2_...)
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
                + "required: say where a record states its roles (with { path, allowEmpty: true } when a list that is there and empty "
                + "means none stated)");
        Map<String, Object> lookup = lookupOnly();
        Map<String, Object> l = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) lookup.get("mapping")).get("lookup"));
        l.put("entity", Map.of("id", "$.id", "identifiers", List.of(Map.of("type", "DID", "value", "$.did"))));
        lookup.put("mapping", Map.of("lookup", l));
        assertThat(loadError(source(ctx, lookup))).contains("mapping.lookup.entity: roles is required");
        assertThat(ctx.http.requests).isEmpty();
        // allowEmpty on roles was refused here; it is allowed again since the registry keeps a party out by an entry not
        // in good standing that names no role (MappedSourceRegistryTest.item2_...): an empty list then means none stated,
        // and a record whose roles are not there at all still fails the load.
        block(m).put("roles", Map.of("path", "$.roles[*]", "allowEmpty", true));
        assertThat(loadError(source(ctx, props("mapping", m)))).contains("record 1 (id 'partner:dmv') cannot be read: it yields no role");
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

    // 2: a mapped document decided how many CRL locations the service fetches ------------------------------------------

    static List<String> crlUrls(int n) {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            urls.add("https://pki.partner.example/crl/" + i + ".crl");
        }
        return urls;
    }

    @Test
    void item2_aMappedDocumentNoLongerDecidesHowManyCrlLocationsTheServiceFetches() throws Exception {
        // Twenty anchors that each take the document's thousand CRL locations (a 41 kB document) made the service fetch
        // 20,000 of them in one refresh. Round three skipped a mapped anchor with more than four; the registry now
        // counts the first 8 of every anchor, whatever its source (follow-up, item 4: the source's own limit is gone,
        // and an honest CA that names five is no longer refused; MappedSourceRegistryTest.item4_...).
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "crlUrls", "^.crl_urls[*]")));
        List<Object> authorities = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            authorities.add(Map.of("kid", "iaca-" + i, "certificate", der("iaca")));
        }
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER")));
        d.put("authorities", authorities);
        d.put("crl_urls", crlUrls(1_000));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(state(manager, "partner").lastError()).isNull();
            assertThat(registry.snapshot().allAnchors()).hasSize(20).allSatisfy(a -> assertThat(a.crlUrls()).isEqualTo(crlUrls(8)));
            assertThat(registry.snapshot().allAnchors().stream().flatMap(a -> a.crlUrls().stream()).distinct()).hasSize(8);
            assertThat(state(manager, "partner").warnings()).hasSize(20)
                    .allSatisfy(w -> assertThat(w).contains("names 1000 CRL locations (crlUrls); an anchor counts with at most 8"));
        }
        // A member still yields at most 1000 values for one record.
        d.put("crl_urls", crlUrls(1_001));
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props("mapping", m)))).contains("record 1 (id 'iaca-0') is skipped: crlUrls: yields more than "
                + "1000 values for one record");
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

    // 5: a restricting list that is empty or renamed, when the path goes on after it --------------------------------------

    static final String PID = MappedSourceValidationTest.PID;

    /** A JSON value written as text. */
    static Object parse(String json) {
        return Json.parseObject("{\"v\": " + json + "}").get("v");
    }

    /**
     * {@link #withRoles} with the issuer "dmv" bound by nothing but the shared IACA, whose record holds
     * {@code authority}: only the anchor's doctypes keep the IACA from signing any doctype.
     */
    static Map<String, Object> sharedIaca(Map<String, Object> authority) {
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "certificates", null));
        Map<String, Object> iaca = new LinkedHashMap<>(Map.of("kid", "shared-iaca", "certificate", der("iaca")));
        iaca.putAll(authority);
        d.put("authorities", List.of(iaca, Map.of("kid", "rp-ca", "certificate", der("rp-ca"))));
        return d;
    }

    static Map<String, Object> withDocTypes(Object docTypes) {
        Map<String, Object> m = boundMapping();
        Map<String, Object> anchors = new LinkedHashMap<>(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca",
                "certificate", "$.certificate", "docTypes", docTypes));
        m.put("anchors", List.of(anchors));
        return m;
    }

    @Test
    void item5_aDocTypesListThatIsThereAndEmptyOrRenamedWhereThePathGoesOnLeavesNoIacaOpen() {
        Map<String, Object> m = withDocTypes("$.doctypes[*].id");
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("[]", "docTypes: $.doctypes[*].id finds a list or an object that holds no value");
        cases.put("[{}]", "docTypes: the path $.doctypes[*].id finds an item without .id");
        cases.put("[{\"code\": \"" + MDL + "\"}]", "docTypes: the path $.doctypes[*].id finds an item without .id");
        cases.forEach((doctypes, warning) -> {
            TestContext ctx = ctx();
            serveJson(ctx, sharedIaca(Map.of("doctypes", parse(doctypes))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(decide(registry, PID)).as(doctypes).isNotEqualTo(Decision.TRUSTED);
                assertThat(registry.snapshot().allAnchors()).as(doctypes).extracting(a -> a.id()).containsExactly("rp-ca");
                assertThat(state(manager, "partner").warnings()).as(doctypes).singleElement().asString()
                        .startsWith("mapping.anchors[0]: record 1 (id 'shared-iaca') is skipped: " + warning);
            }
        });
        // Not there: absent. And what is there is read.
        for (Object doctypes : java.util.Arrays.asList(null, List.of(Map.of("id", MDL)))) {
            TestContext ctx = ctx();
            serveJson(ctx, sharedIaca(doctypes == null ? Map.of() : Map.of("doctypes", doctypes)));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(state(manager, "partner").warnings()).isEmpty();
                assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
                assertThat(decide(registry, PID)).isEqualTo(doctypes == null ? Decision.TRUSTED : Decision.NOT_TRUSTED);
            }
        }
    }

    static Map<String, Object> withTypes(Map<String, Object> item) {
        Map<String, Object> m = boundMapping();
        block(m).put("roles", List.of("CREDENTIAL_ISSUER"));
        block(m).put("authorizations", List.of(item));
        return m;
    }

    @Test
    void item5_anAuthorizationsListThatIsThereAndEmptyOrRenamedWhereThePathGoesOnLeavesNoIssuerOpen() {
        // each: $.credentials[*].types[*]: the issuer's credentials, each with the types it may issue.
        Map<String, Object> types = withTypes(Map.of("each", "$.credentials[*].types[*]", "format", "mso_mdoc", "type", "$"));
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("[]", "authorizations: $.credentials[*].types[*] finds a list or an object that holds no value");
        cases.put("[{\"format\": \"mso_mdoc\"}]", "authorizations: the path $.credentials[*].types[*] finds an item without .types");
        cases.put("[{\"types\": [\"" + MDL + "\"]}, {\"vct\": \"x\"}]", "authorizations: the path $.credentials[*].types[*] finds an item "
                + "without .types");
        cases.forEach((credentials, warning) -> {
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, members("credentials", parse(credentials))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", types)))) {
                assertThat(decide(registry, PID)).as(credentials).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).as(credentials).isEqualTo(EntityStatus.SUSPENDED);
                assertThat(state(manager, "partner").warnings()).as(credentials).singleElement().asString().contains(warning);
            }
        });
        // Read as the document states it: authorized for the mDL only.
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, members("credentials", List.of(Map.of("types", List.of(MDL))))));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", types)))) {
            assertThat(state(manager, "partner").warnings()).isEmpty();
            assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            assertThat(decide(registry, PID)).isEqualTo(Decision.NOT_TRUSTED);
        }
        // With allowEmpty, a list with no item at all, wherever it is in the path, is "none stated"; an item that lacks
        // what the path goes on to is not.
        Map<String, Object> allowed = withTypes(Map.of("each", "$.credentials[*].types[*]", "allowEmpty", true, "format", "mso_mdoc",
                "type", "$"));
        for (String credentials : List.of("[]", "[{\"types\": []}]", "[{\"format\": \"mso_mdoc\"}]")) {
            ctx = ctx();
            serveJson(ctx, withRoles(1, members("credentials", parse(credentials))));
            registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", allowed)))) {
                boolean lacking = credentials.contains("format");
                assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).as(credentials)
                        .isEqualTo(lacking ? EntityStatus.SUSPENDED : EntityStatus.ACTIVE);
                assertThat(decide(registry, PID)).as(credentials).isEqualTo(lacking ? Decision.NOT_TRUSTED : Decision.TRUSTED);
            }
        }
    }

    // 6: allowEmpty hides a restriction ------------------------------------------------------------------------------

    @Test
    void item6_aValueTheTranslationDoesNotKnowInARestrictingListMakesTheRecordUnreadableWithOrWithoutAllowEmpty() {
        Map<String, Object> table = Map.of("mdl", MDL);
        for (Map<String, Object> docTypes : List.<Map<String, Object>>of(Map.of("path", "$.doctypes[*]", "values", table, "allowEmpty", true),
                Map.of("path", "$.doctypes[*]", "values", table))) {
            for (List<String> doctypes : List.of(List.of("photo-id"), List.of("mdl", "photo-id"))) {
                TestContext ctx = ctx();
                serveJson(ctx, sharedIaca(Map.of("doctypes", doctypes)));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", withDocTypes(docTypes))))) {
                    String what = docTypes.keySet() + " " + doctypes;
                    assertThat(decide(registry, PID)).as(what).isNotEqualTo(Decision.TRUSTED);
                    assertThat(registry.snapshot().allAnchors()).as(what).extracting(a -> a.id()).containsExactly("rp-ca");
                    assertThat(state(manager, "partner").warnings()).as(what).singleElement().asString().contains("is skipped: docTypes: "
                            + "the path $.doctypes[*] finds 'photo-id', which its translation does not know, and it has no default");
                }
            }
        }
        // With a default, the default stands for it; values it knows are read.
        TestContext ctx = ctx();
        serveJson(ctx, sharedIaca(Map.of("doctypes", List.of("mdl"))));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", withDocTypes(Map.of("path", "$.doctypes[*]",
                "values", table, "allowEmpty", true)))))) {
            assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            assertThat(decide(registry, PID)).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void item6_aListEmptiedByAFilterIsNotEmptyAndAllowEmptyDoesNotStandForIt() {
        // each: $.credentials[?@.active == true] with allowEmpty, and the only authorization inactive: unconstrained.
        Map<String, Object> m = withTypes(Map.of("each", "$.credentials[?@.active == true]", "allowEmpty", true, "format", "$.format",
                "type", "$.type"));
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, members("credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL, "active", false)))));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(decide(registry, PID)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(decide(registry, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().status()).isEqualTo(EntityStatus.SUSPENDED);
            assertThat(state(manager, "partner").warnings()).singleElement().asString().contains("authorizations: $.credentials[?@.active "
                    + "== true] finds a list but nothing it holds: a filter leaves its items out");
        }
        // The same for an anchor's doctypes.
        serveJson(ctx, sharedIaca(Map.of("doctypes", List.of(Map.of("id", MDL, "withdrawn", true)))));
        registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", withDocTypes(Map.of("path",
                "$.doctypes[?@.withdrawn != true].id", "allowEmpty", true)))))) {
            assertThat(decide(registry, PID)).isNotEqualTo(Decision.TRUSTED);
            assertThat(registry.snapshot().allAnchors()).extracting(a -> a.id()).containsExactly("rp-ca");
        }
    }

    @Test
    void item6_allowEmptyWhereItChangesNothingIsAConfigurationError() {
        Map<String, Object> m = boundMapping();
        Map<String, Map.Entry<String, Object>> places = new LinkedHashMap<>();
        places.put("mapping.entities[0].certificates", Map.entry("certificates", Map.of("path", "$.certificates[*]", "allowEmpty", true)));
        places.put("mapping.entities[0].contexts[0]", Map.entry("contexts", List.of(Map.of("path", "$.contexts[*]", "allowEmpty", true))));
        places.put("mapping.entities[0].contexts[0]: ", Map.entry("contexts", List.of(Map.of("each", "$.contexts[*]", "allowEmpty", true,
                "url", "$.url"))));
        places.put("mapping.entities[0].identifiers[0]", Map.entry("identifiers", List.of(Map.of("each", "$.dids[*]", "allowEmpty", true,
                "type", "DID", "value", "$"))));
        places.put("mapping.entities[0].display[0]", Map.entry("display", List.of(Map.of("each", "$.display[*]", "allowEmpty", true,
                "name", "$.name"))));
        places.forEach((where, member) -> {
            Map<String, Object> mapping = boundMapping();
            block(mapping).put(member.getKey(), member.getValue());
            TestContext ctx = ctx();
            assertThat(loadError(source(ctx, props("mapping", mapping)))).as(where).contains(where).contains("allowEmpty applies to a list "
                    + "that restricts (authorizations, docTypes)").contains("here it would change nothing");
            assertThat(ctx.http.requests).isEmpty();
        });
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "crlUrls", Map.of("path", "$.crl_urls[*]", "allowEmpty", true))));
        assertThat(loadError(source(ctx(), props("mapping", m)))).contains("mapping.anchors[0].crlUrls: allowEmpty applies to a list that "
                + "restricts");
    }

    // 7: an unreadable row for a certificate that another row lists ----------------------------------------------------

    @Test
    void item7_anUnreadableAnchorRowForACertificateAnotherRowListsFailsTheLoad() {
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "status", Map.of("path", "$.state", "values", Map.of("active", "ACTIVE", "withdrawn", "REVOKED")),
                "docTypes", "$.doctypes[*]")));
        Map<String, Map<String, Object>> unreadable = new LinkedHashMap<>();
        unreadable.put("a status the mapping cannot read", Map.of("kid", "row-7", "certificate", der("iaca"), "state", "withdrawn-2023"));
        unreadable.put("doctypes that cannot be read", Map.of("kid", "row-7", "certificate", der("iaca"), "state", "withdrawn",
                "doctypes", MDL));
        unreadable.put("an id that cannot be one", Map.of("kid", "row 7", "certificate", der("iaca"), "state", "withdrawn"));
        unreadable.forEach((what, row7) -> {
            for (boolean listedFirst : List.of(true, false)) {
                Map<String, Object> row1 = Map.of("kid", "row-1", "certificate", der("iaca"), "state", "active");
                Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "certificates", null));
                d.put("authorities", listedFirst ? List.of(row1, row7) : List.of(row7, row1));
                TestContext ctx = ctx();
                serveJson(ctx, d);
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                    assertThat(decide(registry, MDL)).as(what).isNotEqualTo(Decision.TRUSTED);
                    assertThat(state(manager, "partner").lastError()).as(what).startsWith("Anchor 'row-1' and record " + (listedFirst ? 2 : 1)
                            + " of mapping.anchors[0]" + (what.contains("id") ? "" : " (id 'row-7')") + " have the same certificate in "
                            + "domain mdoc-iaca, and the record cannot be read: which one holds cannot be told");
                }
            }
        });
        // An unreadable row of another certificate is skipped, as before; so is one whose certificate cannot be read.
        for (Object certificate : List.of(der("rp-ca"), "not a certificate")) {
            Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "certificates", null));
            d.put("authorities", List.of(Map.of("kid", "row-1", "certificate", der("iaca"), "state", "active"),
                    Map.of("kid", "row-7", "certificate", certificate, "state", "withdrawn-2023")));
            TestContext ctx = ctx();
            serveJson(ctx, d);
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(state(manager, "partner").lastError()).isNull();
                assertThat(registry.snapshot().allAnchors()).extracting(a -> a.id()).containsExactly("row-1");
                assertThat(state(manager, "partner").warnings()).singleElement().asString().startsWith("mapping.anchors[0]: record 2 "
                        + "(id 'row-7') is skipped");
                assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            }
        }
    }

    // 8: honest lists that were refused or suspended without need -------------------------------------------------------

    @Test
    void item8_textThatOnlyDescribesAPartyAndIsOverTheCapIsLeftOutAndThePartyIsRead() {
        Map<String, Object> m = boundMapping();
        block(m).put("display", List.of(Map.of("each", "$.display[*]", "locale", "$.language", "name", "$.title", "logoUri", "$.logo")));
        block(m).put("attributes", Map.of("motto", "$.motto"));
        String logo = "data:image/png;base64," + "A".repeat(20_000);   // an ordinary logo, written into the list
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "display", List.of(Map.of("language", "en",
                "title", "Utopia DMV", "logo", logo)), "motto", "M".repeat(8_193)));
        List<Object> issuers = new ArrayList<>((List<?>) d.get("issuers"));
        Map<String, Object> college = new LinkedHashMap<>((Map<String, Object>) issuers.get(1));
        college.put("name", "C".repeat(8_193));
        issuers.set(1, college);
        d.put("issuers", issuers);
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            // Suspended before, for a logo: its credentials were not trusted.
            assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
            var dmv = registry.snapshot().entity("partner:dmv").orElseThrow();
            assertThat(dmv.status()).isEqualTo(EntityStatus.ACTIVE);
            assertThat(dmv.displayName("en")).isEqualTo("Utopia DMV");
            assertThat(dmv.display().getFirst().logoUri()).isNull();
            assertThat(dmv.attributes()).doesNotContainKey("motto");
            var other = registry.snapshot().entity("partner:college").orElseThrow();
            assertThat(other.status()).isEqualTo(EntityStatus.ACTIVE);
            assertThat(other.display()).isEmpty();
            assertThat(state(manager, "partner").warnings()).containsExactly(
                    "mapping.entities[0]: record 1 (id 'partner:dmv') is listed without text too long to keep: display.logoUri: a value of "
                            + logo.length() + " characters, more than 8192; attributes.motto: a value of 8193 characters, more than 8192",
                    "mapping.entities[0]: record 2 (id 'partner:college') is listed without text too long to keep: name: a value of 8193 "
                            + "characters, more than 8192");
        }
    }

    @Test
    void item8_certificatesAndCrlsAreNotTextAndCountTowardTheLoadsBudgetOnly() throws Exception {
        // A PEM bundle of an issuer's certificates longer than a text value and than a record's text: the load failed.
        String bundle = String.join("", Collections.nCopies(100, MappedTesting.pem("ds-nl"))) + MappedTesting.pem("ds");
        assertThat(bundle.length()).isGreaterThan(65_536);
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "certificates", List.of(bundle)));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", boundMapping())))) {
            assertThat(state(manager, "partner").lastError()).isNull();
            assertThat(state(manager, "partner").warnings()).isEmpty();
            assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().certificates()).isNotEmpty();
            assertThat(decide(registry, MDL)).isEqualTo(Decision.TRUSTED);
        }
        // They still count toward the load's budget.
        assertThat(loadError(source(ctx, props("mapping", boundMapping(), "limits", Map.of("text", 50_000)))))
                .contains("The list's records yield more than 50000 characters and nodes of mapped text (limits.text)");
        // A CRL pushed in the list, for an anchor.
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "crl", "$.crl")));
        d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER")));
        String crl = java.util.Base64.getEncoder().encodeToString(new byte[15_000]);
        d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"), "crl", crl)));
        serveJson(ctx, d);
        var r = source(ctx, props("mapping", m)).load();
        assertThat(r.anchors()).singleElement().satisfies(a -> assertThat(a.constraints()).containsEntry("crl", crl));
        // Up to a mebibyte.
        d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", der("iaca"), "crl", "A".repeat(1_048_577)),
                Map.of("kid", "rp-ca", "certificate", der("rp-ca"))));
        serveJson(ctx, d);
        assertThat(source(ctx, props("mapping", m)).load().warnings()).singleElement().asString()
                .contains("is skipped: crl: a value of 1048577 characters, more than 1048576");
    }

    @Test
    void item8_anEmptyStringIsAbsentLikeNullForEveryMember() {
        // valid_until: "" suspended the issuer; certificates: ["", "<PEM>"] failed the load.
        Map<String, Map<String, Object>> honest = new LinkedHashMap<>();
        honest.put("valid_until: \"\"", members("roles", List.of("CREDENTIAL_ISSUER"), "valid_until", ""));
        honest.put("certificates: [\"\", <PEM>]", members("roles", List.of("CREDENTIAL_ISSUER"), "certificates", List.of("", MappedTesting.pem("ds"))));
        honest.put("name: \"\"", members("roles", List.of("CREDENTIAL_ISSUER"), "name", ""));
        honest.forEach((what, dmv) -> {
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, dmv));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(state(manager, "partner").warnings()).as(what).isEmpty();
                var e = registry.snapshot().entity("partner:dmv").orElseThrow();
                assertThat(e.status()).as(what).isEqualTo(EntityStatus.ACTIVE);
                assertThat(e.certificates()).as(what).hasSize(1);
                assertThat(decide(registry, MDL)).as(what).isEqualTo(Decision.TRUSTED);
            }
        });
        // What identifies a record: an empty id or role is none, and the load fails as for a missing one.
        Map<String, Object> m = boundMapping();
        block(m).put("roles", "$.roles[*]");
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, members("roles", List.of(""))));
        assertThat(loadError(source(ctx, props("mapping", m)))).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be "
                + "read: it yields no role");
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "id", "")));
        assertThat(loadError(source(ctx, props("mapping", m)))).startsWith("mapping.entities[0]: record 1 cannot be read: it yields no id");
        // A restricting list of empty strings is a list with no item: there and empty.
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "credentials", List.of(""))));
        var r = loadQuietly(source(ctx, props("mapping", m)));
        assertThat(r.entities()).filteredOn(e -> e.id().equals("partner:dmv")).singleElement()
                .satisfies(e -> assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED));
    }

    static String derived(String id) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "sha256:" + java.util.HexFormat.of().formatHex(digest).substring(0, 32);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void item8_anEntityWhoseIdTheRegistryCannotTakeIsListedUnderADerivedIdAndKeptOut() throws Exception {
        // The revoked issuer, bound by its signing certificate under the shared IACA, with an id the registry cannot take.
        Map<String, String> why = new LinkedHashMap<>();
        why.put("dmv two", "is not 1 to 128 letters, digits or . _ : @ ~ - starting with a letter or digit");
        why.put("d".repeat(130), "is not 1 to 128 letters");
        why.forEach((id, reason) -> {
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "id", id, "state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", boundMapping())))) {
                assertThat(decide(registry, MDL)).as(id).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(state(manager, "partner").lastError()).as(id).isNull();
                String derived = derived("partner:" + id);
                var e = registry.snapshot().entity(derived).orElseThrow();
                assertThat(e.status()).isEqualTo(EntityStatus.REVOKED);
                assertThat(e.certificates()).hasSize(1);
                assertThat(registry.snapshot().entity("partner:college")).isPresent();
                assertThat(state(manager, "partner").warnings()).as(id).singleElement().asString()
                        .startsWith("mapping.entities[0]: record 1 (id '" + derived + "') is listed REVOKED: its id 'partner:")
                        .contains("' is listed as '" + derived + "': it " + reason);
            }
        });
        // dmv@other was a case above (a derived id) while the registry dropped a name that ends in @ and another
        // framework's id. It places such an entity itself now: the source lists the id as written (follow-up to the
        // third round, item 3; MappedSourceRegistryTest.item3_...), and the registry lists it under its own framework.
        TestContext other = ctx();
        serveJson(other, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "id", "dmv@other", "state", "revoked")));
        TrustRegistry placed = new TrustRegistry();
        try (TrustSourceManager manager = manager(placed, source(other, props("mapping", boundMapping())))) {
            assertThat(decide(placed, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(placed.snapshot().entity("partner:dmv@other@partner").orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
        }
        // In good standing otherwise, it is listed SUSPENDED; an @ followed by the source's own framework is an id.
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "id", "dmv two")));
        var r = loadQuietly(source(ctx, props("mapping", boundMapping())));
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status())
                .containsExactly(derived("partner:dmv two") + " SUSPENDED", "partner:college ACTIVE");
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "id", "dmv@partner")));
        r = loadQuietly(source(ctx, props("mapping", boundMapping())));
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status()).containsExactly("partner:dmv@partner ACTIVE", "partner:college ACTIVE");
        assertThat(r.warnings()).isEmpty();
        // A lookup answer too.
        Map<String, Object> p = lookupOnly();
        OnDemandResolver resolver = (OnDemandResolver) source(ctx, p);
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b c", "did", "did:example:b")));
        assertThat(resolver.resolve(Identifier.did("did:example:b"))).hasValueSatisfying(e -> {
            assertThat(e.id()).isEqualTo(derived("b c"));
            assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED);
        });
    }

    @Test
    void item8_frameworkCannotBeMapped() {
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "framework", "other", "state", "revoked")));
        Map<String, Object> m = boundMapping();
        block(m).put("framework", "$.framework");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            // A record naming another framework was skipped, and a skipped revoked record left its party to the anchor.
            assertThat(decide(registry, MDL)).isNotEqualTo(Decision.TRUSTED);
            assertThat(state(manager, "partner").lastError()).isEqualTo("Source 'partner' (mapped): mapping.entities[0]: framework cannot be "
                    + "mapped: every record of a source belongs to the source's framework");
        }
        Map<String, Object> anchored = boundMapping();
        anchored.put("anchors", List.of(Map.of("each", "$.authorities[*]", "domain", "mdoc-iaca", "certificate", "$.certificate",
                "framework", "partner")));
        assertThat(loadError(source(ctx, props("mapping", anchored)))).contains("mapping.anchors[0]: framework cannot be mapped");
        // What a document says about frameworks is not read: the revoked issuer is listed, in the source's framework.
        registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", boundMapping())))) {
            assertThat(registry.snapshot().entity("partner:dmv").orElseThrow().frameworkId()).isEqualTo("partner");
            assertThat(decide(registry, MDL)).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    static io.vctrust.trust.core.spi.SourceLoadResult loadQuietly(io.vctrust.trust.core.spi.TrustSource s) {
        try {
            return s.load();
        } catch (TrustSourceException e) {
            throw new AssertionError(e.getMessage());
        }
    }

    @Test
    void item8_aDateIsAnIsoDateTimeWithItsOffsetOrADateOrAJsonNumberOfSeconds() {
        Map<String, Object> m = boundMapping();
        block(m).put("validFrom", "$.valid_from");
        // A string of digits is not a date: "2099" was a second of 1970, and an issuer valid only from 2099 was trusted.
        Map<Object, String> notDates = new LinkedHashMap<>();
        notDates.put("2099", "validFrom is not a date: '2099'");
        notDates.put("20991231", "validFrom is not a date: '20991231'");
        notDates.put("2099-12-31T00:00:00", "validFrom is not a date: '2099-12-31T00:00:00'");   // no offset: where?
        notDates.forEach((validFrom, warning) -> {
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "valid_from", validFrom)));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                assertThat(decide(registry, MDL)).as(String.valueOf(validFrom)).isEqualTo(Decision.NOT_TRUSTED);
                var e = registry.snapshot().entity("partner:dmv").orElseThrow();
                assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED);
                assertThat(e.validFrom()).isNull();
                assertThat(state(manager, "partner").warnings()).singleElement().asString().endsWith(warning);
            }
        });
        // An offset without a colon is an offset; a JSON number is seconds since the epoch.
        Map<Object, java.time.Instant> dates = new LinkedHashMap<>();
        dates.put("2020-06-01T12:00:00+0100", java.time.Instant.parse("2020-06-01T11:00:00Z"));
        dates.put("2020-06-01T12:00:00.5-0130", java.time.Instant.parse("2020-06-01T13:30:00.5Z"));
        dates.put("2020-06-01T12:00:00+01:00", java.time.Instant.parse("2020-06-01T11:00:00Z"));
        dates.put("2020-06-01", java.time.Instant.parse("2020-06-01T00:00:00Z"));
        dates.put(1_591_012_800L, java.time.Instant.parse("2020-06-01T12:00:00Z"));
        dates.forEach((validFrom, at) -> {
            TestContext ctx = ctx();
            serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "valid_from", validFrom)));
            var r = loadQuietly(source(ctx, props("mapping", m)));
            assertThat(r.warnings()).as(String.valueOf(validFrom)).isEmpty();
            assertThat(r.entities().getFirst().validFrom()).as(String.valueOf(validFrom)).isEqualTo(at);
        });
        // The same for a list fact: the load fails.
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("issued", String.valueOf(NOW.minus(Duration.ofDays(1)).getEpochSecond()));
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props()))).contains("mapping.list.issuedAt: the document has no date there");
    }

    // 9 ---------------------------------------------------------------------------------------------------------

    @Test
    void item9_aPemTextInWhichABlockIsDamagedCannotBeRead() {
        // The issuer's signing certificate damaged, next to another one that reads: listed with the other only, the
        // revoked issuer's key was bound to nobody, and its CA decided.
        String[] lines = MappedTesting.pem("ds").split("\n", -1);
        lines[1] = lines[1].substring(0, 10) + "!" + lines[1].substring(11);
        String damaged = String.join("\n", lines);
        String bundle = damaged + MappedTesting.pem("ds-nl");
        Map<String, Object> revoked = members("roles", List.of("CREDENTIAL_ISSUER"), "state", "revoked", "certificates", List.of(bundle));
        TestContext ctx = ctx();
        serveJson(ctx, withRoles(1, revoked));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", boundMapping())))) {
            assertThat(decide(registry, MDL)).isNotEqualTo(Decision.TRUSTED);
            assertThat(state(manager, "partner").lastError()).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: "
                    + "certificates: a PEM text with 2 BEGIN lines yields 1 certificate");
        }
        // Every block a certificate: read.
        serveJson(ctx, withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER"), "certificates",
                List.of(MappedTesting.pem("ds") + MappedTesting.pem("ds-nl")))));
        assertThat(loadQuietly(source(ctx, props("mapping", boundMapping()))).entities().getFirst().certificates()).hasSize(2);
        // A key in the bundle is no certificate either; for an anchor, the record is skipped.
        Map<String, Object> m = boundMapping();
        m.put("anchors", List.of(Map.of("each", "$.authorities[*]", "id", "$.kid", "domain", "mdoc-iaca", "certificate", "$.certificate")));
        Map<String, Object> d = withRoles(1, members("roles", List.of("CREDENTIAL_ISSUER")));
        d.put("authorities", List.of(Map.of("kid", "shared-iaca", "certificate", MappedTesting.pem("iaca")
                + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), Map.of("kid", "rp-ca", "certificate", der("rp-ca"))));
        serveJson(ctx, d);
        var r = loadQuietly(source(ctx, props("mapping", m)));
        assertThat(r.anchors()).extracting(a -> a.id()).containsExactly("rp-ca");
        assertThat(r.warnings()).singleElement().asString().contains("is skipped: certificate: a PEM text with 2 BEGIN lines yields 1 certificate");
    }

    @Test
    void item9_aSigningCertificateThatIsItselfPinnedSignsWhateverItsKeyUsage() throws Exception {
        io.vctrust.trust.core.testing.TestPki.Issued pinned = MappedSourceAttacksTest.certificate("CN=Partner List Signer,C=UT", null, false,
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment);
        TestContext ctx = ctx();
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(pinned, pinned, MappedSourceRulesTest.doc("a")));
        var r = source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(pinned.certificate()))))).load();
        assertThat(r.entities()).hasSize(1);
        // Under a pinned CA, the same key usage may not sign (MappedSourceAttacksTest.f7_...).
        io.vctrust.trust.core.testing.TestPki.Issued root = MappedSourceAttacksTest.certificate("CN=Partner CA,C=UT", null, true,
                org.bouncycastle.asn1.x509.KeyUsage.keyCertSign | org.bouncycastle.asn1.x509.KeyUsage.cRLSign);
        io.vctrust.trust.core.testing.TestPki.Issued under = MappedSourceAttacksTest.certificate("CN=Partner List Signer,C=UT", root, false,
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment);
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(under, under, MappedSourceRulesTest.doc("a")));
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(root.certificate())))))))
                .contains("its key usage does not include digitalSignature");
        // A pinned CA certificate whose key usage is for certificates only signs the list as well.
        MappedSourceRulesTest.serveJws(ctx, MappedSourceRulesTest.signedWithChain(root, root, MappedSourceRulesTest.doc("a")));
        assertThat(source(ctx, props("format", "jws", "verify", Map.of("certificates",
                List.of(io.vctrust.trust.core.x509.Certificates.toPem(root.certificate()))))).load().entities()).hasSize(1);
    }

    @Test
    void item9_theListsIssuerIsEscapedAndCutAsAMessageIs() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> d = MappedSourceRulesTest.doc("a");
        d.put("publisher", "Partner\r\n2026-11-12 WARN Trust source 'partner' (mapped): all good\u2028" + "P".repeat(8_000));
        serveJson(ctx, d);
        String issuer = source(ctx, props()).load().listInfo().issuer();
        assertThat(issuer).startsWith("Partner\\r\\n2026-11-12 WARN").contains("\\u2028").doesNotContain("\r").doesNotContain("\n")
                .doesNotContain("\u2028").hasSize(2_000).endsWith("…");
    }

    @Test
    void item9_theLookupMemoHoldsAtMost16MebiCharactersOfMappedText() throws Exception {
        // Answers of 56,000 characters each: 300 of them are 16.8 million, which the memo does not hold. The oldest go.
        TestContext ctx = ctx();
        Map<String, Object> attributes = new LinkedHashMap<>();
        for (int i = 1; i <= 7; i++) {
            attributes.put("a" + i, "$.a" + i);
        }
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly("entity", Map.of("id", "$.id", "roles", List.of("CREDENTIAL_ISSUER"),
                "identifiers", List.of(Map.of("type", "DID", "value", "$.did")), "attributes", attributes)));
        int n = 320;
        for (int i = 0; i < n; i++) {
            Map<String, Object> answer = new LinkedHashMap<>(Map.of("id", "p" + i, "did", "did:example:p" + i));
            for (int a = 1; a <= 7; a++) {
                answer.put("a" + a, String.valueOf(a).repeat(8_000));
            }
            ctx.http.json(BASE + "did%3Aexample%3Ap" + i, Json.write(answer));
        }
        for (int i = 0; i < n; i++) {
            assertThat(r.resolve(Identifier.did("did:example:p" + i))).isPresent();
        }
        assertThat(ctx.http.requests).hasSize(n);
        // The last ones are held; the first ones were dropped to make room, and are asked again.
        assertThat(r.resolve(Identifier.did("did:example:p" + (n - 1)))).isPresent();
        assertThat(ctx.http.requests).hasSize(n);
        assertThat(r.resolve(Identifier.did("did:example:p0"))).isPresent();
        assertThat(ctx.http.requests).hasSize(n + 1);
    }
}
