package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustSourceManagerTest.Fixed;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An entry whose id another framework already has is listed as {@code <id>@<its framework>}. That name belongs to the
 * framework it names: an entry of another framework cannot take it, so the entry it is the fallback for is always
 * placed. And no entry is left out without a warning in its source's state.
 *
 * <p>The scenarios: framework {@code other} lists, under a shared CA, the issuer {@code victim} as REVOKED. Framework
 * {@code partner} lists {@code victim} and {@code victim@other} (or anchors {@code iaca} and {@code iaca@other}).
 */
class FallbackNamesTest {

    static final TestPki.Issued SHARED_CA = TestPki.rootCa("CN=Shared Issuer CA,C=UT");
    static final TestPki.Issued VICTIM = TestPki.leaf("CN=Victim Issuer,C=UT", SHARED_CA, List.of(), null);
    static final TestPki.Issued PARTNER_CA = TestPki.rootCa("CN=Partner CA,C=UT");

    static final ClientProfile OTHER = new ClientProfile("other-wallet", "Other", Set.of("other"), false, false, false);
    static final List<TrustFramework> FRAMEWORKS = List.of(new TrustFramework("other", "Other", null, null, null),
            new TrustFramework("partner", "Partner", null, null, null));

    static TrustedEntity issuer(String id, String framework, String url) {
        return TrustSourceManagerTest.issuer(id, framework, url).build();
    }

    /** The victim, as framework "other" lists it: withdrawn, and bound to its certificate by the certificate's subject. */
    static TrustedEntity victim() {
        return TrustedEntity.builder("victim").framework("other").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(VICTIM.certificate()))
                .status(EntityStatus.REVOKED).build();
    }

    static TrustAnchor anchor(String id, TestPki.Issued ca, String framework) {
        return new TrustAnchor(id, TrustDomain.CREDENTIAL_ISSUER, ca.certificate(), framework, null, null, null, null);
    }

    static SourceLoadResult listing(List<TrustedEntity> entities, List<TrustAnchor> anchors) {
        return new SourceLoadResult(entities, anchors, ListInfo.unsigned(), List.of());
    }

    /** "official" (framework other): the victim and the shared CA. */
    static Fixed official() {
        return new Fixed("official", "other", listing(List.of(victim()), List.of(anchor("iaca", SHARED_CA, "other"))));
    }

    /** The decision a client of "other" gets for the victim's certificate. */
    static TrustDecision decide(TrustRegistry registry, TrustSourceManager manager) {
        TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1));
        return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(null, List.of(Certificates.toBase64(VICTIM.certificate())), null, null),
                new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())), OTHER);
    }

    static List<String> warnings(TrustSourceManager manager, String source) {
        return manager.states().stream().filter(s -> s.id().equals(source)).findFirst().orElseThrow().warnings();
    }

    @Test
    void theOfficialListAloneRefusesTheVictim() {
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(official()), Clock.systemUTC())) {
            manager.start();
            assertThat(decide(registry, manager).decision()).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void anEntityOfAnotherFrameworkCannotTakeTheNameTheVictimFallsBackTo() {
        Fixed partner = new Fixed("partner", "partner", listing(List.of(issuer("victim", "partner", "https://partner.example/a"),
                issuer("victim@other", "partner", "https://partner.example/b")), List.of()));
        for (boolean partnerFirst : List.of(true, false)) {
            var registry = new TrustRegistry();
            List<io.vctrust.trust.core.spi.TrustSource> sources = partnerFirst ? List.of(partner, official()) : List.of(official(), partner);
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, sources, Clock.systemUTC())) {
                manager.start();
                String order = partnerFirst ? "partner first" : "official first";
                // The client of "other" is refused the victim, which is in the registry, in its framework.
                TrustDecision d = decide(registry, manager);
                assertThat(d.decision()).as(order + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.reasons()).as(order).extracting(r -> r.code()).contains("entity.status");
                assertThat(registry.snapshot().entities()).as(order).filteredOn(e -> "other".equals(e.frameworkId()))
                        .singleElement().satisfies(e -> assertThat(e.status()).isEqualTo(EntityStatus.REVOKED));
                // The partner's "victim@other" does not get that name: it is listed under its own framework's,
                // "victim@other@partner", and its source says so.
                assertThat(registry.snapshot().entities()).as(order).noneMatch(e -> "partner".equals(e.frameworkId()) && e.id().equals("victim@other"));
                assertThat(registry.snapshot().entity("victim@other@partner")).as(order).get().satisfies(e -> {
                    assertThat(e.frameworkId()).isEqualTo("partner");
                    assertThat(e.identifiers()).extracting(i -> i.value()).containsExactly("https://partner.example/b");
                });
                assertThat(warnings(manager, "partner")).as(order).anyMatch(w -> w.startsWith("Entity 'victim@other' is listed as 'victim@other@partner'"));
                assertThat(warnings(manager, "official")).as(order).noneMatch(w -> w.contains("not loaded"));
            }
        }
    }

    @Test
    void anAnchorOfAnotherFrameworkCannotTakeTheNameTheVictimsAnchorFallsBackTo() {
        Fixed partner = new Fixed("partner", "partner", listing(List.of(),
                List.of(anchor("iaca", PARTNER_CA, "partner"), anchor("iaca@other", PARTNER_CA, "partner"))));
        for (boolean partnerFirst : List.of(true, false)) {
            var registry = new TrustRegistry();
            List<io.vctrust.trust.core.spi.TrustSource> sources = partnerFirst ? List.of(partner, official()) : List.of(official(), partner);
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, sources, Clock.systemUTC())) {
                manager.start();
                String order = partnerFirst ? "partner first" : "official first";
                // The client of "other" is refused the victim: the shared CA is an anchor of "other".
                TrustDecision d = decide(registry, manager);
                assertThat(d.decision()).as(order + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.reasons()).as(order).extracting(r -> r.code()).contains("x509.valid", "entity.status");
                assertThat(registry.snapshot().allAnchors()).as(order).filteredOn(a -> "other".equals(a.frameworkId()))
                        .singleElement().satisfies(a -> assertThat(a.thumbprint()).isEqualTo(Certificates.sha256Thumbprint(SHARED_CA.certificate())));
                // The partner's "iaca@other" is not loaded, and its source says so.
                assertThat(registry.snapshot().allAnchors()).as(order).filteredOn(a -> "partner".equals(a.frameworkId())).hasSize(1);
                assertThat(warnings(manager, "partner")).as(order).anyMatch(w -> w.contains("'iaca@other'") && w.contains("not loaded"));
                assertThat(warnings(manager, "official")).as(order).isEmpty();
            }
        }
    }

    static final TestPki.Issued NATIONAL_CA = TestPki.rootCa("CN=National Issuer CA,C=UT");
    static final TestPki.Issued ACME = TestPki.leaf("CN=Acme Issuer,C=UT", NATIONAL_CA, List.of(), null);
    static final ClientProfile NATIONAL = new ClientProfile("national-wallet", "National", Set.of("national"), false, false, false);
    static final List<TrustFramework> WITH_NATIONAL = List.of(new TrustFramework("other", "Other", null, null, null),
            new TrustFramework("national", "National", null, null, null));

    /** "acme@other" as framework "national" lists it: withdrawn, and bound to its certificate under national's CA. */
    static TrustedEntity acme(String id) {
        return TrustedEntity.builder(id).framework("national").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(ACME.certificate()))
                .status(EntityStatus.REVOKED).build();
    }

    static TrustDecision decideAcme(TrustRegistry registry, TrustSourceManager manager) {
        TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1));
        return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(null, List.of(Certificates.toBase64(ACME.certificate())), null, null),
                new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())), NATIONAL);
    }

    /**
     * An entity of framework "national" written with an id that is framework "other"'s name ({@code acme@other}) is
     * listed under the name it would fall back to, {@code acme@other@national}, with all it says. Left out, the revoked
     * entry would no longer restrict its party, and its certificate would be trusted through national's CA.
     */
    @Test
    void anEntityWrittenWithAnotherFrameworksNameIsListedUnderItsOwn() {
        Fixed national = new Fixed("national-list", "national", listing(List.of(acme("acme@other")),
                List.of(anchor("national-ca", NATIONAL_CA, "national"))));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, WITH_NATIONAL, List.of(national), Clock.systemUTC())) {
            manager.start();
            TrustDecision d = decideAcme(registry, manager);
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(d.reasons()).extracting(r -> r.code()).contains("x509.valid", "entity.status");
            assertThat(d.entity().id()).isEqualTo("acme@other@national");
            assertThat(registry.snapshot().entity("acme@other")).isEmpty();
            assertThat(registry.snapshot().entity("acme@other@national")).get().satisfies(e -> {
                assertThat(e.frameworkId()).isEqualTo("national");
                assertThat(e.status()).isEqualTo(EntityStatus.REVOKED);
                assertThat(e.identifiers()).isEqualTo(acme("acme@other").identifiers());
            });
            assertThat(warnings(manager, "national-list")).containsExactly("Entity 'acme@other' is listed as 'acme@other@national': 'acme@other'"
                    + " is the name an entry of framework 'other' is listed under when another framework has its id");
        }
    }

    @Test
    void anEntityWrittenWithAnotherFrameworksNameWhoseOwnNameIsTakenTooIsMergedWithTheEntryThere() {
        // National's own "acme@other@national" comes first and holds the name. The revoked "acme@other" used to be left
        // out; it is merged into that entry now, as it is when it comes first.
        Fixed national = new Fixed("national-list", "national", listing(List.of(issuer("acme@other@national", "national", "https://acme.example"),
                acme("acme@other")), List.of()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, WITH_NATIONAL, List.of(national), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entities()).singleElement()
                    .satisfies(e -> assertThat(e.status()).isEqualTo(EntityStatus.REVOKED));
            assertThat(warnings(manager, "national-list")).containsExactly("Entity 'acme@other' is listed as 'acme@other@national' together with"
                    + " the entry already there: 'acme@other' is the name an entry of framework 'other' is listed under when another framework has its id");
        }
    }

    /**
     * National's active {@code acme@other@national} and its revoked {@code acme@other} (which pins a certificate and falls
     * back to that name), from two sources: listed in one order they merge, and in the other the revoked one used to be
     * left out, so that its certificate was trusted through national's CA. Only an entry of national can hold that name,
     * so the two are merged in either order.
     */
    @Test
    void anEntityWhoseFallbackNameIsHeldIsMergedWithTheEntryThereInEitherOrder() {
        Fixed own = new Fixed("own", "national", listing(List.of(issuer("acme@other@national", "national", "https://acme.example")),
                List.of(anchor("national-ca", NATIONAL_CA, "national"))));
        Fixed withdrawn = new Fixed("withdrawn", "national", listing(List.of(acme("acme@other").toBuilder().certificate(ACME.certificate()).build()),
                List.of()));
        for (List<io.vctrust.trust.core.spi.TrustSource> order : List.<List<io.vctrust.trust.core.spi.TrustSource>>of(
                List.of(own, withdrawn), List.of(withdrawn, own))) {
            String which = order.getFirst().id() + " first";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, WITH_NATIONAL, order, Clock.systemUTC())) {
                manager.start();
                TrustDecision d = decideAcme(registry, manager);
                assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.reasons()).as(which).extracting(r -> r.code()).contains("entity.status");
                assertThat(registry.snapshot().entities()).as(which).singleElement().satisfies(e -> {
                    assertThat(e.id()).isEqualTo("acme@other@national");
                    assertThat(e.status()).isEqualTo(EntityStatus.REVOKED);
                    assertThat(e.certificates()).containsExactly(ACME.certificate());
                });
            }
        }
    }

    @Test
    void anEntryOfItsOwnFrameworkMayCarryItsFrameworksName() {
        // "x@partner" written by the partner is its own: nobody else's fallback name.
        Fixed partner = new Fixed("partner", "partner", listing(List.of(issuer("x@partner", "partner", "https://partner.example/x")),
                List.of(anchor("ca@partner", PARTNER_CA, "partner"))));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(partner), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entity("x@partner")).isPresent();
            assertThat(registry.snapshot().anchor("ca@partner")).isPresent();
            assertThat(warnings(manager, "partner")).isEmpty();
            // A name ending in something that is not a framework is an ordinary id.
            assertThat(manager.fallbackNameOf("victim@nowhere", "partner")).isEmpty();
            assertThat(manager.fallbackNameOf("victim@other", "partner")).contains("other");
            assertThat(manager.fallbackNameOf("victim@other", "other")).isEmpty();
        }
    }

    @Test
    void anEntryThatStillCannotBePlacedIsReported() {
        // "other" holds "a" first; the partner's own "a@partner" then holds the name its "a" would fall back to.
        Fixed first = new Fixed("official", "other", listing(List.of(issuer("a", "other", "https://other.example/a")),
                List.of(anchor("ca", SHARED_CA, "other"))));
        Fixed partner = new Fixed("partner", "partner", listing(
                List.of(issuer("a@partner", "partner", "https://partner.example/own"), issuer("a", "partner", "https://partner.example/a")),
                List.of(anchor("ca@partner", PARTNER_CA, "partner"), anchor("ca", SHARED_CA, "partner"))));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(first, partner), Clock.systemUTC())) {
            manager.start();
            // The partner's "a" falls back to "a@partner", which its own entry holds: the two are merged (it used to be
            // left out). The partner's "ca" falls back to "ca@partner", which its own anchor of another certificate holds:
            // two records of one anchor id in one framework that differ, and neither is loaded (the first one listed was kept).
            assertThat(warnings(manager, "partner")).anyMatch(w -> w.equals("Entity 'a' is listed as 'a@partner' together with the entry already"
                            + " there: framework 'other' already has an entity with that id"))
                    .anyMatch(w -> w.startsWith("Anchor 'ca@partner' is not loaded: source 'partner' lists it twice in framework 'partner'"
                            + " (written as 'ca@partner' and 'ca') with records that differ (certificate)"));
            assertThat(registry.snapshot().entity("a@partner")).get().satisfies(e -> assertThat(e.identifiers()).extracting(i -> i.value())
                    .containsExactly("https://partner.example/own", "https://partner.example/a"));
            assertThat(registry.snapshot().anchor("ca@partner")).isEmpty();
            assertThat(registry.snapshot().anchor("ca")).get().satisfies(a -> assertThat(a.frameworkId()).isEqualTo("other"));
        }
    }

    /**
     * A framework id is plain: letters, digits, '.', '_' and '-'. With an '@' in it, the fallback name of one
     * framework's entry ({@code x@a@b} for framework {@code a@b}) could be a literal name of another's ({@code x@a}
     * with the suffix {@code @b}), and the rule that a fallback name is its framework's would no longer say whose it is.
     */
    @Test
    void aFrameworkIdThatIsNotPlainIsRefused() {
        for (String id : List.of("a@b", "a b", "", "national/id", "café", "a:b")) {
            List<TrustFramework> configured = List.of(new TrustFramework("other", "Other", null, null, null), new TrustFramework(id, "x", null, null, null));
            assertThatThrownBy(() -> new TrustSourceManager(new TrustRegistry(), configured, List.of(), Clock.systemUTC()).close()).as(id)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Framework '" + id + "' (trust.frameworks): a framework id is letters, digits, '.', '_' and '-' only");
            // Also the framework a source loads into without its being configured.
            Fixed source = new Fixed("odd", id, listing(List.of(), List.of()));
            assertThatThrownBy(() -> new TrustSourceManager(new TrustRegistry(), FRAMEWORKS, List.of(source), Clock.systemUTC()).close()).as(id)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Framework '" + id + "' (of source 'odd'): a framework id is letters, digits, '.', '_' and '-' only");
        }
        List<TrustFramework> plain = List.of(new TrustFramework("eu-pid_2.0", "EU PID", null, null, null));
        new TrustSourceManager(new TrustRegistry(), plain, List.of(new Fixed("s", "eu-pid_2.0", listing(List.of(), List.of()))), Clock.systemUTC()).close();
    }

    @Test
    void anAnchorListedTwiceInOneFrameworkIsReportedOnlyWhenTheTwoDiffer() {
        Fixed one = new Fixed("one", "other", listing(List.of(), List.of(anchor("ca", SHARED_CA, "other"))));
        Fixed same = new Fixed("same", "other", listing(List.of(), List.of(anchor("ca", SHARED_CA, "other"))));
        Fixed different = new Fixed("different", "other", listing(List.of(), List.of(anchor("ca", PARTNER_CA, "other"))));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(one, same), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().allAnchors()).singleElement()
                    .satisfies(a -> assertThat(a.thumbprint()).isEqualTo(Certificates.sha256Thumbprint(SHARED_CA.certificate())));
            assertThat(warnings(manager, "one")).isEmpty();
            assertThat(warnings(manager, "same")).isEmpty();
        }
        // A record that differs: the first one listed used to be kept. Now neither is loaded, whatever the order, and every
        // source concerned is told.
        registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(one, same, different), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().allAnchors()).isEmpty();
            for (String source : List.of("one", "same", "different")) {
                assertThat(warnings(manager, source)).as(source).anyMatch(w -> w.startsWith("Anchor 'ca' is not loaded: sources 'one', 'same' and 'different'"));
            }
        }
    }
}
