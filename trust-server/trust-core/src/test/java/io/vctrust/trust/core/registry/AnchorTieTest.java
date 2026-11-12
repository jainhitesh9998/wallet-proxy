package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.Reason;
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
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.util.ForeignText;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An anchor's {@code entity} says whose CA it is. The DMV is listed as REVOKED and found only through its IACA's tie
 * (it lists no certificate and no name of one), so the tie is what keeps its Document Signer out. When the tie names an
 * id no source of the anchor's framework lists (written another way, or only another framework's), the evaluator
 * finds no entity for the CA, and the chain to it would decide alone: such an anchor is not loaded, and its source's
 * state says why.
 */
class AnchorTieTest {

    static final TestPki.Issued IACA = TestPki.rootCa("CN=Utopia IACA,C=UT");
    static final TestPki.Issued SIGNER = TestPki.leaf("CN=Utopia Document Signer,C=UT", IACA, List.of(), null);
    static final List<TrustFramework> FRAMEWORKS = List.of(new TrustFramework("example", "Example", null, null, null),
            new TrustFramework("other", "Other", null, null, null));

    /** The DMV as framework {@code framework} lists it: withdrawn, and bound to nothing but a URL. */
    static TrustedEntity dmv(String framework) {
        return TrustedEntity.builder("utopia-dmv").framework(framework).role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://issuer.utopia.example").status(EntityStatus.REVOKED).build();
    }

    static TrustAnchor iaca(String framework, String entity, EntityStatus status) {
        return new TrustAnchor("utopia-iaca", TrustDomain.CREDENTIAL_ISSUER, IACA.certificate(), framework, entity, status, null, null);
    }

    static TrustAnchor iaca(String framework, String entity) {
        return iaca(framework, entity, null);
    }

    static Fixed source(String id, String framework, List<TrustedEntity> entities, List<TrustAnchor> anchors) {
        return new Fixed(id, framework, new SourceLoadResult(entities, anchors, ListInfo.unsigned(), List.of()));
    }

    /** What a client of {@code framework} is told about the Document Signer's certificate. */
    static TrustDecision decide(TrustRegistry registry, TrustSourceManager manager, String framework) {
        TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1));
        return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(null, List.of(Certificates.toBase64(SIGNER.certificate())), null, null),
                new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())),
                new ClientProfile("wallet", "Wallet", Set.of(framework), false, false, false));
    }

    static List<String> warnings(TrustSourceManager manager, String source) {
        return manager.states().stream().filter(s -> s.id().equals(source)).findFirst().orElseThrow().warnings();
    }

    @Test
    void anAnchorTiedToTheEntityAsItIsListedKeepsTheWithdrawnPartyOut() {
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS,
                List.of(source("registry", "example", List.of(dmv("example")), List.of(iaca("example", "utopia-dmv")))), Clock.systemUTC())) {
            manager.start();
            TrustDecision d = decide(registry, manager, "example");
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(d.entity().id()).isEqualTo("utopia-dmv");
            assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
            assertThat(warnings(manager, "registry")).isEmpty();
        }
    }

    @Test
    void anAnchorWhoseEntityNamesNobodyOfItsFrameworkIsNotLoaded() {
        // Another case, a trailing space, an id nobody has: the DMV's withdrawal no longer restricts the CA's certificates.
        for (String entity : List.of("Utopia-DMV", "utopia-dmv ", "ghost")) {
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS,
                    List.of(source("registry", "example", List.of(dmv("example")), List.of(iaca("example", entity)))), Clock.systemUTC())) {
                manager.start();
                // UNKNOWN for want of an anchor: not TRUSTED through a CA whose party the registry does not find.
                TrustDecision d = decide(registry, manager, "example");
                assertThat(d.decision()).as(entity + ": " + d.summary()).isEqualTo(Decision.UNKNOWN);
                assertThat(d.reasons()).as(entity).extracting(Reason::code).contains("x509.no_anchor");
                assertThat(registry.snapshot().allAnchors()).as(entity).isEmpty();
                assertThat(warnings(manager, "registry")).as(entity).containsExactly("Anchor 'utopia-iaca' is not loaded: it belongs to entity '"
                        + entity + "', which no source of framework 'example' lists");
            }
        }
    }

    @Test
    void anAnchorWithoutEntityIsLoadedAsBefore() {
        // A CA shared by many parties: a valid chain to it says the certificate is valid, not whose it is.
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS,
                List.of(source("registry", "example", List.of(dmv("example")), List.of(iaca("example", null)))), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().anchor("utopia-iaca")).get().satisfies(a -> assertThat(a.entityId()).isNull());
            assertThat(decide(registry, manager, "example").decision()).isEqualTo(Decision.TRUSTED);
            assertThat(warnings(manager, "registry")).isEmpty();
        }
    }

    @Test
    void theEntityMayBeListedByAnotherSourceOfTheFrameworkInEitherOrder() {
        Fixed anchors = source("anchors", "example", List.of(), List.of(iaca("example", "utopia-dmv")));
        Fixed entities = source("entities", "example", List.of(dmv("example")), List.of());
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(anchors, entities), List.of(entities, anchors))) {
            String which = order.getFirst().id() + " first";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, order, Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().anchor("utopia-iaca")).as(which).get().satisfies(a -> assertThat(a.entityId()).isEqualTo("utopia-dmv"));
                TrustDecision d = decide(registry, manager, "example");
                assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.reasons()).as(which).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
                assertThat(warnings(manager, "anchors")).as(which).isEmpty();
                assertThat(warnings(manager, "entities")).as(which).isEmpty();
            }
        }
    }

    @Test
    void anAnchorWhoseEntityOnlyAnotherFrameworkHasIsNotLoaded() {
        // Framework "other" lists the DMV; framework "example" lists the IACA and names the DMV, which it does not list.
        Fixed other = source("other-list", "other", List.of(dmv("other")), List.of());
        Fixed example = source("registry", "example", List.of(), List.of(iaca("example", "utopia-dmv")));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(other, example), List.of(example, other))) {
            String which = order.getFirst().id() + " first";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, order, Clock.systemUTC())) {
                manager.start();
                TrustDecision d = decide(registry, manager, "example");
                assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.UNKNOWN);
                assertThat(d.reasons()).as(which).extracting(Reason::code).contains("x509.no_anchor");
                assertThat(registry.snapshot().allAnchors()).as(which).isEmpty();
                assertThat(warnings(manager, "registry")).as(which).containsExactly("Anchor 'utopia-iaca' is not loaded: it belongs to entity"
                        + " 'utopia-dmv', which no source of framework 'example' lists; only framework 'other' has an entity of that id");
                assertThat(warnings(manager, "other-list")).as(which).isEmpty();
            }
        }
    }

    @Test
    void anAnchorFollowsItsEntityToTheNameItIsListedUnder() {
        // Framework "other" has an active "utopia-dmv" too. Listed first, it keeps the id, and example's DMV is listed as
        // "utopia-dmv@example": the IACA's tie follows it there. Listed after, example's DMV keeps the id.
        Fixed other = source("other-list", "other", List.of(TrustSourceManagerTest.issuer("utopia-dmv", "other", "https://other.example").build()),
                List.of());
        Fixed example = source("registry", "example", List.of(dmv("example")), List.of(iaca("example", "utopia-dmv")));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(other, example), List.of(example, other))) {
            boolean otherFirst = order.getFirst() == other;
            String which = order.getFirst().id() + " first";
            String listedAs = otherFirst ? "utopia-dmv@example" : "utopia-dmv";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, order, Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().anchor("utopia-iaca")).as(which).get().satisfies(a -> assertThat(a.entityId()).isEqualTo(listedAs));
                TrustDecision d = decide(registry, manager, "example");
                assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.entity().id()).as(which).isEqualTo(listedAs);
                assertThat(d.reasons()).as(which).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
                assertThat(warnings(manager, "registry")).as(which).noneMatch(w -> w.startsWith("Anchor"));
            }
        }
    }

    @Test
    void recordsOfOneAnchorThatDifferInTheirTieLoadNeither() {
        // The record that names nobody is not loaded, and its withdrawal of the CA must not let the other one load in its
        // place: two records that differ are not loaded, whichever comes first.
        Fixed entities = source("entities", "example", List.of(dmv("example")), List.of());
        Fixed tied = source("tied", "example", List.of(), List.of(iaca("example", "utopia-dmv")));
        Fixed withdrawn = source("withdrawn", "example", List.of(), List.of(iaca("example", "Utopia-DMV", EntityStatus.REVOKED)));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(entities, tied, withdrawn), List.of(entities, withdrawn, tied))) {
            String which = order.get(1).id() + " first";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, order, Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().allAnchors()).as(which).isEmpty();
                assertThat(decide(registry, manager, "example").decision()).as(which).isEqualTo(Decision.UNKNOWN);
                assertThat(warnings(manager, "tied")).as(which).singleElement()
                        .satisfies(w -> assertThat(w).startsWith("Anchor 'utopia-iaca' is not loaded: sources ").contains("(entity, status)"));
                assertThat(warnings(manager, "withdrawn")).as(which).contains("Anchor 'utopia-iaca' is not loaded: it belongs to entity 'Utopia-DMV',"
                        + " which no source of framework 'example' lists").anyMatch(w -> w.contains("(entity, status)"));
            }
        }
    }

    @Test
    void aRecordThatNamesNobodyDiffersFromOneTiedToTheNameItsEntityIsListedUnder() {
        // With "other" first, example's DMV is listed as "utopia-dmv@example". A record whose entity is written so names an
        // id no source of example lists; another, written "utopia-dmv", is tied to that name. Alike as they look, which
        // one counted would depend on the order of the sources: neither is loaded.
        Fixed other = source("other-list", "other", List.of(dmv("other")), List.of());
        Fixed entities = source("entities", "example", List.of(dmv("example")), List.of());
        Fixed tied = source("tied", "example", List.of(), List.of(iaca("example", "utopia-dmv")));
        Fixed written = source("written", "example", List.of(), List.of(iaca("example", "utopia-dmv@example")));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(other, entities, tied, written), List.of(other, entities, written, tied))) {
            String which = order.get(2).id() + " first";
            var registry = new TrustRegistry();
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, order, Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().allAnchors()).as(which).isEmpty();
                assertThat(warnings(manager, "tied")).as(which).singleElement().satisfies(w -> assertThat(w).contains("(entity)"));
                assertThat(warnings(manager, "written")).as(which).contains("Anchor 'utopia-iaca' is not loaded: it belongs to entity"
                        + " 'utopia-dmv@example', which no source of framework 'example' lists");
            }
        }
    }

    @Test
    void theWarningIsEscapedCutAndBoundedAsTheRegistrysOthers() {
        // The id is the list's text: a line break and a right-to-left override are escaped, and a long one is cut.
        String entity = "ghost\n‮" + "x".repeat(600);
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS,
                List.of(source("registry", "example", List.of(), List.of(iaca("example", entity)))), Clock.systemUTC())) {
            manager.start();
            assertThat(warnings(manager, "registry")).singleElement().satisfies(w -> {
                assertThat(w).startsWith("Anchor 'utopia-iaca' is not loaded: it belongs to entity 'ghost\\u000A\\u202Exxx").endsWith(ForeignText.CUT)
                        .doesNotContain("\n", "‮");
                assertThat(w.length()).isLessThanOrEqualTo(ForeignText.MAX_LENGTH + ForeignText.CUT.length());
            });
        }
        // A list decides how many such anchors it has: at most 50 warnings, then a line that counts the rest.
        List<TrustAnchor> many = IntStream.range(0, 60).mapToObj(i -> new TrustAnchor(String.format("ca-%02d", i), TrustDomain.CREDENTIAL_ISSUER,
                TestPki.rootCa("CN=CA " + i + ",C=UT").certificate(), "example", "ghost-" + i, null, null, null)).toList();
        registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(source("registry", "example", List.of(), many)), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().allAnchors()).isEmpty();
            List<String> warnings = warnings(manager, "registry");
            assertThat(warnings).hasSize(TrustSourceManager.MAX_REPORTED + 1);
            assertThat(warnings.get(49)).isEqualTo("Anchor 'ca-49' is not loaded: it belongs to entity 'ghost-49', which no source of framework 'example' lists");
            assertThat(warnings.getLast()).isEqualTo("10 more warnings of the registry about this source are not shown");
        }
    }
}
