package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class TrustSourceManagerTest {

    /** A source whose content and availability the test controls. */
    static final class Source implements TrustSource {
        final SourceDefinition def;
        final AtomicBoolean failing = new AtomicBoolean();
        volatile String issuerUrl = "https://issuer.example";

        Source(String id, boolean required) {
            def = new SourceDefinition(id, "test", "fw", null, true, required, Map.of());
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
            if (failing.get()) {
                throw new TrustSourceException("upstream down");
            }
            // The retrieval time differs on every load, as it does for real sources.
            var entity = TrustedEntity.builder(def.id() + "-issuer").framework("fw").role(EntityRole.CREDENTIAL_ISSUER)
                    .identifier(IdentifierType.URL, issuerUrl).provenance(Provenance.of(def.id(), "test", "fw", null, Instant.now())).build();
            return new SourceLoadResult(List.of(entity), List.of(), ListInfo.unsigned(), List.of());
        }
    }

    @Test
    void isNotReadyUntilEveryRequiredSourceHasLoadedOnce() {
        var required = new Source("list", true);
        var optional = new Source("sandbox", false);
        required.failing.set(true);
        optional.failing.set(true);
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(required, optional), Clock.systemUTC())) {
            manager.start();
            // A registry without the required list would look like its parties having been delisted.
            assertThat(manager.ready()).isFalse();
            assertThat(manager.waitingFor()).containsExactly("list");
            required.failing.set(false);
            manager.refresh("list");
            assertThat(manager.ready()).isTrue();
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("list-issuer");
            // Once loaded, a failure keeps the last good result: still ready, still listed.
            required.failing.set(true);
            manager.refresh("list");
            assertThat(manager.ready()).isTrue();
            assertThat(registry.snapshot().entities()).hasSize(1);
        }
    }

    @Test
    void publishesANewVersionOnlyWhenTheContentChanged() {
        var source = new Source("list", true);
        var registry = new TrustRegistry();
        AtomicInteger published = new AtomicInteger();
        registry.onChange(s -> published.incrementAndGet());
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(source), Clock.systemUTC())) {
            manager.start();
            long version = registry.snapshot().version();
            int count = published.get();
            manager.refresh("list");
            manager.refresh("list");
            assertThat(registry.snapshot().version()).isEqualTo(version);
            assertThat(published).hasValue(count);
            source.issuerUrl = "https://issuer.example/v2";
            manager.refresh("list");
            assertThat(registry.snapshot().version()).isEqualTo(version + 1);
        }
    }

    /** A source that serves what the test hands it. */
    static final class Fixed implements TrustSource {
        final SourceDefinition def;
        volatile SourceLoadResult result;

        Fixed(String id, String framework, SourceLoadResult result) {
            def = new SourceDefinition(id, "test", framework, null, true, true, Map.of());
            this.result = result;
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        @Override
        public SourceLoadResult load() {
            return result;
        }
    }

    static TrustedEntity.Builder issuer(String id, String framework, String url) {
        return TrustedEntity.builder(id).framework(framework).role(EntityRole.CREDENTIAL_ISSUER).identifier(IdentifierType.URL, url);
    }

    static SourceLoadResult listing(TrustedEntity... entities) {
        return new SourceLoadResult(List.of(entities), List.of(), ListInfo.unsigned(), List.of());
    }

    @Test
    void aSourceAddsNothingToAnEntityOfAnotherFramework() {
        // The sandbox list reuses the id of the government's issuer and adds a key of its own to it.
        var gov = new Fixed("gov-list", "gov", listing(issuer("issuer", "gov", "https://issuer.gov.example").build()));
        var sandbox = new Fixed("sandbox-list", "sandbox", listing(issuer("issuer", "sandbox", "https://elsewhere.example")
                .identifier(IdentifierType.JWK_THUMBPRINT, "attacker-key").build()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(gov, sandbox), Clock.systemUTC())) {
            manager.start();
            var snap = registry.snapshot();
            assertThat(snap.entity("issuer")).get().satisfies(e -> {
                assertThat(e.frameworkId()).isEqualTo("gov");
                assertThat(e.identifiers()).extracting(i -> i.type()).containsExactly(IdentifierType.URL);
            });
            // The sandbox's entity is a different party: listed under an id of its own, in its own framework.
            assertThat(snap.entity("issuer@sandbox")).get().satisfies(e -> assertThat(e.frameworkId()).isEqualTo("sandbox"));
            assertThat(snap.byIdentifier(io.vctrust.trust.core.model.Identifier.of(IdentifierType.JWK_THUMBPRINT, "attacker-key")))
                    .extracting(TrustedEntity::frameworkId).containsExactly("sandbox");
            assertThat(manager.states()).filteredOn(st -> st.id().equals("sandbox-list")).singleElement()
                    .satisfies(st -> assertThat(st.warnings()).anyMatch(w -> w.contains("issuer@sandbox")));
            assertThat(manager.states()).filteredOn(st -> st.id().equals("gov-list")).singleElement()
                    .satisfies(st -> assertThat(st.warnings()).isEmpty());
        }
    }

    @Test
    void theOrderOfSourcesDoesNotLetOneFrameworkTakeAnEntityOfAnother() {
        // The same, with the sandbox list configured first: the government's issuer keeps its own identifiers only.
        var sandbox = new Fixed("sandbox-list", "sandbox", listing(issuer("issuer", "sandbox", "https://elsewhere.example")
                .identifier(IdentifierType.JWK_THUMBPRINT, "attacker-key").build()));
        var gov = new Fixed("gov-list", "gov", listing(issuer("issuer", "gov", "https://issuer.gov.example").build()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(sandbox, gov), Clock.systemUTC())) {
            manager.start();
            var listed = registry.snapshot().byIdentifier(io.vctrust.trust.core.model.Identifier.url("https://issuer.gov.example"));
            assertThat(listed).singleElement().satisfies(e -> {
                assertThat(e.frameworkId()).isEqualTo("gov");
                assertThat(e.id()).isEqualTo("issuer@gov");
                assertThat(e.identifiers()).hasSize(1);
            });
        }
    }

    @Test
    void whatASourceLoadsIsPlacedInItsOwnFramework() {
        // An adapter (or a list it parsed) that labels an entity with another framework does not move it there.
        var sandbox = new Fixed("sandbox-list", "sandbox", listing(issuer("evil", "gov", "https://evil.example").build()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(sandbox), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entity("evil")).get().satisfies(e -> assertThat(e.frameworkId()).isEqualTo("sandbox"));
        }
    }

    @Test
    void sourcesOfOneFrameworkStillDescribeTheSameEntityTogether() {
        var list = new Fixed("list", "gov", listing(issuer("issuer", "gov", "https://issuer.gov.example").build()));
        var more = new Fixed("more", "gov", listing(issuer("issuer", "gov", "https://issuer.gov.example")
                .identifier(IdentifierType.DID, "did:web:issuer.gov.example").build()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(list, more), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entities()).singleElement()
                    .satisfies(e -> assertThat(e.identifiers()).extracting(i -> i.type()).containsExactly(IdentifierType.URL, IdentifierType.DID));
        }
    }

    @Test
    void anAnchorIsTiedOnlyToAnEntityOfItsOwnFramework() {
        var ca = io.vctrust.trust.core.testing.TestPki.rootCa("CN=Sandbox CA,C=UT");
        var gov = new Fixed("gov-list", "gov", listing(issuer("issuer", "gov", "https://issuer.gov.example").build()));
        // The sandbox's CA claims to belong to the government's issuer.
        var anchor = new io.vctrust.trust.core.model.TrustAnchor("sandbox-ca", io.vctrust.trust.core.model.TrustDomain.CREDENTIAL_ISSUER,
                ca.certificate(), "gov", "issuer", null, null, null);
        var sandbox = new Fixed("sandbox-list", "sandbox", new SourceLoadResult(List.of(), List.of(anchor), ListInfo.unsigned(), List.of()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(gov, sandbox), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().anchor("sandbox-ca")).get().satisfies(a -> {
                assertThat(a.frameworkId()).isEqualTo("sandbox");
                assertThat(a.entityId()).isNull();
            });
            assertThat(manager.states()).filteredOn(st -> st.id().equals("sandbox-list")).singleElement()
                    .satisfies(st -> assertThat(st.warnings()).anyMatch(w -> w.contains("another framework")));
        }
    }

    @Test
    void aCertificateAuthorityListedByTwoFrameworksIsAnAnchorInBoth() {
        var ca = io.vctrust.trust.core.testing.TestPki.rootCa("CN=Shared IACA,C=UT");
        java.util.function.Function<String, SourceLoadResult> listing = framework -> new SourceLoadResult(List.of(),
                List.of(new io.vctrust.trust.core.model.TrustAnchor(null, io.vctrust.trust.core.model.TrustDomain.MDOC_IACA, ca.certificate(),
                        framework, null, null, null, null)), ListInfo.unsigned(), List.of());
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(),
                List.of(new Fixed("one", "one", listing.apply("one")), new Fixed("two", "two", listing.apply("two"))), Clock.systemUTC())) {
            manager.start();
            // Each framework's clients are given the anchors of their own framework: neither may hide the other's.
            assertThat(registry.snapshot().anchors(io.vctrust.trust.core.model.TrustDomain.MDOC_IACA))
                    .extracting(io.vctrust.trust.core.model.TrustAnchor::frameworkId).containsExactly("one", "two");
        }
    }

    @Test
    void anAnchorCountsWithAtMostEightCrlLocations() {
        var many = io.vctrust.trust.core.testing.TestPki.rootCa("CN=Many CRL Locations,C=UT");
        var eight = io.vctrust.trust.core.testing.TestPki.rootCa("CN=Eight CRL Locations,C=UT");
        List<String> locations = java.util.stream.IntStream.range(0, 20).mapToObj(i -> "https://crl" + i + ".example/ca.crl").toList();
        List<String> named = new java.util.ArrayList<>(List.of("ldap://crl.example/cn=ca"));
        named.addAll(locations);
        Map<String, Object> eightNamed = Map.of("crlUrls", locations.subList(0, 8));
        var anchors = List.of(
                new io.vctrust.trust.core.model.TrustAnchor("many", io.vctrust.trust.core.model.TrustDomain.MDOC_IACA, many.certificate(), "fw", null, null,
                        Map.of("crlUrls", named, "docTypes", List.of("org.iso.18013.5.1.mDL")), null),
                new io.vctrust.trust.core.model.TrustAnchor("eight", io.vctrust.trust.core.model.TrustDomain.MDOC_IACA, eight.certificate(), "fw", null, null,
                        eightNamed, null));
        var source = new Fixed("list", "fw", new SourceLoadResult(List.of(), anchors, ListInfo.unsigned(), List.of()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(source), Clock.systemUTC())) {
            manager.start();
            // The registry, and so the snapshot and every device, sees the first eight http(s) locations; the rest of the
            // record as it was written.
            assertThat(registry.snapshot().anchor("many")).get().satisfies(a -> {
                assertThat(a.constraints().get("crlUrls")).isEqualTo(locations.subList(0, 8));
                assertThat(a.constraints().get("docTypes")).isEqualTo(List.of("org.iso.18013.5.1.mDL"));
            });
            assertThat(registry.snapshot().anchor("eight")).get().satisfies(a -> assertThat(a.constraints()).isEqualTo(eightNamed));
            assertThat(manager.states()).singleElement().satisfies(st -> assertThat(st.warnings()).singleElement()
                    .isEqualTo("Anchor 'many' names 20 CRL locations (crlUrls); an anchor counts with at most 8, and the other 12 are not used,"
                            + " from https://crl8.example/ca.crl on"));
        }
    }

    @Test
    void whatTheRegistryReportsOfOneSourceIsBounded() {
        // A list decides how many of its anchors name too many CRL locations: what the state and the log carry is bounded.
        List<String> locations = java.util.stream.IntStream.range(0, 9).mapToObj(i -> "https://crl" + i + ".example/ca.crl").toList();
        List<io.vctrust.trust.core.model.TrustAnchor> anchors = java.util.stream.IntStream.range(0, 60)
                .mapToObj(i -> new io.vctrust.trust.core.model.TrustAnchor(String.format("ca-%02d", i), io.vctrust.trust.core.model.TrustDomain.MDOC_IACA,
                        io.vctrust.trust.core.testing.TestPki.rootCa("CN=CA " + i + ",C=UT").certificate(), "fw", null, null, Map.of("crlUrls", locations), null))
                .toList();
        var source = new Fixed("list", "fw", new SourceLoadResult(List.of(), anchors, ListInfo.unsigned(), List.of()));
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(source), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().allAnchors()).hasSize(60);
            assertThat(manager.states()).singleElement().satisfies(st -> {
                assertThat(st.warnings()).hasSize(51);
                assertThat(st.warnings().subList(0, 50)).allMatch(w -> w.startsWith("Anchor 'ca-") && w.contains("names 9 CRL locations"));
                assertThat(st.warnings().get(49)).startsWith("Anchor 'ca-49'");
                assertThat(st.warnings().getLast()).isEqualTo("10 more warnings of the registry about this source are not shown");
            });
        }
    }

    @Test
    void aListOlderThanTheOneHeldIsNotLoaded() {
        var current = new SourceLoadResult(List.of(issuer("kept", "fw", "https://kept.example").build()), List.of(),
                new ListInfo("Operator", "12", Instant.parse("2026-10-01T00:00:00Z"), null, ListInfo.SignatureStatus.VERIFIED, Map.of()), List.of());
        // From before "withdrawn" was taken off the list: signed by the same operator, and served again later.
        var replayed = new SourceLoadResult(List.of(issuer("kept", "fw", "https://kept.example").build(),
                issuer("withdrawn", "fw", "https://withdrawn.example").build()), List.of(),
                new ListInfo("Operator", "11", Instant.parse("2026-09-01T00:00:00Z"), null, ListInfo.SignatureStatus.VERIFIED, Map.of()), List.of());
        var source = new Fixed("list", "fw", current);
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(source), Clock.systemUTC())) {
            manager.start();
            source.result = replayed;
            var state = manager.refresh("list");
            assertThat(state.lastError()).contains("older than the one already loaded");
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("kept");
            // The same number issued later is a new list; so is a higher number.
            source.result = new SourceLoadResult(replayed.entities(), List.of(),
                    new ListInfo("Operator", "13", Instant.parse("2026-11-01T00:00:00Z"), null, ListInfo.SignatureStatus.VERIFIED, Map.of()), List.of());
            assertThat(manager.refresh("list").lastError()).isNull();
            assertThat(registry.snapshot().entities()).hasSize(2);
        }
    }
}
