package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two records of one anchor id in one framework that differ (a status, a constraint) are not loaded at all: kept first
 * come, which one survived would depend on the order of the sources, and the one left out may be the CA's withdrawal
 * or constraint. The same record listed twice loses nothing.
 */
class DifferingAnchorRecordsTest {

    static final TestPki.Issued CA = TestPki.rootCa("CN=Listed Twice CA,C=UT");
    static final TestPki.Issued SIGNER = TestPki.leaf("CN=Signer,C=UT", CA, List.of(), null);

    static TrustAnchor record(String source, EntityStatus status, Map<String, Object> constraints) {
        return new TrustAnchor("shared-ca", TrustDomain.CREDENTIAL_ISSUER, CA.certificate(), "fw", null, status, constraints,
                Provenance.of(source, "test", "fw", "https://" + source + ".example/list", Instant.now()));
    }

    static TrustSourceManagerTest.Fixed source(String id, TrustAnchor... anchors) {
        return new TrustSourceManagerTest.Fixed(id, "fw", new SourceLoadResult(List.of(), List.of(anchors), ListInfo.unsigned(), List.of()));
    }

    static TrustDecision decide(TrustRegistry registry, TrustSourceManager sources) {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                        new TrustQuery.Subject(null, List.of(Certificates.toBase64(SIGNER.certificate())), null, null),
                        new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())), ClientProfile.unrestricted("wallet"));
    }

    @Test
    void aRevokedRecordAndAnActiveOneOfOneAnchorLoadNeither() {
        var active = source("official", record("official", EntityStatus.ACTIVE, Map.of()));
        var revoked = source("mirror", record("mirror", EntityStatus.REVOKED, Map.of()));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(active, revoked), List.of(revoked, active))) {
            var registry = new TrustRegistry();
            String named = order.stream().map(TrustSource::id).toList().toString();
            try (var sources = new TrustSourceManager(registry, List.of(), order, Clock.systemUTC())) {
                sources.start();
                assertThat(registry.snapshot().anchor("shared-ca")).as(named).isEmpty();
                // UNKNOWN for want of an anchor: not TRUSTED under the active record, whichever source comes first.
                TrustDecision d = decide(registry, sources);
                assertThat(d.decision()).as(named).isEqualTo(Decision.UNKNOWN);
                assertThat(d.reasons()).extracting(r -> r.code()).contains("x509.no_anchor");
                assertThat(sources.states()).as(named).hasSize(2).allSatisfy(st -> assertThat(st.warnings()).singleElement()
                        .satisfies(w -> assertThat(w).startsWith("Anchor 'shared-ca' is not loaded: ").contains("'official'", "'mirror'", "status")));
            }
        }
    }

    @Test
    void aConstrainedRecordAndAnUnconstrainedOneOfOneAnchorLoadNeither() {
        var open = source("official", record("official", EntityStatus.ACTIVE, Map.of()));
        var constrained = source("mirror", record("mirror", EntityStatus.ACTIVE, Map.of("docTypes", List.of("org.iso.18013.5.1.mDL"))));
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(open, constrained), List.of(constrained, open))) {
            var registry = new TrustRegistry();
            String named = order.stream().map(TrustSource::id).toList().toString();
            try (var sources = new TrustSourceManager(registry, List.of(), order, Clock.systemUTC())) {
                sources.start();
                assertThat(registry.snapshot().allAnchors()).as(named).isEmpty();
                assertThat(decide(registry, sources).decision()).as(named).isEqualTo(Decision.UNKNOWN);
                assertThat(sources.states()).allSatisfy(st -> assertThat(st.warnings()).singleElement()
                        .satisfies(w -> assertThat(w).contains("'official'", "'mirror'", "constraints")));
            }
        }
    }

    @Test
    void oneSourceListingTwoDifferentRecordsOfOneAnchorLoadsNeither() {
        var list = source("list", record("list", EntityStatus.ACTIVE, Map.of()), record("list", EntityStatus.SUSPENDED, Map.of()));
        var registry = new TrustRegistry();
        try (var sources = new TrustSourceManager(registry, List.of(), List.of(list), Clock.systemUTC())) {
            sources.start();
            assertThat(registry.snapshot().allAnchors()).isEmpty();
            assertThat(sources.states()).singleElement().satisfies(st -> assertThat(st.warnings()).singleElement()
                    .satisfies(w -> assertThat(w).startsWith("Anchor 'shared-ca' is not loaded: source 'list' lists it twice")));
        }
    }

    @Test
    void theSameRecordListedTwiceLosesNothing() {
        // Where it was retrieved from and when differ; nothing else does.
        var official = source("official", record("official", EntityStatus.ACTIVE, Map.of("docTypes", List.of("org.example.diploma"))));
        var mirror = source("mirror", record("mirror", EntityStatus.ACTIVE, Map.of("docTypes", List.of("org.example.diploma"))));
        var registry = new TrustRegistry();
        try (var sources = new TrustSourceManager(registry, List.of(), List.of(official, mirror), Clock.systemUTC())) {
            sources.start();
            assertThat(registry.snapshot().anchor("shared-ca")).get().satisfies(a -> assertThat(a.provenance().sourceId()).isEqualTo("official"));
            assertThat(decide(registry, sources).decision()).isEqualTo(Decision.TRUSTED);
            assertThat(sources.states()).allSatisfy(st -> assertThat(st.warnings()).isEmpty());
        }
    }
}
