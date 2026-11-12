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
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Entries of one id in one framework (from two sources, or listed twice in one) are merged into one entity. What
 * restricts the party must survive the merge, whichever entry comes first: the most restrictive status, and the
 * validity of both, the later start and the earlier end of those stated.
 */
class EntityMergeTest {

    static final Instant Y2020 = Instant.parse("2020-01-01T00:00:00Z");
    static final Instant Y2025 = Instant.parse("2025-01-01T00:00:00Z");
    static final Instant Y2026 = Instant.parse("2026-01-01T00:00:00Z");
    static final Instant Y2028 = Instant.parse("2028-01-01T00:00:00Z");
    static final Instant Y2030 = Instant.parse("2030-01-01T00:00:00Z");

    static TrustedEntity entry(Instant validFrom, Instant validUntil) {
        return TrustedEntity.builder("issuer").framework("fw").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://issuer.example").validFrom(validFrom).validUntil(validUntil).build();
    }

    @Test
    void theMergedEntryIsValidOnlyWhereBothAre() {
        TrustedEntity wide = entry(Y2025, Y2030);
        TrustedEntity narrow = entry(Y2026, Y2028);
        for (List<TrustedEntity> order : List.of(List.of(wide, narrow), List.of(narrow, wide))) {
            TrustedEntity merged = RegistrySnapshot.merge(order.get(0), order.get(1));
            assertThat(merged.validFrom()).isEqualTo(Y2026);
            assertThat(merged.validUntil()).isEqualTo(Y2028);
        }
        // Validity overlapping only in part: from the later start to the earlier end.
        TrustedEntity early = entry(Y2020, Y2028);
        TrustedEntity late = entry(Y2026, Y2030);
        for (List<TrustedEntity> order : List.of(List.of(early, late), List.of(late, early))) {
            TrustedEntity merged = RegistrySnapshot.merge(order.get(0), order.get(1));
            assertThat(merged.validFrom()).isEqualTo(Y2026);
            assertThat(merged.validUntil()).isEqualTo(Y2028);
        }
    }

    @Test
    void anEntryThatStatesNoValiditySetsNoBound() {
        TrustedEntity unbounded = entry(null, null);
        TrustedEntity ended = entry(null, Y2020);
        TrustedEntity notYet = entry(Y2030, null);
        for (TrustedEntity bounded : List.of(ended, notYet)) {
            for (List<TrustedEntity> order : List.of(List.of(unbounded, bounded), List.of(bounded, unbounded))) {
                TrustedEntity merged = RegistrySnapshot.merge(order.get(0), order.get(1));
                assertThat(merged.validFrom()).isEqualTo(bounded.validFrom());
                assertThat(merged.validUntil()).isEqualTo(bounded.validUntil());
            }
        }
        TrustedEntity merged = RegistrySnapshot.merge(unbounded, entry(null, null));
        assertThat(merged.validFrom()).isNull();
        assertThat(merged.validUntil()).isNull();
    }

    static final TestPki.Issued CA = TestPki.rootCa("CN=Shared Issuer CA,C=UT");
    static final TestPki.Issued SIGNER = TestPki.leaf("CN=Merged Issuer,C=UT", CA, List.of(), null);
    static final ClientProfile CLIENT = new ClientProfile("wallet", "Wallet", Set.of("fw"), false, false, false);

    /** The issuer as a source lists it: bound to its certificate under the shared CA by the certificate's subject. */
    static TrustedEntity issuer(Instant validUntil) {
        return TrustedEntity.builder("issuer").framework("fw").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(SIGNER.certificate())).validUntil(validUntil).build();
    }

    static Fixed source(String id, TrustedEntity entity, List<TrustAnchor> anchors) {
        return new Fixed(id, "fw", new SourceLoadResult(List.of(entity), anchors, ListInfo.unsigned(), List.of()));
    }

    /** The party bound by the subject of its certificate, with these roles and this status. */
    static TrustedEntity party(Set<EntityRole> roles, EntityStatus status) {
        TrustedEntity.Builder b = TrustedEntity.builder("party").framework("fw").status(status)
                .identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(SIGNER.certificate()));
        roles.forEach(b::role);
        return b.build();
    }

    @Test
    void aWithdrawalThatNamesNoRoleNamesNoneOnceMerged() {
        TrustedEntity withdrawn = party(Set.of(), EntityStatus.REVOKED);
        TrustedEntity wallet = party(Set.of(EntityRole.WALLET_PROVIDER), EntityStatus.ACTIVE);
        for (List<TrustedEntity> order : List.of(List.of(withdrawn, wallet), List.of(wallet, withdrawn))) {
            TrustedEntity merged = RegistrySnapshot.merge(order.get(0), order.get(1));
            assertThat(merged.roles()).isEmpty();
            assertThat(merged.status()).isEqualTo(EntityStatus.REVOKED);
        }
        // An active entry without roles adds nothing to withdraw: the roles are the union, as before.
        TrustedEntity unroled = party(Set.of(), EntityStatus.ACTIVE);
        for (List<TrustedEntity> order : List.of(List.of(unroled, wallet), List.of(wallet, unroled))) {
            assertThat(RegistrySnapshot.merge(order.get(0), order.get(1)).roles()).containsExactly(EntityRole.WALLET_PROVIDER);
        }
        // A withdrawn entry that names roles limits the withdrawal to them: the union, as before.
        TrustedEntity revokedWallet = party(Set.of(EntityRole.WALLET_PROVIDER), EntityStatus.REVOKED);
        TrustedEntity issuer = party(Set.of(EntityRole.CREDENTIAL_ISSUER), EntityStatus.ACTIVE);
        assertThat(RegistrySnapshot.merge(revokedWallet, issuer).roles()).containsExactlyInAnyOrder(EntityRole.WALLET_PROVIDER, EntityRole.CREDENTIAL_ISSUER);
    }

    @Test
    void aWithdrawalThatNamesNoRoleKeepsThePartyOutWhateverIsAskedInEitherOrder() {
        List<TrustAnchor> anchors = List.of(
                new TrustAnchor("shared-issuer-ca", TrustDomain.CREDENTIAL_ISSUER, CA.certificate(), "fw", null, null, null, null),
                new TrustAnchor("shared-verifier-ca", TrustDomain.VERIFIER_ACCESS, CA.certificate(), "fw", null, null, null, null));
        Fixed withdrawn = source("withdrawn", party(Set.of(), EntityStatus.REVOKED), anchors);
        Fixed wallet = source("wallet", party(Set.of(EntityRole.WALLET_PROVIDER), EntityStatus.ACTIVE), List.of());
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(withdrawn, wallet), List.of(wallet, withdrawn))) {
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = new TrustSourceManager(registry, List.of(new TrustFramework("fw", "Framework", null, null, null)),
                    order, Clock.systemUTC())) {
                manager.start();
                TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                        Clock.systemUTC(), Duration.ofHours(1));
                for (EntityRole role : List.of(EntityRole.CREDENTIAL_ISSUER, EntityRole.VERIFIER)) {
                    String which = order.getFirst().id() + " first, asked as " + role;
                    TrustDecision d = evaluator.evaluate(new TrustQuery(role,
                            new TrustQuery.Subject(null, List.of(Certificates.toBase64(SIGNER.certificate())), null, null),
                            new TrustQuery.Context(role == EntityRole.VERIFIER ? "oid4vp" : "oid4vci", role == EntityRole.VERIFIER ? null : "dc+sd-jwt",
                                    null, null, null, List.of())), CLIENT);
                    assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(d.reasons()).as(which).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
                }
            }
        }
    }

    @Test
    void aSecondSourceWhoseEntryHasEndedKeepsTheIssuerOutInEitherOrder() {
        TrustAnchor anchor = new TrustAnchor("shared-ca", TrustDomain.CREDENTIAL_ISSUER, CA.certificate(), "fw", null, null, null, null);
        Fixed listed = source("list", issuer(null), List.of(anchor));
        // The other source of the framework says the registration ended in 2020.
        Fixed ended = source("ended", issuer(Y2020), List.of());
        for (List<TrustSource> order : List.<List<TrustSource>>of(List.of(listed, ended), List.of(ended, listed))) {
            String which = order.getFirst().id() + " first";
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = new TrustSourceManager(registry, List.of(new TrustFramework("fw", "Framework", null, null, null)),
                    order, Clock.systemUTC())) {
                manager.start();
                TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                        Clock.systemUTC(), Duration.ofHours(1));
                TrustDecision d = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                        new TrustQuery.Subject(null, List.of(Certificates.toBase64(SIGNER.certificate())), null, null),
                        new TrustQuery.Context("oid4vci", "dc+sd-jwt", null, null, null, List.of())), CLIENT);
                assertThat(d.decision()).as(which + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.entity().id()).as(which).isEqualTo("issuer");
                assertThat(d.reasons()).as(which).filteredOn(Reason::isError).singleElement().satisfies(r -> {
                    assertThat(r.code()).isEqualTo("entity.status");
                    assertThat(r.message()).isEqualTo("Entity 'issuer' is ACTIVE (expired)");
                });
                assertThat(registry.snapshot().entity("issuer")).as(which).get()
                        .satisfies(e -> assertThat(e.validUntil()).isEqualTo(Y2020));
            }
        }
    }
}
