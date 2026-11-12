package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.testing.TestPki.Revoked;
import io.vctrust.trust.core.x509.CertificateRevocation.Status;
import io.vctrust.trust.core.x509.RevocationChecker.Crl;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RevocationCheckerTest {

    static final TestPki.Issued IACA = TestPki.rootCa("CN=Revocation IACA,C=UT");
    static final TestPki.Issued DS = TestPki.documentSigner("CN=Revocation DS,C=UT", IACA);

    /** In-memory CRL source: CRLs held per issuer thumbprint, and CRLs at distribution point URLs. */
    static final class Crls implements RevocationChecker.CrlSource {
        final Map<String, List<Crl>> held = new HashMap<>();
        final Map<String, Crl> byUrl = new HashMap<>();
        final List<String> fetched = new java.util.ArrayList<>();

        Crls hold(TestPki.Issued issuer, X509CRL crl) {
            held.computeIfAbsent(Certificates.sha256Thumbprint(issuer.certificate()), k -> new java.util.ArrayList<>())
                    .add(Crl.parse(der(crl), null, Instant.now()));
            return this;
        }

        Crls at(String url, X509CRL crl) {
            byUrl.put(url, Crl.parse(der(crl), url, Instant.now()));
            return this;
        }

        @Override
        public List<Crl> heldFor(X509Certificate issuer) {
            return held.getOrDefault(Certificates.sha256Thumbprint(issuer), List.of());
        }

        @Override
        public Crl fetch(String url) throws IOException {
            fetched.add(url);
            Crl c = byUrl.get(url);
            if (c == null) {
                throw new IOException("HTTP 404 from " + url);
            }
            return c;
        }
    }

    static byte[] der(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static PathValidationResult validate(List<X509Certificate> chain, TestPki.Issued root, Crls crls, boolean required) {
        return validate(chain, root, new RevocationChecker(crls, "trust-service"), required);
    }

    private static PathValidationResult validate(List<X509Certificate> chain, TestPki.Issued root, RevocationChecker checker, boolean required) {
        TrustAnchor anchor = new TrustAnchor(null, TrustDomain.MDOC_IACA, root.certificate(), "fw", null, null, null, null);
        return new X509PathValidator().validate(chain, List.of(anchor),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.NONE).withRevocation(checker, required));
    }

    private static List<String> codes(PathValidationResult r) {
        return r.issues().stream().map(ValidationIssue::code).toList();
    }

    @Test
    void certificateNotOnTheCrlIsGood() {
        var r = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, TestPki.crl(IACA)), false);
        assertThat(r.valid()).isTrue();
        assertThat(codes(r)).contains("x509.not_revoked");
        CertificateRevocation s = r.revocation().getFirst();
        assertThat(s.status()).isEqualTo(Status.GOOD);
        assertThat(s.method()).isEqualTo("crl");
        assertThat(s.crlUrl()).isNull();
        assertThat(s.source()).isEqualTo("trust-service");
        assertThat(s.serialNumber()).isEqualTo(DS.certificate().getSerialNumber().toString(16));
        assertThat(s.nextUpdate()).isAfter(Instant.now());
        assertThat(r.issues().stream().filter(i -> i.code().equals("x509.not_revoked")).findFirst().orElseThrow().message())
                .contains("from the trust list");
    }

    @Test
    void revokedCertificateFailsWithItsReason() {
        var r = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, TestPki.crl(IACA, Revoked.of(DS, 1))), false);
        assertThat(r.valid()).isFalse();
        assertThat(codes(r)).contains("x509.revoked");
        assertThat(r.revocation().getFirst().status()).isEqualTo(Status.REVOKED);
        assertThat(r.revocation().getFirst().reason()).isEqualTo("keyCompromise");
        assertThat(r.revocation().getFirst().revokedAt()).isNotNull();
    }

    @Test
    void certificateOnHoldFails() {
        var r = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, TestPki.crl(IACA, Revoked.of(DS, 6))), false);
        assertThat(r.valid()).isFalse();
        assertThat(codes(r)).contains("x509.on_hold");
        assertThat(r.revocation().getFirst().status()).isEqualTo(Status.ON_HOLD);
        // removeFromCRL (8) lifts a hold only in a delta CRL read with its base; in a complete CRL it proves nothing, as on
        // the device (conformance/revocation/crl-cases.json has the rest)
        var removed = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, TestPki.crl(IACA, Revoked.of(DS, 8))), false);
        assertThat(removed.revocation().getFirst().status()).isEqualTo(Status.UNKNOWN);
        assertThat(removed.revocation().getFirst().reason()).isEqualTo("the CRL lists the certificate with reason removeFromCRL, which only a delta CRL may use");
    }

    @Test
    void expiredCrlLeavesTheStatusUnknownWarningOrErrorByPolicy() {
        X509CRL expired = TestPki.crl(IACA, Instant.now().minus(Duration.ofDays(8)), Instant.now().minus(Duration.ofDays(1)),
                List.of(), null, null);
        var lenient = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, expired), false);
        assertThat(lenient.valid()).isTrue();
        ValidationIssue w = lenient.issues().stream().filter(i -> i.code().equals("x509.revocation_unknown")).findFirst().orElseThrow();
        assertThat(w.severity()).isEqualTo(ValidationIssue.Severity.WARNING);
        assertThat(w.message()).contains("CRL expired at");
        var strict = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, expired), true);
        assertThat(strict.valid()).isFalse();
        assertThat(strict.issues()).anyMatch(i -> i.code().equals("x509.revocation_unknown") && i.isError());
        assertThat(strict.revocation().getFirst().status()).isEqualTo(Status.UNKNOWN);
    }

    @Test
    void crlSignedByAnotherKeyIsIgnored() {
        var rogue = TestPki.rootCa("CN=Rogue,C=UT");
        X509CRL forged = TestPki.crl(IACA, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(1)),
                List.of(), null, rogue.keys().getPrivate());
        var r = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, forged), false);
        assertThat(r.revocation().getFirst().status()).isEqualTo(Status.UNKNOWN);
        assertThat(r.revocation().getFirst().reason()).isEqualTo("CRL signature does not verify");
    }

    @Test
    void issuingDistributionPointScopeAndDeltaCrls() {
        X509CRL caOnly = TestPki.crl(IACA, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(1)), List.of(),
                b -> addExt(b, Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(null, false, true, null, false, false)), null);
        var r = validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, caOnly), false);
        assertThat(r.revocation().getFirst().reason()).isEqualTo("the CRL covers only CA certificates");

        X509CRL byReason = TestPki.crl(IACA, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(1)), List.of(),
                b -> addExt(b, Extension.issuingDistributionPoint, true,
                        new IssuingDistributionPoint(null, false, false, new ReasonFlags(ReasonFlags.keyCompromise), false, false)), null);
        assertThat(validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, byReason), false).revocation().getFirst().reason())
                .isEqualTo("the CRL is partitioned by reason");

        X509CRL otherScope = TestPki.crl(IACA, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(1)), List.of(),
                b -> addExt(b, Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(new DistributionPointName(
                        new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.test/part2.crl"))),
                        false, false, null, false, false)), null);
        assertThat(validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, otherScope), false).revocation().getFirst().reason())
                .isEqualTo("the CRL's distribution point does not match the certificate");

        X509CRL delta = TestPki.crl(IACA, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(1)), List.of(),
                b -> addExt(b, Extension.deltaCRLIndicator, true, new org.bouncycastle.asn1.x509.CRLNumber(BigInteger.ONE)), null);
        assertThat(validate(List.of(DS.certificate()), IACA, new Crls().hold(IACA, delta), false).revocation().getFirst().reason())
                .isEqualTo("delta CRLs are not supported");
    }

    @Test
    void intermediateChainUsesEachIssuersCrl() {
        var root = TestPki.rootCa("CN=Chain Root,C=UT");
        var inter = TestPki.withRevocationUrls("CN=Chain Intermediate,C=UT", root, true, List.of("http://crl.test/root.crl"), List.of(), null);
        var leaf = TestPki.withRevocationUrls("CN=Chain Leaf,C=UT", inter, false, List.of("http://crl.test/inter.crl"), List.of(), null);
        Crls crls = new Crls().hold(root, TestPki.crl(root)).at("http://crl.test/inter.crl", TestPki.crl(inter, Revoked.of(leaf, 4)));
        var r = validate(List.of(leaf.certificate(), inter.certificate()), root, crls, false);
        assertThat(r.valid()).isFalse();
        assertThat(r.revocation()).extracting(CertificateRevocation::status).containsExactly(Status.REVOKED, Status.GOOD);
        assertThat(r.revocation().getFirst().reason()).isEqualTo("superseded");
        assertThat(r.revocation().getFirst().crlUrl()).isEqualTo("http://crl.test/inter.crl");
        // the root's CRL is held, so the intermediate's distribution point is not fetched
        assertThat(crls.fetched).containsExactly("http://crl.test/inter.crl");
    }

    @Test
    void withoutAnyCrlTheStatusIsUnknown() {
        var none = validate(List.of(DS.certificate()), IACA, new Crls(), false);
        assertThat(none.valid()).isTrue();
        assertThat(none.revocation().getFirst().reason()).isEqualTo("no CRL is published for it");

        var root = TestPki.rootCa("CN=OCSP Root,C=UT");
        var ocspOnly = TestPki.withRevocationUrls("CN=OCSP only,C=UT", root, false, List.of(), List.of("http://ocsp.test"), null);
        var r = validate(List.of(ocspOnly.certificate()), root, new Crls(), false);
        assertThat(r.revocation().getFirst().reason()).isEqualTo("the issuer publishes only OCSP, which is not used");

        var unreachable = TestPki.withRevocationUrls("CN=Unreachable CRL,C=UT", root, false, List.of("http://crl.test/missing.crl"), List.of(), null);
        var u = validate(List.of(unreachable.certificate()), root, new Crls(), true);
        assertThat(u.valid()).isFalse();
        assertThat(u.revocation().getFirst().reason()).startsWith("CRL unavailable: HTTP 404");
    }

    /** The status of {@code DS} from CRLs held for its issuer, in the order given. */
    private static CertificateRevocation statusFrom(List<X509CRL> held) {
        Crls crls = new Crls();
        held.forEach(c -> crls.hold(IACA, c));
        return validate(List.of(DS.certificate()), IACA, crls, false).revocation().getFirst();
    }

    /**
     * Several usable CRLs for one certificate decide as on the device (checkRevocation in trust-client): a revocation
     * in any of them stands, and otherwise the newest decides (by thisUpdate, then CRL number). The order they are held
     * in decides nothing.
     */
    @Test
    void ofSeveralCrlsARevocationInAnyStandsAndOtherwiseTheNewestDecides() {
        Instant now = Instant.now();
        Instant lastWeek = now.minus(Duration.ofDays(7));
        Instant today = now.minus(Duration.ofHours(1));
        Instant nextWeek = now.plus(Duration.ofDays(7));
        X509CRL oldGood = TestPki.crl(IACA, lastWeek, nextWeek, List.of(), BigInteger.ONE);
        X509CRL newRevoked = TestPki.crl(IACA, today, nextWeek, List.of(Revoked.of(DS, 1)), BigInteger.TWO);
        X509CRL oldRevoked = TestPki.crl(IACA, lastWeek, nextWeek, List.of(Revoked.of(DS, 1)), BigInteger.ONE);
        X509CRL newGood = TestPki.crl(IACA, today, nextWeek, List.of(), BigInteger.TWO);
        X509CRL oldHold = TestPki.crl(IACA, lastWeek, nextWeek, List.of(Revoked.of(DS, 6)), BigInteger.ONE);
        X509CRL newHold = TestPki.crl(IACA, today, nextWeek, List.of(Revoked.of(DS, 6)), BigInteger.TWO);
        for (boolean reversed : List.of(false, true)) {
            java.util.function.BiFunction<X509CRL, X509CRL, CertificateRevocation> held = (a, b) -> statusFrom(reversed ? List.of(b, a) : List.of(a, b));
            // A stale CRL from before the revocation does not take it back, whichever arrived first.
            assertThat(held.apply(oldGood, newRevoked)).as("reversed=" + reversed).satisfies(s -> {
                assertThat(s.status()).isEqualTo(Status.REVOKED);
                assertThat(s.thisUpdate()).isEqualTo(today.truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
            });
            // A revocation stands in an older CRL too: a certificate does not come back from a revocation.
            assertThat(held.apply(oldRevoked, newGood).status()).as("reversed=" + reversed).isEqualTo(Status.REVOKED);
            // Two that agree: the newest is the one reported.
            assertThat(held.apply(oldGood, newGood)).as("reversed=" + reversed).satisfies(s -> {
                assertThat(s.status()).isEqualTo(Status.GOOD);
                assertThat(s.thisUpdate()).isEqualTo(today.truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
            });
            // A hold can be lifted: it counts only when the newest CRL says it.
            assertThat(held.apply(oldHold, newGood).status()).as("reversed=" + reversed).isEqualTo(Status.GOOD);
            assertThat(held.apply(oldGood, newHold).status()).as("reversed=" + reversed).isEqualTo(Status.ON_HOLD);
            // Issued at the same second: the higher CRL number is the newer.
            X509CRL firstHold = TestPki.crl(IACA, today, nextWeek, List.of(Revoked.of(DS, 6)), BigInteger.ONE);
            X509CRL secondGood = TestPki.crl(IACA, today, nextWeek, List.of(), BigInteger.TWO);
            X509CRL firstGood = TestPki.crl(IACA, today, nextWeek, List.of(), BigInteger.ONE);
            X509CRL secondHold = TestPki.crl(IACA, today, nextWeek, List.of(Revoked.of(DS, 6)), BigInteger.TWO);
            assertThat(held.apply(firstHold, secondGood).status()).as("reversed=" + reversed).isEqualTo(Status.GOOD);
            assertThat(held.apply(firstGood, secondHold).status()).as("reversed=" + reversed).isEqualTo(Status.ON_HOLD);
        }
        // A CRL that cannot be used decides nothing, also when it is held first.
        X509CRL expiredRevoking = TestPki.crl(IACA, now.minus(Duration.ofDays(14)), now.minus(Duration.ofDays(1)), List.of(Revoked.of(DS, 1)), BigInteger.TEN);
        assertThat(statusFrom(List.of(expiredRevoking, oldGood)).status()).isEqualTo(Status.GOOD);
    }

    /** A source that holds CRLs per framework, as the service's CrlService does. */
    static final class FrameworkCrls implements RevocationChecker.CrlSource {
        final Map<String, Crl> byFramework = new java.util.LinkedHashMap<>();

        @Override
        public List<Crl> heldFor(X509Certificate issuer) {
            return List.copyOf(byFramework.values());
        }

        @Override
        public List<Crl> heldFor(X509Certificate issuer, java.util.function.Predicate<String> frameworks) {
            return byFramework.entrySet().stream().filter(e -> frameworks.test(e.getKey())).map(Map.Entry::getValue).toList();
        }

        @Override
        public Crl fetch(String url) throws IOException {
            throw new IOException("HTTP 404 from " + url);
        }
    }

    @Test
    void askedForAClientsFrameworksOnlyTheirCrlsCount() {
        FrameworkCrls crls = new FrameworkCrls();
        crls.byFramework.put("official", Crl.parse(der(TestPki.crl(IACA, Revoked.of(DS, 1))), "http://ca.test/current.crl", Instant.now()));
        crls.byFramework.put("partner", Crl.parse(der(TestPki.crl(IACA, Instant.now().minus(Duration.ofDays(7)), Instant.now().plus(Duration.ofDays(7)),
                List.of(), null, null)), "http://ca.test/last-week.crl", Instant.now()));
        RevocationChecker checker = new RevocationChecker(crls, "trust-service");
        java.util.function.Function<RevocationChecker, CertificateRevocation> status =
                c -> validate(List.of(DS.certificate()), IACA, c, false).revocation().getFirst();
        assertThat(status.apply(checker.forFrameworks(Set.of("official")::contains)).status()).isEqualTo(Status.REVOKED);
        assertThat(status.apply(checker.forFrameworks(Set.of("partner")::contains))).satisfies(s -> {
            assertThat(s.status()).isEqualTo(Status.GOOD);
            assertThat(s.crlUrl()).isEqualTo("http://ca.test/last-week.crl");
        });
        assertThat(status.apply(checker.forFrameworks(Set.of("official", "partner")::contains)).status()).isEqualTo(Status.REVOKED);
        assertThat(status.apply(checker.forFrameworks(f -> false))).satisfies(s -> {
            assertThat(s.status()).isEqualTo(Status.UNKNOWN);
            assertThat(s.reason()).isEqualTo("no CRL is published for it");
        });
        // Not asked for any frameworks: every CRL held counts.
        assertThat(status.apply(checker).status()).isEqualTo(Status.REVOKED);
        // Revocation switched off: the frameworks change nothing, the status is unknown and says why.
        assertThat(status.apply(new RevocationChecker(RevocationChecker.CrlSource.SWITCHED_OFF, "trust-service")
                .forFrameworks(Set.of("official")::contains))).satisfies(s -> {
            assertThat(s.status()).isEqualTo(Status.UNKNOWN);
            assertThat(s.reason()).isEqualTo(RevocationChecker.CrlSource.SWITCHED_OFF.unavailable());
        });
    }

    @Test
    void aDirectlyPinnedCertificateIsNotChecked() {
        var r = validate(List.of(IACA.certificate()), IACA, new Crls(), true);
        assertThat(r.valid()).isTrue();
        assertThat(r.revocation()).isEmpty();
    }

    private static void addExt(org.bouncycastle.cert.X509v2CRLBuilder b, org.bouncycastle.asn1.ASN1ObjectIdentifier oid, boolean critical,
                               org.bouncycastle.asn1.ASN1Encodable value) {
        try {
            b.addExtension(oid, critical, value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
