package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.testing.TestPki;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Each member of a mechanism's certificate profile is one check, with a code of its own; a member that is not set checks nothing. */
class CertificateRequirementsTest {

    static final String EKU = "1.3.6.1.4.1.99999.1.1";
    static final String DP = "http://crl.nation.example/id.crl";

    final TestPki.Issued ca = TestPki.rootCa("CN=National ID CA,O=Nation,C=UT");
    /** Meets every member below. */
    final TestPki.Issued good = TestPki.custom("CN=Signer,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of(DP), Duration.ofDays(1000));

    static CertificateRequirements all() {
        return new CertificateRequirements(true, List.of("digitalSignature"), List.of(EKU), true, 1100, true, 0);
    }

    static List<String> codes(CertificateRequirements r, X509Certificate anchor, X509Certificate... path) {
        return r.check(List.of(path), anchor).stream().map(ValidationIssue::code).toList();
    }

    @Test
    void aCertificateThatMeetsEveryMemberPasses() {
        assertThat(codes(all(), ca.certificate(), good.certificate())).isEmpty();
    }

    @Test
    void eachMemberFailsAlone() {
        X509Certificate anchor = ca.certificate();
        assertThat(codes(all(), anchor, TestPki.custom("CN=A CA,O=Nation,C=UT", ca, true, KeyUsage.digitalSignature, List.of(EKU), List.of(DP),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.leaf_is_ca");
        assertThat(codes(all(), anchor, TestPki.custom("CN=No key usage,O=Nation,C=UT", ca, false, null, List.of(EKU), List.of(DP),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.key_usage");
        assertThat(codes(all(), anchor, TestPki.custom("CN=Agreement only,O=Nation,C=UT", ca, false, KeyUsage.keyAgreement, List.of(EKU), List.of(DP),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.key_usage");
        assertThat(codes(all(), anchor, TestPki.custom("CN=Other purpose,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature,
                List.of("1.3.6.1.5.5.7.3.4"), List.of(DP), Duration.ofDays(1000)).certificate())).containsExactly("profile.extended_key_usage");
        assertThat(codes(all(), anchor, TestPki.custom("CN=Abroad,O=Nation,C=NL", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of(DP),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.country");
        assertThat(codes(all(), anchor, TestPki.custom("CN=No country,O=Nation", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of(DP),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.country");
        assertThat(codes(all(), anchor, TestPki.custom("CN=Long lived,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of(DP),
                Duration.ofDays(1100).plusSeconds(1)).certificate())).containsExactly("profile.validity");
        assertThat(codes(all(), anchor, TestPki.custom("CN=No CRL,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of(),
                Duration.ofDays(1000)).certificate())).containsExactly("profile.crl_distribution_point");
        assertThat(codes(all(), anchor, TestPki.custom("CN=LDAP CRL,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature, List.of(EKU),
                List.of("ldap://ldap.nation.example/cn=crl"), Duration.ofDays(1000)).certificate())).containsExactly("profile.crl_distribution_point");
        TestPki.Issued sub = TestPki.intermediateCa("CN=Sub CA,O=Nation,C=UT", ca);
        TestPki.Issued under = TestPki.custom("CN=Under a sub CA,O=Nation,C=UT", sub, false, KeyUsage.digitalSignature, List.of(EKU), List.of(DP),
                Duration.ofDays(500));
        assertThat(codes(all(), anchor, under.certificate(), sub.certificate())).containsExactly("profile.path_length");
    }

    @Test
    void theBoundariesAreInclusive() {
        TestPki.Issued exactly = TestPki.custom("CN=Exactly,O=Nation,C=UT", ca, false, KeyUsage.digitalSignature, List.of(EKU), List.of("HTTPS://crl.nation.example/x"),
                Duration.ofDays(1100));
        assertThat(codes(all(), ca.certificate(), exactly.certificate())).isEmpty();
        TestPki.Issued sub = TestPki.intermediateCa("CN=Sub CA,O=Nation,C=UT", ca);
        assertThat(codes(new CertificateRequirements(false, List.of(), List.of(), false, null, false, 1), ca.certificate(), good.certificate(),
                sub.certificate())).isEmpty();
    }

    @Test
    void aMemberThatIsNotSetChecksNothing() {
        TestPki.Issued bare = TestPki.custom("CN=Bare", ca, true, null, List.of(), List.of(), Duration.ofDays(9000));
        assertThat(codes(new CertificateRequirements(false, List.of(), List.of(), false, null, false, null), ca.certificate(), bare.certificate())).isEmpty();
    }

    @Test
    void theBuiltInProfileKeepsApplyingUnderItsOwnName() {
        CertificateProfile combined = CertificateProfiles.withRequirements(CertificateProfiles.MDOC_DOCUMENT_SIGNER, all());
        assertThat(combined.name()).isEqualTo(CertificateProfiles.MDOC_DOCUMENT_SIGNER.name());
        // An mDL signer without the ISO 18013-5 extended key usage fails the built-in profile, whatever the mechanism asks for.
        List<String> codes = combined.check(List.of(good.certificate()), ca.certificate(), new CertificateProfile.ProfileContext(null, "org.iso.18013.5.1.mDL"))
                .stream().map(ValidationIssue::code).toList();
        assertThat(codes).containsExactly("mdoc.ds.eku");
        assertThat(CertificateProfiles.withRequirements(CertificateProfiles.NONE, null)).isSameAs(CertificateProfiles.NONE);
    }
}
