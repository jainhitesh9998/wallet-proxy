package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.testing.TestPki;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class X509PathValidatorTest {

    private final X509PathValidator validator = new X509PathValidator();

    private static TrustAnchor anchor(TestPki.Issued ca, TrustDomain d) {
        return new TrustAnchor(null, d, ca.certificate(), "fw", null, null, null, null);
    }

    @Test
    void validatesDocumentSignerAgainstIaca() {
        var iaca = TestPki.rootCa("CN=Utopia IACA,C=UT");
        var ds = TestPki.documentSigner("CN=Utopia DS,C=UT", iaca);
        var r = validator.validate(List.of(ds.certificate()), List.of(anchor(iaca, TrustDomain.MDOC_IACA)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER));
        assertThat(r.valid()).as(r.issues().toString()).isTrue();
        assertThat(r.anchor().certificate()).isEqualTo(iaca.certificate());
        assertThat(r.path()).hasSize(1);
    }

    @Test
    void acceptsChainThatIncludesTheAnchor() {
        var root = TestPki.rootCa("CN=Root,C=UT");
        var inter = TestPki.intermediateCa("CN=Inter,C=UT", root);
        var leaf = TestPki.leaf("CN=Issuer,C=UT", inter, List.of(), null);
        var r = validator.validate(List.of(leaf.certificate(), inter.certificate(), root.certificate()),
                List.of(anchor(root, TrustDomain.CREDENTIAL_ISSUER)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.CREDENTIAL_ISSUER));
        assertThat(r.valid()).as(r.issues().toString()).isTrue();
        assertThat(r.path()).hasSize(2);
    }

    @Test
    void reportsNoAnchorAsUnknownNotInvalidChain() {
        var root = TestPki.rootCa("CN=Root,C=UT");
        var other = TestPki.rootCa("CN=Other,C=UT");
        var leaf = TestPki.leaf("CN=Issuer,C=UT", root, List.of(), null);
        var r = validator.validate(List.of(leaf.certificate()), List.of(anchor(other, TrustDomain.CREDENTIAL_ISSUER)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.NONE));
        assertThat(r.valid()).isFalse();
        assertThat(r.anchorFound()).isFalse();
        assertThat(r.issues()).extracting(ValidationIssue::code).contains("x509.no_anchor");
    }

    @Test
    void rejectsExpiredLeaf() {
        var root = TestPki.rootCa("CN=Root,C=UT");
        var leaf = TestPki.leaf("CN=Old,C=UT", root, List.of(), null,
                Instant.now().minus(Duration.ofDays(30)), Instant.now().minus(Duration.ofDays(1)));
        var r = validator.validate(List.of(leaf.certificate()), List.of(anchor(root, TrustDomain.CREDENTIAL_ISSUER)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.NONE));
        assertThat(r.valid()).isFalse();
        assertThat(r.anchorFound()).isTrue();
        assertThat(r.issues()).anyMatch(i -> i.code().startsWith("x509.path"));
    }

    @Test
    void mdocProfileRequiresDocumentSignerEku() {
        var iaca = TestPki.rootCa("CN=IACA,C=UT");
        var notDs = TestPki.leaf("CN=Not a DS,C=UT", iaca, List.of(), null);
        var r = validator.validate(List.of(notDs.certificate()), List.of(anchor(iaca, TrustDomain.MDOC_IACA)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER));
        assertThat(r.valid()).isFalse();
        assertThat(r.issues()).extracting(ValidationIssue::code).contains("mdoc.ds.eku");
    }

    @Test
    void mdocProfileRejectsCountryMismatch() {
        var iaca = TestPki.rootCa("CN=IACA,C=UT");
        var ds = TestPki.documentSigner("CN=DS,C=NL", iaca);
        var r = validator.validate(List.of(ds.certificate()), List.of(anchor(iaca, TrustDomain.MDOC_IACA)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER));
        assertThat(r.valid()).isFalse();
        assertThat(r.issues()).extracting(ValidationIssue::code).contains("mdoc.ds.country");
    }

    @Test
    void verifierProfileChecksSanDns() {
        var ca = TestPki.rootCa("CN=RP CA,C=UT");
        var leaf = TestPki.leaf("CN=Verifier,C=UT", ca, List.of("verifier.example"), null);
        var ok = validator.validate(List.of(leaf.certificate()), List.of(anchor(ca, TrustDomain.VERIFIER_ACCESS)),
                new X509PathValidator.Options(Instant.now(), CertificateProfiles.VERIFIER_ACCESS,
                        new CertificateProfile.ProfileContext("verifier.example", null), false));
        var bad = validator.validate(List.of(leaf.certificate()), List.of(anchor(ca, TrustDomain.VERIFIER_ACCESS)),
                new X509PathValidator.Options(Instant.now(), CertificateProfiles.VERIFIER_ACCESS,
                        new CertificateProfile.ProfileContext("evil.example", null), false));
        assertThat(ok.valid()).isTrue();
        assertThat(bad.valid()).isFalse();
        assertThat(bad.issues()).extracting(ValidationIssue::code).contains("verifier.san_dns");
    }

    @Test
    void pinnedLeafIsAccepted() {
        var self = TestPki.rootCa("CN=Self signed issuer,C=UT");
        var r = validator.validate(List.of(self.certificate()), List.of(anchor(self, TrustDomain.CREDENTIAL_ISSUER)),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.NONE));
        assertThat(r.valid()).isTrue();
        assertThat(r.issues()).extracting(ValidationIssue::code).contains("x509.pinned");
    }

    @Test
    void anchorDocTypeConstraintIsEnforced() {
        var iaca = TestPki.rootCa("CN=IACA,C=UT");
        var ds = TestPki.documentSigner("CN=DS,C=UT", iaca);
        var constrained = new TrustAnchor(null, TrustDomain.MDOC_IACA, iaca.certificate(), "fw", null, null,
                java.util.Map.of("docTypes", List.of("org.iso.18013.5.1.mDL")), null);
        var ok = validator.validate(List.of(ds.certificate()), List.of(constrained), new X509PathValidator.Options(
                Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER, new CertificateProfile.ProfileContext(null, "org.iso.18013.5.1.mDL"), false));
        var bad = validator.validate(List.of(ds.certificate()), List.of(constrained), new X509PathValidator.Options(
                Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER, new CertificateProfile.ProfileContext(null, "eu.europa.ec.eudi.pid.1"), false));
        assertThat(ok.valid()).isTrue();
        assertThat(bad.valid()).isFalse();
    }

    @Test
    void relaxedAnchorTurnsProfileErrorsIntoWarnings() {
        var iaca = TestPki.rootCa("CN=Sandbox Root,C=IN");
        var notDs = TestPki.leaf("CN=Sandbox signer,C=IN", iaca, List.of(), null);
        var relaxed = new TrustAnchor(null, TrustDomain.MDOC_IACA, iaca.certificate(), "fw", null, null,
                java.util.Map.of("relaxProfile", true), null);
        var r = validator.validate(List.of(notDs.certificate()), List.of(relaxed),
                X509PathValidator.Options.at(Instant.now(), CertificateProfiles.MDOC_DOCUMENT_SIGNER));
        assertThat(r.valid()).isTrue();
        assertThat(r.issues()).extracting(ValidationIssue::code).contains("x509.profile_relaxed", "mdoc.ds.eku");
        assertThat(r.issues()).noneMatch(ValidationIssue::isError);
    }
}
