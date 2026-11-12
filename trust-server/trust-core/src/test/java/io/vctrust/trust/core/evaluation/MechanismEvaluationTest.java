package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.did.DidJwkDriver;
import io.vctrust.trust.core.did.DidKeyDriver;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The service's evaluator under operator mechanisms: a governed question is decided under the mechanism's rules on top
 * of the built-in ones, a question no mechanism governs exactly as without mechanisms. The shared vectors
 * (conformance/evaluation/mechanisms.*) hold the client library to the same.
 */
class MechanismEvaluationTest {

    static final String DID_KEY = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    static final String NATIONAL_EKU = "1.3.6.1.4.1.99999.1.1";
    static final String MDL_EKU = "1.0.18013.5.1.2";
    static final String DP = "http://crl.nation.example/id.crl";

    final TestPki.Issued iaca = TestPki.rootCa("CN=Utopia IACA,C=UT");
    final TestPki.Issued ds = TestPki.documentSigner("CN=Utopia DS,C=UT", iaca);
    final TestPki.Issued nationCa = TestPki.rootCa("CN=National ID CA,C=UT");
    final TestPki.Issued nationSigner = TestPki.custom("CN=National ID signer,C=UT", nationCa, false, KeyUsage.digitalSignature,
            List.of(NATIONAL_EKU, MDL_EKU), List.of(DP), Duration.ofDays(1000));
    final TestPki.Issued nationNoMdlEku = TestPki.custom("CN=National ID signer without the mDL purpose,C=UT", nationCa, false, KeyUsage.digitalSignature,
            List.of(NATIONAL_EKU), List.of(DP), Duration.ofDays(1000));
    final TestPki.Issued rpCa = TestPki.rootCa("CN=RP Access CA,C=UT");
    final TestPki.Issued rp = TestPki.leaf("CN=Verifier,C=UT", rpCa, List.of("verifier.example"), null);

    final TrustRegistry registry = new TrustRegistry();
    final ClientProfile lenient = new ClientProfile("w", "Wallet", java.util.Set.of("utopia"), false, false, false, false, false);
    /** Holds no CRL and can fetch none: every status is unknown. */
    final RevocationChecker noCrls = new RevocationChecker(new RevocationChecker.CrlSource() {
        @Override
        public List<io.vctrust.trust.core.x509.RevocationChecker.Crl> heldFor(X509Certificate issuer) {
            return List.of();
        }

        @Override
        public io.vctrust.trust.core.x509.RevocationChecker.Crl fetch(String url) throws IOException {
            throw new IOException("offline");
        }
    }, "trust-service");

    static final List<Object> MECHANISMS = List.of(
            Map.of("id", "national-id",
                    "for", Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.example.id.*")),
                    "keys", List.of("x5c"),
                    "x509", Map.of("domain", "national-id", "profile", Map.of("leaf", Map.of("extended-key-usage", List.of(NATIONAL_EKU))))),
            Map.of("id", "mdl", "for", Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.iso.18013.5.1.mDL")),
                    "x509", Map.of("domain", "national-id")),
            Map.of("id", "strict-revocation", "for", Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.example.revoc")),
                    "x509", Map.of("domain", "national-id", "revocation", "required")),
            Map.of("id", "university", "for", Map.of("role", "issuer", "formats", List.of("ldp_vc")), "keys", List.of("did"),
                    "did", Map.of("methods", List.of("web"))),
            Map.of("id", "verifiers", "for", Map.of("role", "verifier"), "keys", List.of("x5c")));

    TrustEvaluator evaluator;

    @BeforeEach
    void setUp() {
        Provenance prov = Provenance.of("test", "static", "utopia", null, Instant.now());
        var dmv = TrustedEntity.builder("utopia-dmv").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .authorization(CredentialAuthorization.of("mso_mdoc", "org.iso.18013.5.1.mDL")).provenance(prov).build();
        var university = TrustedEntity.builder("university").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.DID, DID_KEY).provenance(prov).build();
        var verifier = TrustedEntity.builder("rp").framework("utopia").role(EntityRole.VERIFIER)
                .identifier(IdentifierType.DNS, "verifier.example").provenance(prov).build();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("utopia", "Utopia", null, null, null)),
                List.of(dmv, university, verifier), List.of(
                new TrustAnchor("iaca", TrustDomain.MDOC_IACA, iaca.certificate(), "utopia", "utopia-dmv", null, null, prov),
                new TrustAnchor("nation", TrustDomain.of("national-id"), nationCa.certificate(), "utopia", null, null, null, prov),
                new TrustAnchor("rp-ca", TrustDomain.VERIFIER_ACCESS, rpCa.certificate(), "utopia", null, null, null, prov))));
        evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of(new DidKeyDriver(), new DidJwkDriver())), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1), noCrls, TrustMechanisms.fromConfiguration(MECHANISMS));
    }

    TrustDecision issuer(TestPki.Issued signer, String format, String type) {
        return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null, List.of(Certificates.toBase64(signer.certificate())), null, null),
                new TrustQuery.Context("oid4vci", format, type, null, null, List.of())), lenient);
    }

    static List<String> errors(TrustDecision d) {
        return d.reasons().stream().filter(Reason::isError).map(Reason::code).toList();
    }

    @Test
    void aGovernedQuestionCountsTheAnchorsOfTheMechanismsDomainAndNamesTheMechanism() {
        TrustDecision d = issuer(nationSigner, "mso_mdoc", "org.example.id.card");
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.evidence().mechanism()).isEqualTo("national-id");
        assertThat(d.evidence().x509().anchor().id()).isEqualTo("nation");
        // The default domain's anchors do not count for it: a Document Signer under the IACA is unknown there.
        TrustDecision underIaca = issuer(ds, "mso_mdoc", "org.example.id.card");
        assertThat(underIaca.decision()).isEqualTo(Decision.UNKNOWN);
        assertThat(underIaca.reasons()).extracting(Reason::code).contains("x509.no_anchor");
    }

    @Test
    void aQuestionNoMechanismGovernsIsDecidedAsWithout() {
        TrustDecision d = issuer(nationSigner, "mso_mdoc", "eu.europa.ec.eudi.pid.1");
        assertThat(d.decision()).isEqualTo(Decision.UNKNOWN);
        assertThat(d.evidence().mechanism()).isNull();
        TrustEvaluator without = new TrustEvaluator(registry, null, new DidResolver(List.of(new DidKeyDriver())), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1), noCrls);
        TrustQuery q = new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null, List.of(Certificates.toBase64(ds.certificate())), null, null),
                new TrustQuery.Context("oid4vci", "mso_mdoc", "eu.europa.ec.eudi.pid.1", null, null, List.of()));
        assertThat(evaluator.evaluate(q, lenient)).usingRecursiveComparison().ignoringFields("evaluatedAt", "validUntil", "evidence.x509.validationTime")
                .isEqualTo(without.evaluate(q, lenient));
    }

    @Test
    void theBuiltInProfileFollowsTheQuestionToAnotherDomain() {
        // An mDL governed into the national-id domain still needs the ISO 18013-5 purpose of a Document Signer.
        assertThat(issuer(nationSigner, "mso_mdoc", "org.iso.18013.5.1.mDL").decision()).isEqualTo(Decision.TRUSTED);
        TrustDecision d = issuer(nationNoMdlEku, "mso_mdoc", "org.iso.18013.5.1.mDL");
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(errors(d)).containsExactly("mdoc.ds.eku");
        assertThat(d.evidence().x509().profile()).isEqualTo("iso18013-5-document-signer");
    }

    @Test
    void aProfileMemberThatFailsRefuses() {
        TestPki.Issued otherPurpose = TestPki.custom("CN=Other purpose,C=UT", nationCa, false, KeyUsage.digitalSignature, List.of(MDL_EKU), List.of(DP),
                Duration.ofDays(1000));
        TrustDecision d = issuer(otherPurpose, "mso_mdoc", "org.example.id.card");
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(errors(d)).containsExactly("profile.extended_key_usage");
    }

    @Test
    void revocationRequiredMakesAnUnknownStatusAnErrorForALenientClient() {
        TrustDecision governed = issuer(nationSigner, "mso_mdoc", "org.example.revoc");
        assertThat(governed.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(errors(governed)).containsExactly("x509.revocation_unknown");
        TrustDecision other = issuer(nationSigner, "mso_mdoc", "org.example.id.card");
        assertThat(other.reasons()).filteredOn(r -> r.code().equals("x509.revocation_unknown")).allMatch(r -> !r.isError()).isNotEmpty();
    }

    @Test
    void aKeyPresentedInAWayTheMechanismDoesNotAcceptIsRefused() {
        TrustDecision did = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null, List.of(), null,
                DID_KEY + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), new TrustQuery.Context("oid4vci", "mso_mdoc", "org.example.id.card", null, null, List.of())), lenient);
        assertThat(errors(did)).containsExactly("mechanism.key_not_accepted");
        TrustDecision jwk = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null, List.of(),
                Map.of("kty", "OKP", "crv", "Ed25519", "x", "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"), null),
                new TrustQuery.Context("oid4vci", "ldp_vc", null, null, null, List.of())), lenient);
        assertThat(errors(jwk)).containsExactly("mechanism.key_not_accepted");
        TrustDecision x5c = issuer(nationSigner, "ldp_vc", null);
        assertThat(errors(x5c)).contains("mechanism.key_not_accepted");
        // An identifier alone is a registry lookup: there is no key to refuse.
        TrustDecision lookup = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(DID_KEY, List.of(), null, null),
                new TrustQuery.Context("oid4vci", "ldp_vc", null, null, null, List.of())), lenient);
        assertThat(lookup.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(lookup.evidence().mechanism()).isEqualTo("university");
    }

    @Test
    void aDidKeyOfAMethodTheMechanismDoesNotListIsRefused() {
        TrustDecision d = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(DID_KEY, List.of(), null,
                DID_KEY + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), new TrustQuery.Context("oid4vci", "ldp_vc", null, null, null, List.of())), lenient);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(errors(d)).containsExactly("mechanism.did_method_not_accepted");
    }

    @Test
    void aGovernedVerifierStillHasItsDnsNameChecked() {
        TrustQuery wrongName = new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:other.example",
                List.of(Certificates.toBase64(rp.certificate())), null, null), new TrustQuery.Context("oid4vp", null, null, null,
                "https://other.example/response", List.of()));
        TrustDecision d = evaluator.evaluate(wrongName, lenient);
        assertThat(d.evidence().mechanism()).isEqualTo("verifiers");
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(errors(d)).contains("verifier.san_dns");
    }
}
