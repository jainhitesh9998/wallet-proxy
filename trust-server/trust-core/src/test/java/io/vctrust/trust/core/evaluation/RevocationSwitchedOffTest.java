package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.CertificateRevocation;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.ValidationIssue;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.vctrust.trust.core.x509.ValidationIssue.Severity.ERROR;
import static io.vctrust.trust.core.x509.ValidationIssue.Severity.WARNING;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * The service's evaluator with revocation checking switched off (trust.revocation.enabled: false). Whether a status
 * must be known is a rule about the answer, set by the client profile or the governing mechanism: the evaluator still
 * gives every certificate below the anchor a status, UNKNOWN because nothing is checked, and the rule applies to it as
 * to any other unknown status. A device always checks; this keeps the service's answer the device's.
 */
class RevocationSwitchedOffTest {

    static final String SWITCHED_OFF = "revocation checking is switched off on this service";

    final TestPki.Issued root = TestPki.rootCa("CN=Example Issuer Root,C=UT");
    /** One CA below the anchor that names where its CRL is, and a signer that names none: the reason is the same for both. */
    final TestPki.Issued ca = TestPki.withRevocationUrls("CN=Example Issuing CA,C=UT", root, true, List.of("http://crl.example/root.crl"), List.of(), null);
    final TestPki.Issued signer = TestPki.leaf("CN=Example Issuer,C=UT", ca, List.of(), null);
    /** A signer certificate an operator listed as an anchor itself. */
    final TestPki.Issued pinned = TestPki.leaf("CN=Pinned Issuer,C=UT", root, List.of(), null);

    final ClientProfile lenient = new ClientProfile("wallet", "Wallet", Set.of("example"), false, false, false, false, false);
    final ClientProfile strict = new ClientProfile("verifier", "Verifier", Set.of("example"), false, false, false, true, false);

    final TrustRegistry registry = new TrustRegistry();
    TrustEvaluator evaluator;

    @BeforeEach
    void setUp() {
        Provenance prov = Provenance.of("test", "static", "example", null, Instant.now());
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("example", "Example", null, null, null)), List.of(),
                List.of(new TrustAnchor("root", TrustDomain.CREDENTIAL_ISSUER, root.certificate(), "example", null, null, null, prov),
                        new TrustAnchor("pinned", TrustDomain.CREDENTIAL_ISSUER, pinned.certificate(), "example", null, null, null, prov))));
        // As TrustCoreConfiguration wires it when trust.revocation.enabled is false.
        RevocationChecker switchedOff = new RevocationChecker(RevocationChecker.CrlSource.SWITCHED_OFF, "trust-service");
        evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1),
                switchedOff, TrustMechanisms.fromConfiguration(List.of(Map.of("id", "strict-revocation",
                        "for", Map.of("role", "issuer", "formats", List.of("dc+sd-jwt"), "types", List.of("org.example.strict")),
                        "x509", Map.of("revocation", "required")))));
    }

    TrustDecision ask(List<X509Certificate> chain, String type, ClientProfile client) {
        return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null,
                chain.stream().map(Certificates::toBase64).toList(), null, null),
                new TrustQuery.Context("oid4vci", "dc+sd-jwt", type, null, null, List.of())), client);
    }

    static List<String> codes(TrustDecision d, ValidationIssue.Severity severity) {
        return d.reasons().stream().filter(r -> r.severity() == severity).map(Reason::code).toList();
    }

    @Test
    void aLenientClientIsTrustedWithAWarningForEveryCertificateBelowTheAnchor() {
        TrustDecision d = ask(List.of(signer.certificate(), ca.certificate()), "org.example.diploma", lenient);
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(codes(d, ERROR)).isEmpty();
        assertThat(codes(d, WARNING)).containsExactly("x509.revocation_unknown", "x509.revocation_unknown");
        assertThat(d.reasons()).filteredOn(r -> r.code().equals("x509.revocation_unknown")).extracting(Reason::message)
                .allMatch(m -> m.endsWith("is unknown: " + SWITCHED_OFF));
        assertThat(d.evidence().x509().revocation()).extracting(CertificateRevocation::index, CertificateRevocation::status, CertificateRevocation::reason)
                .containsExactly(tuple(0, CertificateRevocation.Status.UNKNOWN, SWITCHED_OFF),
                        tuple(1, CertificateRevocation.Status.UNKNOWN, SWITCHED_OFF));
        assertThat(d.evidence().x509().revocation()).extracting(CertificateRevocation::method, CertificateRevocation::crlUrl)
                .containsOnly(tuple(null, null));
    }

    @Test
    void aClientThatRequiresRevocationStatusIsRefused() {
        TrustDecision d = ask(List.of(signer.certificate(), ca.certificate()), "org.example.diploma", strict);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(codes(d, ERROR)).containsExactly("x509.revocation_unknown", "x509.revocation_unknown");
        assertThat(d.evidence().x509().valid()).isFalse();
        assertThat(d.evidence().x509().anchorFound()).isTrue();
        assertThat(d.evidence().x509().revocation()).extracting(CertificateRevocation::status).containsOnly(CertificateRevocation.Status.UNKNOWN);
    }

    @Test
    void aMechanismThatRequiresRevocationRefusesALenientClient() {
        TrustDecision d = ask(List.of(signer.certificate(), ca.certificate()), "org.example.strict", lenient);
        assertThat(d.evidence().mechanism()).isEqualTo("strict-revocation");
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(codes(d, ERROR)).containsExactly("x509.revocation_unknown", "x509.revocation_unknown");
    }

    @Test
    void aDirectlyPinnedCertificateHasNoStatus() {
        for (ClientProfile client : List.of(lenient, strict)) {
            TrustDecision d = ask(List.of(pinned.certificate()), "org.example.diploma", client);
            assertThat(d.decision()).as(client.clientId()).isEqualTo(Decision.TRUSTED);
            assertThat(d.reasons()).as(client.clientId()).extracting(Reason::code).contains("x509.valid").doesNotContain("x509.revocation_unknown");
            assertThat(d.evidence().x509().revocation()).as(client.clientId()).isEmpty();
        }
        // Under the mechanism too: it is the anchor itself.
        assertThat(ask(List.of(pinned.certificate()), "org.example.strict", lenient).decision()).isEqualTo(Decision.TRUSTED);
    }
}
