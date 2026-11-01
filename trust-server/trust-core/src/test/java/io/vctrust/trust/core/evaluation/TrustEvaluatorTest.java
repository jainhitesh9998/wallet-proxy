package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.did.DidJwkDriver;
import io.vctrust.trust.core.did.DidKeyDriver;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TrustEvaluatorTest {

    static final String DID_KEY = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    TestPki.Issued iaca = TestPki.rootCa("CN=Utopia IACA,C=UT");
    TestPki.Issued ds = TestPki.documentSigner("CN=Utopia DS,C=UT", iaca);
    TestPki.Issued rogueIaca = TestPki.rootCa("CN=Rogue IACA,C=UT");
    TestPki.Issued rogueDs = TestPki.documentSigner("CN=Rogue DS,C=UT", rogueIaca);
    TestPki.Issued rpCa = TestPki.rootCa("CN=RP Access CA,C=UT");
    TestPki.Issued rp = TestPki.leaf("CN=Verifier,C=UT", rpCa, List.of("verifier.example"), null);

    TrustRegistry registry = new TrustRegistry();
    TrustEvaluator evaluator;
    ClientProfile all = ClientProfile.anonymous(Set.of());

    @BeforeEach
    void setUp() {
        Provenance prov = Provenance.of("test", "static", "utopia", "https://lists.example/utopia", Instant.now());
        var issuer = TrustedEntity.builder("utopia-dmv").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://issuer.example/utopia")
                .authorization(CredentialAuthorization.of("mso_mdoc", "org.iso.18013.5.1.mDL"))
                .provenance(prov).build();
        var didIssuer = TrustedEntity.builder("did-issuer").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.DID, DID_KEY).provenance(prov).build();
        var revoked = TrustedEntity.builder("revoked").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://revoked.example").status(EntityStatus.REVOKED).provenance(prov).build();
        var otherFw = TrustedEntity.builder("other").framework("elsewhere").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://other.example").provenance(prov).build();
        var verifier = TrustedEntity.builder("rp").framework("utopia").role(EntityRole.VERIFIER)
                .identifier(IdentifierType.DNS, "verifier.example").provenance(prov).build();
        var anchors = List.of(
                new TrustAnchor(null, TrustDomain.MDOC_IACA, iaca.certificate(), "utopia", "utopia-dmv", null, null, prov),
                new TrustAnchor(null, TrustDomain.VERIFIER_ACCESS, rpCa.certificate(), "utopia", null, null, null, prov));
        registry.publish(new RegistrySnapshot(1, Instant.now(),
                List.of(new TrustFramework("utopia", "Utopia", null, null, null), new TrustFramework("elsewhere", "Elsewhere", null, null, null)),
                List.of(issuer, didIssuer, revoked, otherFw, verifier), anchors));
        evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of(new DidKeyDriver(), new DidJwkDriver())),
                new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1));
    }

    private TrustDecision eval(EntityRole role, String id, List<String> x5c, String kid, String format, String type, ClientProfile p) {
        return evaluator.evaluate(new TrustQuery(role, new TrustQuery.Subject(id, x5c, null, kid),
                new TrustQuery.Context("oid4vci", format, type, null, null, List.of())), p);
    }

    @Test
    void trustedIssuerByUrl() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://issuer.example/utopia/", List.of(), null, null, null, all);
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("utopia-dmv");
        assertThat(d.framework().id()).isEqualTo("utopia");
    }

    @Test
    void unknownIssuer() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://nobody.example", List.of(), null, null, null, all);
        assertThat(d.decision()).isEqualTo(Decision.UNKNOWN);
    }

    @Test
    void revokedIssuerIsNotTrusted() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://revoked.example", List.of(), null, null, null, all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("entity.status");
    }

    @Test
    void frameworkFilteringHidesEntities() {
        var utopiaOnly = new ClientProfile("w", "Wallet", Set.of("utopia"), false, true, false);
        assertThat(eval(EntityRole.CREDENTIAL_ISSUER, "https://other.example", List.of(), null, null, null, utopiaOnly).decision())
                .isEqualTo(Decision.UNKNOWN);
        assertThat(eval(EntityRole.CREDENTIAL_ISSUER, "https://other.example", List.of(), null, null, null, all).decision())
                .isEqualTo(Decision.TRUSTED);
    }

    @Test
    void mdocChainResolvesEntityViaAnchor() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, null, List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(d.decision()).as(d.reasons().toString()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("utopia-dmv");
        assertThat(d.evidence().x509().valid()).isTrue();
        assertThat(d.evidence().authorization().authorized()).isTrue();
    }

    @Test
    void mdocChainFromUnknownIacaIsUnknown() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, null, List.of(Certificates.toBase64(rogueDs.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(d.decision()).isEqualTo(Decision.UNKNOWN);
        assertThat(d.reasons()).extracting(Reason::code).contains("x509.no_anchor");
    }

    @Test
    void unauthorizedDoctypeIsNotTrusted() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://issuer.example/utopia", List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "eu.europa.ec.eudi.pid.1", all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("entity.not_authorized");
    }

    @Test
    void didIssuerWithKidChecksDidDocument() {
        String vm = DID_KEY + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        var ok = eval(EntityRole.CREDENTIAL_ISSUER, DID_KEY, List.of(), vm, "ldp_vc", null, all);
        assertThat(ok.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(ok.evidence().did().relationshipValid()).isTrue();
        var bad = eval(EntityRole.CREDENTIAL_ISSUER, DID_KEY, List.of(), DID_KEY + "#nope", "ldp_vc", null, all);
        assertThat(bad.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(bad.reasons()).extracting(Reason::code).contains("did.vm_not_found");
    }

    @Test
    void verifierX509Hash() {
        String hash = Certificates.sha256Thumbprint(rp.certificate());
        var x5c = List.of(Certificates.toBase64(rp.certificate()));
        var ok = eval(EntityRole.VERIFIER, "x509_hash:" + hash, x5c, null, null, null, all);
        assertThat(ok.decision()).as(ok.reasons().toString()).isEqualTo(Decision.TRUSTED);
        assertThat(ok.entity().id()).isEqualTo("rp");
        var mismatch = eval(EntityRole.VERIFIER, "x509_hash:AAAA", x5c, null, null, null, all);
        assertThat(mismatch.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(mismatch.reasons()).extracting(Reason::code).contains("client_id.x509_hash_mismatch");
    }

    @Test
    void verifierX509SanDnsAndResponseUri() {
        var x5c = List.of(Certificates.toBase64(rp.certificate()));
        var ok = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example", x5c, null, null),
                new TrustQuery.Context("oid4vp", null, null, null, "https://verifier.example/response", List.of())), all);
        assertThat(ok.decision()).isEqualTo(Decision.TRUSTED);
        var wrongSan = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:evil.example", x5c, null, null),
                TrustQuery.Context.EMPTY), all);
        assertThat(wrongSan.decision()).isEqualTo(Decision.NOT_TRUSTED);
        var noX5c = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example", List.of(), null, null),
                TrustQuery.Context.EMPTY), all);
        assertThat(noX5c.reasons()).extracting(Reason::code).contains("client_id.x5c_required");
    }

    @Test
    void trustedAuthoritiesAkiMatch() {
        String aki = Certificates.authorityKeyIdentifier(ds.certificate()).orElseThrow();
        var d = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(null, List.of(Certificates.toBase64(ds.certificate())), null, null),
                new TrustQuery.Context("oid4vp", "mso_mdoc", "org.iso.18013.5.1.mDL", null, null,
                        List.of(new TrustQuery.TrustedAuthority("aki", List.of(aki)),
                                new TrustQuery.TrustedAuthority("etsi_tl", List.of("https://lists.example/utopia")),
                                new TrustQuery.TrustedAuthority("aki", List.of("nope"))))), all);
        assertThat(d.evidence().trustedAuthorities()).extracting(TrustDecision.TrustedAuthorityMatch::matched)
                .containsExactly(true, true, false);
    }
}
