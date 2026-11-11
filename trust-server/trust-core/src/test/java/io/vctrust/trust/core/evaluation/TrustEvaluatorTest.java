package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.did.DidJwkDriver;
import io.vctrust.trust.core.did.DidKeyDriver;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    ClientProfile all = ClientProfile.unrestricted("test");

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
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://issuer.example/utopia", List.of(), null, null, null, all);
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("utopia-dmv");
        assertThat(d.framework().id()).isEqualTo("utopia");
    }

    @Test
    void issuerIdentifiersAreComparedByteForByte() {
        // RFC 8414 section 3.3, OpenID4VCI 1.0 section 12.2.1: no normalization; another spelling is another identifier.
        for (String other : List.of("https://issuer.example/utopia/", "HTTPS://issuer.example/utopia", "https://Issuer.Example/utopia",
                "https://issuer.example:443/utopia", "https://issuer.example/x/../utopia")) {
            assertThat(eval(EntityRole.CREDENTIAL_ISSUER, other, List.of(), null, null, null, all).decision()).as(other).isEqualTo(Decision.UNKNOWN);
        }
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

    // ---- identifiers are bound to the presented key (mirrors packages/trust-client/test/binding.test.ts) ----

    @Test
    void certificateOutsideTheAnchorsCannotClaimARegisteredDnsName() {
        TestPki.Issued rogueCa = TestPki.rootCa("CN=Rogue RP CA,C=UT");
        TestPki.Issued fake = TestPki.leaf("CN=Verifier,C=UT", rogueCa, List.of("verifier.example"), null);
        var d = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example",
                List.of(Certificates.toBase64(fake.certificate()), Certificates.toBase64(rogueCa.certificate())), null, null),
                new TrustQuery.Context("oid4vp", null, null, null, "https://verifier.example/cb", List.of())), all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("identifier.unbound");
        assertThat(d.entity()).isNull();
        var real = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example",
                List.of(Certificates.toBase64(rp.certificate())), null, null),
                new TrustQuery.Context("oid4vp", null, null, null, "https://verifier.example/cb", List.of())), all);
        assertThat(real.decision()).as(real.reasons().toString()).isEqualTo(Decision.TRUSTED);
    }

    @Test
    void issuerIdentifierIsNotBoundToAnUnanchoredChain() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://issuer.example/utopia", List.of(Certificates.toBase64(rogueDs.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("identifier.unbound");
    }

    @Test
    void identifierOfAnotherEntityThanTheAnchorsIsRefused() {
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://other.example", List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("identifier.unbound");
    }

    @Test
    void didIdentifierSignedWithAKeyOfAnotherDidIsRefused() {
        String other = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        var d = eval(EntityRole.CREDENTIAL_ISSUER, DID_KEY, List.of(), other + "#0", "ldp_vc", null, all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("identifier.unbound");
    }

    @Test
    void everyAssertedTypeMustBeAuthorized() {
        var strict = new ClientProfile("v", "Verifier", Set.of(ClientProfile.ALL_FRAMEWORKS), true, true, false);
        var q = new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject("https://issuer.example/utopia", List.of(), null, null),
                new TrustQuery.Context("oid4vci", "mso_mdoc", "org.iso.18013.5.1.mDL", null, null, List.of(),
                        List.of("org.iso.18013.5.1.mDL", "eu.europa.ec.eudi.pid.1")));
        var d = evaluator.evaluate(q, strict);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).anyMatch(r -> r.code().equals("entity.not_authorized") && r.message().contains("eu.europa.ec.eudi.pid.1"));
    }

    @Test
    void certificateAndDidKeyTogetherAreRefused() {
        var d = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:verifier.example",
                List.of(Certificates.toBase64(rp.certificate())), null, DID_KEY + "#" + DID_KEY.substring("did:key:".length())),
                new TrustQuery.Context("oid4vp", null, null, null, null, List.of())), all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).extracting(Reason::code).contains("key.ambiguous");
    }

    @Test
    void frameworkAnchorNeverMakesAKeyBoundToOneEntityAnother() {
        Provenance prov = Provenance.of("test", "static", "utopia", null, Instant.now());
        var suspended = TrustedEntity.builder("b").framework("utopia").role(EntityRole.VERIFIER)
                .identifier(IdentifierType.DNS, "verifier.example").status(EntityStatus.SUSPENDED).provenance(prov).build();
        var active = TrustedEntity.builder("a").framework("utopia").role(EntityRole.VERIFIER)
                .identifier(IdentifierType.CLIENT_ID, "verifier-a").provenance(prov).build();
        var anchors = List.of(new TrustAnchor(null, TrustDomain.VERIFIER_ACCESS, rpCa.certificate(), "utopia", null, null, null, prov));
        registry.publish(new RegistrySnapshot(2, Instant.now(), List.of(new TrustFramework("utopia", "Utopia", null, null, null)),
                List.of(suspended, active), anchors));
        var d = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("verifier-a",
                List.of(Certificates.toBase64(rp.certificate())), null, null), TrustQuery.Context.EMPTY), all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.entity() == null ? null : d.entity().id()).isNotEqualTo("a");
    }

    @Test
    void aSharedAnchorDoesNotLendItsFrameworksIdentitiesToEveryCertificateBelowIt() {
        // An anchor a whole framework shares (one root for several issuers) proves that a certificate belongs to the
        // framework, never which of its members signed: a claimed identifier needs the certificate itself, or an
        // anchor tied to that one entity, to back it.
        Provenance prov = Provenance.of("test", "static", "utopia", null, Instant.now());
        var ministry = TrustedEntity.builder("ministry").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, "https://ministry.example").provenance(prov).build();
        var frameworks = List.of(new TrustFramework("utopia", "Utopia", null, null, null));
        registry.publish(new RegistrySnapshot(3, Instant.now(), frameworks, List.of(ministry),
                List.of(new TrustAnchor(null, TrustDomain.MDOC_IACA, iaca.certificate(), "utopia", null, null, null, prov))));
        var claimed = eval(EntityRole.CREDENTIAL_ISSUER, "https://ministry.example", List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(claimed.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(claimed.reasons()).extracting(Reason::code).contains("identifier.unbound");
        // Without the claim the chain stands on the anchor alone: trusted as a certificate of the framework, no entity.
        var chainOnly = eval(EntityRole.CREDENTIAL_ISSUER, null, List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(chainOnly.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(chainOnly.entity()).isNull();
        // An anchor that belongs to one entity names it.
        registry.publish(new RegistrySnapshot(4, Instant.now(), frameworks, List.of(ministry),
                List.of(new TrustAnchor(null, TrustDomain.MDOC_IACA, iaca.certificate(), "utopia", "ministry", null, null, prov))));
        var tied = eval(EntityRole.CREDENTIAL_ISSUER, "https://ministry.example", List.of(Certificates.toBase64(ds.certificate())), null,
                "mso_mdoc", "org.iso.18013.5.1.mDL", all);
        assertThat(tied.decision()).as(tied.reasons().toString()).isEqualTo(Decision.TRUSTED);
        assertThat(tied.entity().id()).isEqualTo("ministry");
    }

    @Test
    void aPinnedCertificateIsNotTrustedPastItsValidity() {
        // A certificate registered on an entity is a pin; no anchor checks it, so its own validity period must.
        Provenance prov = Provenance.of("test", "static", "utopia", null, Instant.now());
        TestPki.Issued selfCa = TestPki.rootCa("CN=Self,C=UT");
        TestPki.Issued expired = TestPki.leaf("CN=Old verifier,C=UT", selfCa, List.of("old.example"), null,
                Instant.now().minus(Duration.ofDays(800)), Instant.now().minus(Duration.ofDays(400)));
        TestPki.Issued current = TestPki.leaf("CN=Verifier,C=UT", selfCa, List.of("pinned.example"), null);
        var entity = TrustedEntity.builder("pinned").framework("utopia").role(EntityRole.VERIFIER)
                .certificate(expired.certificate()).certificate(current.certificate()).provenance(prov).build();
        registry.publish(new RegistrySnapshot(5, Instant.now(), List.of(new TrustFramework("utopia", "Utopia", null, null, null)), List.of(entity), List.of()));
        var old = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_hash:" + Certificates.sha256Thumbprint(expired.certificate()),
                List.of(Certificates.toBase64(expired.certificate())), null, null), TrustQuery.Context.EMPTY), all);
        assertThat(old.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(old.reasons()).extracting(Reason::code).contains("x509.pinned_expired");
        var ok = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_hash:" + Certificates.sha256Thumbprint(current.certificate()),
                List.of(Certificates.toBase64(current.certificate())), null, null), TrustQuery.Context.EMPTY), all);
        assertThat(ok.decision()).as(ok.reasons().toString()).isEqualTo(Decision.TRUSTED);
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

    // ---- on-demand registries are asked where the device asks them (mirrors packages/trust-client/test/binding.test.ts) ----

    static final String EBSI_DID = "did:ebsi:zParityIssuer4LkPq";
    static final String OTHER_DID = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";

    /** A registry too large for the snapshot (OpenID Federation, EBSI) that records what it is asked. */
    static final class OnDemandRegistry implements TrustSource, OnDemandResolver {
        final List<TrustedEntity> entities;
        final List<String> asked = new ArrayList<>();

        OnDemandRegistry(List<TrustedEntity> entities) {
            this.entities = entities;
        }

        @Override
        public SourceDefinition definition() {
            return new SourceDefinition("federation", "test", "utopia", null, true, Map.of());
        }

        @Override
        public SourceLoadResult load() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean canResolve(Identifier id) {
            // As the real resolvers: OpenID Federation entity ids, EBSI DIDs.
            return (id.type() == IdentifierType.DID && id.value().startsWith("did:ebsi:"))
                    || ((id.type() == IdentifierType.URL || id.type() == IdentifierType.FEDERATION_ENTITY) && id.value().startsWith("https://"));
        }

        @Override
        public Optional<TrustedEntity> resolve(Identifier id) {
            asked.add(id.toString());
            return entities.stream().filter(e -> e.identifiers().stream().anyMatch(i -> i.value().equals(id.value()))).findFirst();
        }
    }

    private OnDemandRegistry onDemand() {
        Provenance prov = Provenance.of("federation", "test", "utopia", "https://fed.example", Instant.now());
        var registry = new OnDemandRegistry(List.of(
                TrustedEntity.builder("fed-issuer").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                        .identifier(IdentifierType.URL, "https://fed.example/issuer").provenance(prov).build(),
                TrustedEntity.builder("fed-verifier").framework("utopia").role(EntityRole.VERIFIER)
                        .identifier(IdentifierType.URL, "https://fed.example").provenance(prov).build(),
                TrustedEntity.builder("fed-rp").framework("utopia").role(EntityRole.VERIFIER)
                        .identifier(IdentifierType.URL, "https://fed.example/rp").status(EntityStatus.REVOKED).provenance(prov).build(),
                TrustedEntity.builder("ebsi-issuer").framework("utopia").role(EntityRole.CREDENTIAL_ISSUER)
                        .identifier(IdentifierType.DID, EBSI_DID).provenance(prov).build()));
        // The manager publishes what its sources load into a registry of its own; the evaluator keeps the test snapshot.
        evaluator = new TrustEvaluator(this.registry, new TrustSourceManager(new TrustRegistry(), List.of(), List.of(registry), Clock.systemUTC()),
                new DidResolver(List.of(new DidKeyDriver(), new DidJwkDriver())), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1));
        return registry;
    }

    private TrustDecision verifier(String clientId, List<String> x5c) {
        return evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject(clientId, x5c, null, null),
                new TrustQuery.Context("oid4vp", null, null, null, null, List.of())), all);
    }

    @Test
    void asksAboutAnIssuerUrlMissingFromTheSnapshot() {
        var od = onDemand();
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://fed.example/issuer", List.of(), null, null, null, all);
        assertThat(od.asked.getFirst()).isEqualTo("URL:https://fed.example/issuer");
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("fed-issuer");
        assertThat(d.reasons()).extracting(Reason::code).contains("lookup.on_demand");
        assertThat(d.evidence().matchedIdentifiers()).containsExactly("URL:https://fed.example/issuer (on-demand)");
    }

    @Test
    void asksAboutTheOriginOfAnUnsignedDcApiRequest() {
        var od = onDemand();
        var d = verifier("origin:https://fed.example", List.of());
        assertThat(od.asked).containsExactly("URL:https://fed.example");
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("fed-verifier");
    }

    @Test
    void neverAsksAboutAPreRegisteredClientIdOrAPartyTheSnapshotKnows() {
        var od = onDemand();
        verifier("my-client", List.of());
        var known = eval(EntityRole.CREDENTIAL_ISSUER, "https://issuer.example/utopia", List.of(), null, null, null, all);
        assertThat(od.asked).isEmpty();
        assertThat(known.entity().id()).isEqualTo("utopia-dmv");
    }

    @Test
    void withAKeyAsksAboutTheKeysIdentifiersNotTheClaimedOne() {
        var od = onDemand();
        var d = eval(EntityRole.CREDENTIAL_ISSUER, "https://fed.example/issuer", List.of(), EBSI_DID + "#key-1", null, null, all);
        assertThat(od.asked).containsExactly("DID:" + EBSI_DID);
        assertThat(d.decision()).as(d.reasons().toString()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("ebsi-issuer");
        assertThat(d.reasons()).extracting(Reason::code).contains("did.unresolved");
    }

    @Test
    void neverAsksAboutADidThatIsAPublicKeyItself() {
        var od = onDemand();
        var d = eval(EntityRole.CREDENTIAL_ISSUER, OTHER_DID, List.of(), OTHER_DID + "#0", null, null, all);
        assertThat(od.asked).isEmpty();
        assertThat(d.decision()).isEqualTo(Decision.UNKNOWN);
    }

    @Test
    void responseUriHostIsReadAsOnTheDevice() {
        // java.net.URI has no host for "collector_1.example"; the check must not be skipped (mirrors binding.test.ts).
        TestPki.Issued leaf = TestPki.leaf("CN=unregistered.example,C=UT", rpCa, List.of("unregistered.example"), null);
        var d = evaluator.evaluate(new TrustQuery(EntityRole.VERIFIER, new TrustQuery.Subject("x509_san_dns:unregistered.example",
                List.of(Certificates.toBase64(leaf.certificate())), null, null),
                new TrustQuery.Context("oid4vp", null, null, null, "https://collector_1.example/cb", List.of())), all);
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("client_id.response_uri_host");
    }

    @Test
    void asksAboutAValidatedCertificatesUriNamesEvenWhenItsAnchorAloneIsTrusted() {
        var od = onDemand();
        TestPki.Issued fed = TestPki.leaf("CN=fed.example,C=UT", rpCa, List.of("https://fed.example/rp"), null);
        var d = verifier("x509_hash:" + Certificates.sha256Thumbprint(fed.certificate()), List.of(Certificates.toBase64(fed.certificate())));
        assertThat(od.asked).containsExactly("URL:https://fed.example/rp");
        assertThat(d.decision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(d.entity().id()).isEqualTo("fed-rp");
        assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
    }
}
