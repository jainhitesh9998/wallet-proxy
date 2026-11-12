package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.etsi.EtsiTrustedListSourceFactory;
import io.vctrust.trust.adapters.lote.LoteSourceFactory;
import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.adapters.vical.VicalSourceFactory;
import io.vctrust.trust.adapters.x509.X509BundleSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSourceFactory;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What a source publishes as the location of its list ({@code Provenance.sourceUri}, the {@code trustedListUri}
 * constraint and attribute) reaches every client. A web location is published as it is; a location on the service's
 * own host is not published at all, unless the source names the list's public URI ({@code publicUri}).
 */
class PublishedLocationTest {

    /** Every local location below carries this, so that finding it anywhere in what a source produced is a leak. */
    static final String HOST_DIRECTORY = "trust-lists-7d2e";
    static final List<String> LOCAL = List.of("file:/srv/" + HOST_DIRECTORY + "/list", "/srv/" + HOST_DIRECTORY + "/list",
            "classpath:" + HOST_DIRECTORY + "/list");
    static final String REMOTE = "https://lists.example/list";
    static final String PUBLIC_URI = "https://lists.example/published";

    /**
     * One adapter with a list it loads: the list's bytes, the properties it needs besides its location, the property
     * that names the location, and whether it also writes the location as {@code trustedListUri}.
     */
    record Fixture(String type, TrustSourceFactory factory, byte[] list, Map<String, Object> properties, String locationKey,
                   boolean trustedListUri) {

        SourceDefinition definition(String location, String publicUri) {
            Map<String, Object> p = new LinkedHashMap<>(properties);
            p.put(locationKey, location);
            if (publicUri != null) {
                p.put("publicUri", publicUri);
            }
            return new SourceDefinition("src-" + type, type, "fw", null, true, p);
        }

        SourceLoadResult load(String location, String publicUri) throws Exception {
            return factory.create(definition(location, publicUri), new TestContext().put(location, list)).load();
        }
    }

    static List<Fixture> fixtures() throws Exception {
        var ca = TestPki.rootCa("CN=Listed CA,C=UT");
        String pem = Certificates.toPem(ca.certificate());
        String registry = """
                entities:
                  - {id: listed, roles: [CREDENTIAL_ISSUER], identifiers: ["https://issuer.example"]}
                anchors:
                  - domain: mdoc-iaca
                    entity: listed
                    certificate: |
                %s
                """.formatted(pem.indent(6));
        var vicalRoot = TestPki.rootCa("CN=VICAL Root,C=US");
        var vicalSigner = TestPki.leaf("CN=VICAL Signer,C=US", vicalRoot, List.of(), "1.0.18013.5.1.8");
        var tlSigner = TestPki.rootCa("CN=TL Signer,C=UT");
        String b64 = Certificates.toBase64(ca.certificate());
        return List.of(
                new Fixture("static", new StaticTrustSourceFactory(), registry.getBytes(StandardCharsets.UTF_8), Map.of(), "location", false),
                new Fixture("x509-bundle", new X509BundleSourceFactory(), pem.getBytes(StandardCharsets.US_ASCII),
                        Map.of("domain", "mdoc-iaca", "sha256", List.of(Certificates.sha256Thumbprint(ca.certificate()))),
                        "certificateLocation", false),
                new Fixture("vical", new VicalSourceFactory(), VicalSourceTest.vical(vicalSigner, List.of(ca), false),
                        Map.of("signerCertificates", List.of(Certificates.toPem(vicalRoot.certificate()))), "location", true),
                new Fixture("etsi-tl", new EtsiTrustedListSourceFactory(), EtsiTrustedListSourceTest.sign(EtsiTrustedListSourceTest.nationalTl(b64, b64), tlSigner),
                        Map.of("signerCertificates", List.of(Certificates.toPem(tlSigner.certificate()))), "location", true),
                new Fixture("etsi-lote", new LoteSourceFactory(), LoteSourceTest.lote(b64, "2099-01-01T00:00:00Z").getBytes(StandardCharsets.UTF_8),
                        Map.of("allowUnverified", true), "location", true));
    }

    /** What every entity and anchor of {@code r} says about where it came from: {@code expected}, or nothing when that is null. */
    static void publishes(SourceLoadResult r, Fixture f, String expected, String as) {
        assertThat(r.entities().size() + r.anchors().size()).as(as + ": records").isPositive();
        for (var e : r.entities()) {
            assertThat(e.provenance()).as(as).extracting(Provenance::sourceUri).isEqualTo(expected);
            if (expected == null || !f.trustedListUri()) {
                assertThat(e.attributes()).as(as).doesNotContainKey("trustedListUri");
            } else {
                assertThat(e.attributes()).as(as).containsEntry("trustedListUri", expected);
            }
        }
        for (var a : r.anchors()) {
            assertThat(a.provenance()).as(as).extracting(Provenance::sourceUri).isEqualTo(expected);
            if (expected == null || !f.trustedListUri()) {
                assertThat(a.constraints()).as(as).doesNotContainKey("trustedListUri");
            } else {
                assertThat(a.constraints()).as(as).containsEntry("trustedListUri", expected);
            }
        }
        assertThat(r.entities().toString() + r.anchors()).as(as + ": anything naming the host's directory").doesNotContain(HOST_DIRECTORY);
    }

    @Test
    void aLocationOnTheServicesHostIsNotPublished() throws Exception {
        for (Fixture f : fixtures()) {
            for (String location : LOCAL) {
                publishes(f.load(location, null), f, null, f.type() + " from " + location);
            }
        }
    }

    @Test
    void aSourceThatLoadsALocalCopyPublishesTheListsPublicUri() throws Exception {
        for (Fixture f : fixtures()) {
            for (String location : LOCAL) {
                publishes(f.load(location, PUBLIC_URI), f, PUBLIC_URI, f.type() + " from " + location + " with publicUri");
            }
            // A mirror reached over the network is not what clients know the list by either.
            publishes(f.load(REMOTE, PUBLIC_URI), f, PUBLIC_URI, f.type() + " from " + REMOTE + " with publicUri");
        }
    }

    @Test
    void aWebLocationIsPublishedAsItIs() throws Exception {
        for (Fixture f : fixtures()) {
            publishes(f.load(REMOTE, null), f, REMOTE, f.type() + " from " + REMOTE);
        }
    }

    @Test
    void aPublicUriThatIsNotAWebUrlIsAConfigurationErrorNamingTheSource() throws Exception {
        for (Fixture f : fixtures()) {
            for (String bad : List.of("file:/srv/list.xml", "/srv/list.xml", "classpath:list.xml", "ftp://lists.example/list.xml",
                    "https://", "https:///list.xml", "https://lists example/list.xml", "")) {
                assertThatThrownBy(() -> f.factory().create(f.definition(LOCAL.getFirst(), bad), new TestContext()))
                        .as(f.type() + " with publicUri '" + bad + "'").isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("Source 'src-" + f.type() + "'").hasMessageContaining("publicUri");
            }
        }
    }

    @Test
    void theListsALocalListOfListsPointsToKeepTheirOwnLocations() throws Exception {
        var ca = TestPki.rootCa("CN=QEAA CA,C=UT");
        var lotlSigner = TestPki.rootCa("CN=LOTL Signer,C=EU");
        var tlSigner = TestPki.rootCa("CN=TL Signer,C=UT");
        String b64 = Certificates.toBase64(ca.certificate());
        String lotl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="lotl">
                  <SchemeInformation>
                    <TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>3</TSLSequenceNumber>
                    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
                    <SchemeOperatorName><Name xml:lang="en">Test Commission</Name></SchemeOperatorName>
                    <SchemeTerritory>EU</SchemeTerritory>
                    <PointersToOtherTSL>
                      <OtherTSLPointer>
                        <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId><X509Certificate>%s</X509Certificate></DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
                        <TSLLocation>https://tl.example/ut.xml</TSLLocation>
                        <AdditionalInformation>
                          <OtherInformation><SchemeTerritory>UT</SchemeTerritory></OtherInformation>
                          <OtherInformation><MimeType>application/vnd.etsi.tsl+xml</MimeType></OtherInformation>
                        </AdditionalInformation>
                      </OtherTSLPointer>
                    </PointersToOtherTSL>
                    <ListIssueDateTime>2026-10-01T00:00:00Z</ListIssueDateTime>
                    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
                  </SchemeInformation>
                </TrustServiceStatusList>
                """.formatted(Certificates.toBase64(tlSigner.certificate())).trim();
        String location = "file:/srv/" + HOST_DIRECTORY + "/eu-lotl.xml";
        var ctx = new TestContext().put(location, EtsiTrustedListSourceTest.sign(lotl, lotlSigner))
                .put("https://tl.example/ut.xml", EtsiTrustedListSourceTest.sign(EtsiTrustedListSourceTest.nationalTl(b64, b64), tlSigner));
        var def = new SourceDefinition("lotl", "etsi-tl", "eu", null, true, Map.of("location", location,
                "publicUri", "https://ec.europa.eu/tools/lotl/eu-lotl.xml", "signerCertificates", List.of(Certificates.toPem(lotlSigner.certificate()))));
        SourceLoadResult r = new EtsiTrustedListSourceFactory().create(def, ctx).load();
        // The national list was fetched from where the list of lists points: that is its location, not the mirror's publicUri.
        assertThat(r.warnings()).isEmpty();
        Fixture etsi = new Fixture("etsi-tl", new EtsiTrustedListSourceFactory(), new byte[0], Map.of(), "location", true);
        publishes(r, etsi, "https://tl.example/ut.xml", "national list behind a local list of lists");
    }

    @Test
    void anAnchorFromAMirroredListMatchesTrustedAuthoritiesByItsPublicUri() throws Exception {
        var ca = TestPki.rootCa("CN=QEAA CA,C=UT");
        var signer = TestPki.leaf("CN=QEAA Signer,C=UT", ca, List.of(), null);
        var tlSigner = TestPki.rootCa("CN=TL Signer,C=UT");
        String b64 = Certificates.toBase64(ca.certificate());
        String location = "file:/srv/" + HOST_DIRECTORY + "/ut.xml";
        String publicUri = "https://tl.example/ut.xml";
        var ctx = new TestContext().put(location, EtsiTrustedListSourceTest.sign(EtsiTrustedListSourceTest.nationalTl(b64, b64), tlSigner));
        var query = new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(null, List.of(Certificates.toBase64(signer.certificate())), null, null),
                new TrustQuery.Context("oid4vp", "dc+sd-jwt", null, null, null, List.of(
                        new TrustQuery.TrustedAuthority("etsi_tl", List.of(publicUri)),
                        new TrustQuery.TrustedAuthority("etsi_tl", List.of(location)))));

        Map<String, Object> mirrored = new LinkedHashMap<>(Map.of("location", location, "publicUri", publicUri,
                "signerCertificates", List.of(Certificates.toPem(tlSigner.certificate()))));
        TrustDecision d = evaluator(new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true, mirrored), ctx).load())
                .evaluate(query, ClientProfile.unrestricted("test"));
        assertThat(d.evidence().x509().anchorFound()).isTrue();
        assertThat(d.evidence().trustedAuthorities()).extracting(TrustDecision.TrustedAuthorityMatch::matched, TrustDecision.TrustedAuthorityMatch::matchedValue)
                .containsExactly(org.assertj.core.groups.Tuple.tuple(true, publicUri), org.assertj.core.groups.Tuple.tuple(false, null));

        // Without publicUri nothing names the list: neither its public URI nor the file it was read from matches. A
        // query naming a path cannot learn where the service keeps its lists.
        mirrored.remove("publicUri");
        TrustDecision unnamed = evaluator(new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true, mirrored), ctx).load())
                .evaluate(query, ClientProfile.unrestricted("test"));
        assertThat(unnamed.evidence().x509().anchorFound()).isTrue();
        assertThat(unnamed.evidence().trustedAuthorities()).extracting(TrustDecision.TrustedAuthorityMatch::matched).containsExactly(false, false);
    }

    static TrustEvaluator evaluator(SourceLoadResult r) {
        TrustRegistry registry = new TrustRegistry();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("eu", "EU", null, null, null)), r.entities(), r.anchors()));
        return new TrustEvaluator(registry, null, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1));
    }
}
