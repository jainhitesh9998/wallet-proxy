package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.etsi.EtsiTrustedListSourceFactory;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EtsiTrustedListSourceTest {

    /** A date within the validity of the checked-in list of lists (issued 2026-10-15, next update 2027-04-07). */
    static final String LOTL_READ_AT = "2026-11-01T00:00:00Z";

    static String nationalTl(String eaaCert, String caCert) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/19612/TSLTag">
                  <SchemeInformation>
                    <TSLVersionIdentifier>6</TSLVersionIdentifier><TSLSequenceNumber>12</TSLSequenceNumber>
                    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
                    <SchemeOperatorName><Name xml:lang="en">Utopia Supervisory Body</Name></SchemeOperatorName>
                    <SchemeTerritory>UT</SchemeTerritory>
                    <ListIssueDateTime>2026-10-01T00:00:00Z</ListIssueDateTime>
                    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
                  </SchemeInformation>
                  <TrustServiceProviderList>
                    <TrustServiceProvider>
                      <TSPInformation><TSPName><Name xml:lang="en">Utopia QEAA Provider</Name></TSPName></TSPInformation>
                      <TSPServices>
                        <TSPService><ServiceInformation>
                          <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/EAA/Q</ServiceTypeIdentifier>
                          <ServiceName><Name xml:lang="en">QEAA issuance</Name></ServiceName>
                          <ServiceDigitalIdentity><DigitalId><X509Certificate>%s</X509Certificate></DigitalId></ServiceDigitalIdentity>
                          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                          <StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime>
                        </ServiceInformation></TSPService>
                      </TSPServices>
                    </TrustServiceProvider>
                    <TrustServiceProvider>
                      <TSPInformation><TSPName><Name xml:lang="en">Plain QTSP</Name></TSPName></TSPInformation>
                      <TSPServices>
                        <TSPService><ServiceInformation>
                          <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                          <ServiceName><Name xml:lang="en">QC CA</Name></ServiceName>
                          <ServiceDigitalIdentity><DigitalId><X509Certificate>%s</X509Certificate></DigitalId></ServiceDigitalIdentity>
                          <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
                        </ServiceInformation></TSPService>
                      </TSPServices>
                    </TrustServiceProvider>
                  </TrustServiceProviderList>
                </TrustServiceStatusList>
                """.formatted(eaaCert, caCert).trim();
    }

    static byte[] sign(String xml, TestPki.Issued signer) throws Exception {
        return sign(xml, signer, "");
    }

    static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    static byte[] bytes(Document doc) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }

    /** Signs the list with an enveloped signature whose reference is {@code referenceUri}: "" or "#" and the root's Id. */
    static byte[] sign(String xml, TestPki.Issued signer, String referenceUri) throws Exception {
        Document doc = parse(xml.getBytes(StandardCharsets.UTF_8));
        if (doc.getDocumentElement().hasAttribute("Id")) {
            doc.getDocumentElement().setIdAttribute("Id", true);
        }
        XMLSignatureFactory f = XMLSignatureFactory.getInstance("DOM");
        var ref = f.newReference(referenceUri, f.newDigestMethod(DigestMethod.SHA256, null),
                List.of(f.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        f.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)), null, null);
        var si = f.newSignedInfo(f.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                f.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null), List.of(ref));
        var kif = f.getKeyInfoFactory();
        var ki = kif.newKeyInfo(List.of(kif.newX509Data(List.of(signer.certificate()))));
        f.newXMLSignature(si, ki).sign(new DOMSignContext(signer.keys().getPrivate(), doc.getDocumentElement()));
        return bytes(doc);
    }

    static SourceDefinition pinned(TestPki.Issued signer, Map<String, Object> more) {
        Map<String, Object> properties = new java.util.LinkedHashMap<>(more);
        properties.put("location", "mem:tl");
        properties.put("signerCertificates", List.of(Certificates.toPem(signer.certificate())));
        return new SourceDefinition("tl", "etsi-tl", "eu", null, true, properties);
    }

    @Test
    void mapsEaaServicesToCredentialIssuerAnchors() throws Exception {
        var eaa = TestPki.rootCa("CN=QEAA CA,C=UT");
        var qc = TestPki.rootCa("CN=QC CA,C=UT");
        var ctx = new TestContext().put("https://tl.example/ut.xml",
                nationalTl(Certificates.toBase64(eaa.certificate()), Certificates.toBase64(qc.certificate())));
        // Unsigned, or signed by nobody the operator pinned: refused unless the operator accepts the transport alone.
        assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "https://tl.example/ut.xml")), ctx).load()).isInstanceOf(TrustSourceException.class).hasMessageContaining("not signed");
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "https://tl.example/ut.xml", "allowUnverified", true)), ctx).load();
        assertThat(r.entities()).singleElement().satisfies(e -> {
            assertThat(e.displayName("en")).isEqualTo("Utopia QEAA Provider");
            assertThat(e.hasRole(EntityRole.CREDENTIAL_ISSUER)).isTrue();
            assertThat(e.attributes()).containsEntry("trustedListUri", "https://tl.example/ut.xml");
        });
        assertThat(r.anchors()).singleElement().satisfies(a -> assertThat(a.domain()).isEqualTo(TrustDomain.CREDENTIAL_ISSUER));
        assertThat(r.listInfo().sequence()).isEqualTo("12");
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.NOT_SIGNED);
    }

    @Test
    void verifiesXmlSignatureAgainstPinnedSigner() throws Exception {
        var eaa = TestPki.rootCa("CN=QEAA CA,C=UT");
        var signer = TestPki.rootCa("CN=TL Signer,C=UT");
        byte[] signed = sign(nationalTl(Certificates.toBase64(eaa.certificate()), Certificates.toBase64(eaa.certificate())), signer);
        var ctx = new TestContext().put("mem:tl", signed);
        var ok = new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "mem:tl", "signerCertificates", List.of(Certificates.toPem(signer.certificate())))), ctx).load();
        assertThat(ok.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);

        String tampered = new String(signed, StandardCharsets.UTF_8).replace("Utopia QEAA Provider", "Evil QEAA Provider");
        var bad = new TestContext().put("mem:tl", tampered);
        assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "mem:tl", "signerCertificates", List.of(Certificates.toPem(signer.certificate())))), bad).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("signature");
        var other = TestPki.rootCa("CN=Someone else,C=UT");
        assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "mem:tl", "signerCertificates", List.of(Certificates.toPem(other.certificate())))), ctx).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("not trusted");
    }

    @Test
    void parsesTheRealEuLotlPointers() throws Exception {
        var ctx = new TestContext().at(LOTL_READ_AT);
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "classpath:etsi/eu-lotl.xml", "followPointers", false, "allowUnverified", true)), ctx).load();
        assertThat(r.listInfo().details().get("tslType")).isEqualTo("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists");
        assertThat((Integer) r.listInfo().details().get("pointers")).isGreaterThan(30);
        assertThat(r.listInfo().sequence()).isNotBlank();
    }

    @Test
    void followsLotlPointersWithTerritoryFilter() throws Exception {
        var ctx = new TestContext().at(LOTL_READ_AT);
        // Every national TL is unreachable in the fake HTTP layer: the load must still succeed and report warnings.
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "classpath:etsi/eu-lotl.xml", "territories", List.of("AT", "BE"), "allowUnverified", true)), ctx).load();
        assertThat(r.warnings()).filteredOn(w -> w.startsWith("TL ")).hasSize(2)
                .allMatch(w -> w.startsWith("TL AT") || w.startsWith("TL BE"));
        assertThat(r.warnings()).anyMatch(w -> w.contains("signature not verified"));
    }

    @Test
    void aSignedListCarriedInsideAnotherDocumentSignsNothingOfIt() throws Exception {
        var genuineCa = TestPki.rootCa("CN=QEAA CA,C=UT");
        var evilCa = TestPki.rootCa("CN=Evil CA,C=UT");
        var signer = TestPki.rootCa("CN=TL Signer,C=UT");
        String genuine = nationalTl(Certificates.toBase64(genuineCa.certificate()), Certificates.toBase64(genuineCa.certificate()));
        String evil = nationalTl(Certificates.toBase64(evilCa.certificate()), Certificates.toBase64(evilCa.certificate()))
                .replace("Utopia QEAA Provider", "Evil QEAA Provider");
        for (String referenceUri : List.of("#tsl", "")) {
            byte[] signed = sign(genuine, signer, referenceUri);
            assertThat(new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of()), new TestContext().put("mem:tl", signed)).load()
                    .listInfo().signature()).as("reference %s", referenceUri).isEqualTo(ListInfo.SignatureStatus.VERIFIED);

            // The attacker's list as the document, the genuine signed list moved inside it untouched.
            for (String rootId : List.of("other", "tsl", "")) {
                Document wrapped = parse(evil.replace(" Id=\"tsl\"", rootId.isEmpty() ? "" : " Id=\"" + rootId + "\"").getBytes(StandardCharsets.UTF_8));
                wrapped.getDocumentElement().appendChild(wrapped.importNode(parse(signed).getDocumentElement(), true));
                var ctx = new TestContext().put("mem:tl", bytes(wrapped));
                assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of()), ctx).load())
                        .as("reference %s, wrapping root Id '%s'", referenceUri, rootId).isInstanceOf(TrustSourceException.class)
                        .hasMessageContaining("not signed");
            }

            // The genuine signature lifted out and placed directly under the attacker's root, the signed list beside it.
            Document lifted = parse(evil.replace(" Id=\"tsl\"", "").getBytes(StandardCharsets.UTF_8));
            var inner = (org.w3c.dom.Element) lifted.importNode(parse(signed).getDocumentElement(), true);
            var signature = inner.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
            inner.removeChild(signature);
            lifted.getDocumentElement().appendChild(inner);
            lifted.getDocumentElement().appendChild(signature);
            var ctx = new TestContext().put("mem:tl", bytes(lifted));
            assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of()), ctx).load())
                    .as("reference %s, signature lifted to the root", referenceUri).isInstanceOf(TrustSourceException.class)
                    .hasMessageContaining("signature");
        }
    }

    @Test
    void theRealListOfListsVerifiesAgainstItsOwnSigner() throws Exception {
        // An XAdES signature as the EU publishes it: a reference to the document and one to its signed properties.
        byte[] lotl;
        try (var in = getClass().getResourceAsStream("/etsi/eu-lotl.xml")) {
            lotl = in.readAllBytes();
        }
        var certificate = parse(lotl).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate").item(0);
        String signer = "-----BEGIN CERTIFICATE-----\n" + certificate.getTextContent().replaceAll("\\s", "") + "\n-----END CERTIFICATE-----";
        var definition = new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "classpath:etsi/eu-lotl.xml", "followPointers", false, "signerCertificates", List.of(signer)));
        var r = new EtsiTrustedListSourceFactory().create(definition, new TestContext().at(LOTL_READ_AT)).load();
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);

        // One character of a pointer changed: the signature no longer covers what is read.
        String tampered = new String(lotl, StandardCharsets.UTF_8).replaceFirst("<TSLLocation>https://", "<TSLLocation>https://evil.");
        var bad = new TestContext().at(LOTL_READ_AT).put("mem:lotl", tampered);
        var badDefinition = new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "mem:lotl", "followPointers", false, "signerCertificates", List.of(signer)));
        assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(badDefinition, bad).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("signature");
    }

    @Test
    void aListPastItsNextUpdateIsNotLoaded() throws Exception {
        var ca = TestPki.rootCa("CN=QEAA CA,C=UT");
        var signer = TestPki.rootCa("CN=TL Signer,C=UT");
        String expired = nationalTl(Certificates.toBase64(ca.certificate()), Certificates.toBase64(ca.certificate()))
                .replace("2099-01-01T00:00:00Z", "2026-10-15T00:00:00Z");
        var ctx = new TestContext().put("mem:tl", sign(expired, signer));
        // Validly signed, and possibly from before a provider was withdrawn: whoever serves the list can serve it again.
        assertThatThrownBy(() -> new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of()), ctx).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("past its NextUpdate");
        var allowed = new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of("allowExpired", true)), ctx).load();
        assertThat(allowed.anchors()).isNotEmpty();
        assertThat(allowed.warnings()).anyMatch(w -> w.contains("past its NextUpdate"));
    }

    @Test
    void aListOlderThanTheOneLoadedBeforeIsRefused() throws Exception {
        var ca = TestPki.rootCa("CN=QEAA CA,C=UT");
        var signer = TestPki.rootCa("CN=TL Signer,C=UT");
        String current = nationalTl(Certificates.toBase64(ca.certificate()), Certificates.toBase64(ca.certificate()));
        String earlier = current.replace("<TSLSequenceNumber>12<", "<TSLSequenceNumber>11<").replace("2026-10-01T00:00:00Z", "2026-09-01T00:00:00Z");
        var ctx = new TestContext().put("mem:tl", sign(current, signer));
        var source = new EtsiTrustedListSourceFactory().create(pinned(signer, Map.of()), ctx);
        assertThat(source.load().listInfo().sequence()).isEqualTo("12");
        ctx.put("mem:tl", sign(earlier, signer));
        assertThatThrownBy(source::load).isInstanceOf(TrustSourceException.class).hasMessageContaining("older than the one already loaded");
        ctx.put("mem:tl", sign(current, signer));
        assertThat(source.load().listInfo().sequence()).isEqualTo("12");
    }
}
