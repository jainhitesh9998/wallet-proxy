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
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        XMLSignatureFactory f = XMLSignatureFactory.getInstance("DOM");
        var ref = f.newReference("", f.newDigestMethod(DigestMethod.SHA256, null),
                List.of(f.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        f.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)), null, null);
        var si = f.newSignedInfo(f.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                f.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null), List.of(ref));
        var kif = f.getKeyInfoFactory();
        var ki = kif.newKeyInfo(List.of(kif.newX509Data(List.of(signer.certificate()))));
        f.newXMLSignature(si, ki).sign(new DOMSignContext(signer.keys().getPrivate(), doc.getDocumentElement()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }

    @Test
    void mapsEaaServicesToCredentialIssuerAnchors() throws Exception {
        var eaa = TestPki.rootCa("CN=QEAA CA,C=UT");
        var qc = TestPki.rootCa("CN=QC CA,C=UT");
        var ctx = new TestContext().put("https://tl.example/ut.xml",
                nationalTl(Certificates.toBase64(eaa.certificate()), Certificates.toBase64(qc.certificate())));
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("tl", "etsi-tl", "eu", null, true,
                Map.of("location", "https://tl.example/ut.xml")), ctx).load();
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
        var ctx = new TestContext();
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "classpath:etsi/eu-lotl.xml", "followPointers", false)), ctx).load();
        assertThat(r.listInfo().details().get("tslType")).isEqualTo("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists");
        assertThat((Integer) r.listInfo().details().get("pointers")).isGreaterThan(30);
        assertThat(r.listInfo().sequence()).isNotBlank();
    }

    @Test
    void followsLotlPointersWithTerritoryFilter() throws Exception {
        var ctx = new TestContext();
        // Every national TL is unreachable in the fake HTTP layer: the load must still succeed and report warnings.
        var r = new EtsiTrustedListSourceFactory().create(new SourceDefinition("lotl", "etsi-tl", "eu", null, true,
                Map.of("location", "classpath:etsi/eu-lotl.xml", "territories", List.of("AT", "BE"))), ctx).load();
        assertThat(r.warnings()).filteredOn(w -> w.startsWith("TL ")).hasSize(2)
                .allMatch(w -> w.startsWith("TL AT") || w.startsWith("TL BE"));
        assertThat(r.warnings()).anyMatch(w -> w.contains("signature not verified"));
    }
}
