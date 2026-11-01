package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.support.Cose;
import io.vctrust.trust.adapters.vical.VicalSourceFactory;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.Test;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VicalSourceTest {

    static final CBORMapper CBOR = CBORMapper.builder().build();

    static byte[] vical(TestPki.Issued signer, List<TestPki.Issued> iacas, boolean tamper) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("version", "1.0");
        payload.put("vicalProvider", "Test VICAL Provider");
        payload.put("date", "2026-10-01T00:00:00Z");
        payload.put("vicalIssueID", 7);
        List<Map<String, Object>> infos = new java.util.ArrayList<>();
        for (TestPki.Issued i : iacas) {
            Map<String, Object> ci = new LinkedHashMap<>();
            ci.put("certificate", Certificates.der(i.certificate()));
            ci.put("serialNumber", i.certificate().getSerialNumber());
            ci.put("docType", List.of("org.iso.18013.5.1.mDL"));
            ci.put("issuingAuthority", "Utopia DMV");
            ci.put("issuingCountry", "UT");
            infos.add(ci);
        }
        payload.put("certificateInfos", infos);
        byte[] payloadBytes = CBOR.writeValueAsBytes(payload);
        byte[] prot = CBOR.writeValueAsBytes(Map.of(1, -7));
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(signer.keys().getPrivate());
        s.update(Cose.sigStructure(prot, payloadBytes));
        byte[] sig = s.sign();
        if (tamper) {
            payloadBytes[payloadBytes.length - 1] ^= 1;
        }
        return CBOR.writeValueAsBytes(List.of(prot, Map.of(33, Certificates.der(signer.certificate())), payloadBytes, sig));
    }

    @Test
    void parsesSignedVical() throws Exception {
        var root = TestPki.rootCa("CN=VICAL Root,C=US");
        var signer = TestPki.leaf("CN=VICAL Signer,C=US", root, List.of(), "1.0.18013.5.1.8");
        var iaca = TestPki.rootCa("CN=Utopia IACA,C=UT");
        var ctx = new TestContext().put("mem:vical", vical(signer, List.of(iaca), false));
        var def = new SourceDefinition("v", "vical", "aamva", null, true, Map.of("location", "mem:vical",
                "signerCertificates", List.of(Certificates.toPem(root.certificate()))));
        var r = new VicalSourceFactory().create(def, ctx).load();
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
        assertThat(r.listInfo().issuer()).isEqualTo("Test VICAL Provider");
        assertThat(r.anchors()).singleElement().satisfies(a -> {
            assertThat(a.domain()).isEqualTo(TrustDomain.MDOC_IACA);
            assertThat(a.docTypes()).containsExactly("org.iso.18013.5.1.mDL");
        });
        assertThat(r.entities()).singleElement().satisfies(e -> {
            assertThat(e.displayName("en")).isEqualTo("Utopia DMV");
            assertThat(e.isAuthorizedFor("mso_mdoc", "org.iso.18013.5.1.mDL", true)).isTrue();
        });
    }

    @Test
    void rejectsTamperedOrUntrustedVical() throws Exception {
        var root = TestPki.rootCa("CN=VICAL Root,C=US");
        var signer = TestPki.leaf("CN=VICAL Signer,C=US", root, List.of(), null);
        var iaca = TestPki.rootCa("CN=IACA,C=UT");
        var tampered = new TestContext().put("mem:vical", vical(signer, List.of(iaca), true));
        var def = new SourceDefinition("v", "vical", "f", null, true, Map.of("location", "mem:vical",
                "signerCertificates", List.of(Certificates.toPem(root.certificate()))));
        assertThatThrownBy(() -> new VicalSourceFactory().create(def, tampered).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("signature is invalid");
        var other = TestPki.rootCa("CN=Other,C=US");
        var untrusted = new TestContext().put("mem:vical", vical(signer, List.of(iaca), false));
        var def2 = new SourceDefinition("v", "vical", "f", null, true, Map.of("location", "mem:vical",
                "signerCertificates", List.of(Certificates.toPem(other.certificate()))));
        assertThatThrownBy(() -> new VicalSourceFactory().create(def2, untrusted).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("not trusted");
    }
}
