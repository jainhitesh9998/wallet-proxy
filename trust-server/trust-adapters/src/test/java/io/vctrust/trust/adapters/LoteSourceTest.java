package io.vctrust.trust.adapters;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import io.vctrust.trust.adapters.lote.LoteSourceFactory;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoteSourceTest {

    static String lote(String certB64, String nextUpdate) {
        return """
                {"LoTE":{"ListAndSchemeInformation":{"LoTEVersionIdentifier":1,"LoTESequenceNumber":3,
                  "LoTEType":"http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                  "SchemeOperatorName":[{"lang":"en","value":"Test Commission"}],"SchemeTerritory":"EU",
                  "ListIssueDateTime":"2026-10-01T00:00:00Z","NextUpdate":"%s"},
                 "TrustedEntitiesList":[{"TrustedEntityInformation":{"TEName":[{"lang":"en","value":"Utopia PID Provider"}]},
                   "TrustedEntityServices":[{"ServiceInformation":{"ServiceName":[{"lang":"en","value":"PID issuance"}],
                     "ServiceTypeIdentifier":"http://uri.etsi.org/19602/SvcType/PID/Issuance",
                     "ServiceDigitalIdentity":{"X509Certificates":[{"val":"%s"}]}}}]},
                  {"TrustedEntityInformation":{"TEName":[{"lang":"en","value":"Wallet Co"}]},
                   "TrustedEntityServices":[{"ServiceInformation":{"ServiceName":[{"lang":"en","value":"Wallet"}],
                     "ServiceTypeIdentifier":"http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
                     "ServiceDigitalIdentity":{"X509Certificates":[{"val":"%s"}]}}}]}]}}""".formatted(nextUpdate, certB64, certB64);
    }

    @Test
    void parsesUnsignedLote() throws Exception {
        var ca = TestPki.rootCa("CN=PID CA,C=UT");
        var ctx = new TestContext().put("mem:lote", lote(Certificates.toBase64(ca.certificate()), "2099-01-01T00:00:00Z"));
        // An unsigned list is loaded only when the operator says its transport is trusted.
        assertThatThrownBy(() -> new LoteSourceFactory().create(new SourceDefinition("l", "etsi-lote", "eudi", null, true,
                Map.of("location", "mem:lote")), ctx).load()).isInstanceOf(TrustSourceException.class).hasMessageContaining("not signed");
        var r = new LoteSourceFactory().create(new SourceDefinition("l", "etsi-lote", "eudi", null, true,
                Map.of("location", "mem:lote", "allowUnverified", true)), ctx).load();
        assertThat(r.entities()).hasSize(2);
        assertThat(r.entities().get(0).hasRole(EntityRole.CREDENTIAL_ISSUER)).isTrue();
        assertThat(r.entities().get(1).hasRole(EntityRole.WALLET_PROVIDER)).isTrue();
        assertThat(r.anchors()).extracting(a -> a.domain()).containsExactlyInAnyOrder(TrustDomain.CREDENTIAL_ISSUER,
                TrustDomain.MDOC_IACA, TrustDomain.WALLET_PROVIDER);
        assertThat(r.listInfo().sequence()).isEqualTo("3");
    }

    @Test
    void rejectsExpiredLote() {
        var ca = TestPki.rootCa("CN=PID CA,C=UT");
        var ctx = new TestContext().put("mem:lote", lote(Certificates.toBase64(ca.certificate()), "2020-01-01T00:00:00Z"));
        assertThatThrownBy(() -> new LoteSourceFactory().create(new SourceDefinition("l", "etsi-lote", "eudi", null, true,
                Map.of("location", "mem:lote", "allowUnverified", true)), ctx).load()).isInstanceOf(TrustSourceException.class).hasMessageContaining("NextUpdate");
    }

    @Test
    void verifiesJadesSignedLote() throws Exception {
        var ca = TestPki.rootCa("CN=PID CA,C=UT");
        var listRoot = TestPki.rootCa("CN=LoTE Root,C=EU");
        var signer = TestPki.leaf("CN=LoTE Signer,C=EU", listRoot, List.of(), null);
        JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("JOSE"))
                .x509CertChain(List.of(Base64.encode(Certificates.der(signer.certificate())))).build(),
                new Payload(lote(Certificates.toBase64(ca.certificate()), "2099-01-01T00:00:00Z")));
        jws.sign(new ECDSASigner((ECPrivateKey) signer.keys().getPrivate()));
        var ctx = new TestContext().put("mem:lote", jws.serialize());
        var r = new LoteSourceFactory().create(new SourceDefinition("l", "etsi-lote", "eudi", null, true,
                Map.of("location", "mem:lote", "signerCertificates", List.of(Certificates.toPem(listRoot.certificate())))), ctx).load();
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
        var wrongRoot = TestPki.rootCa("CN=Wrong,C=EU");
        assertThatThrownBy(() -> new LoteSourceFactory().create(new SourceDefinition("l", "etsi-lote", "eudi", null, true,
                Map.of("location", "mem:lote", "signerCertificates", List.of(Certificates.toPem(wrongRoot.certificate())))), ctx).load())
                .isInstanceOf(TrustSourceException.class);
    }
}
