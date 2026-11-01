package io.vctrust.trust.adapters;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.adapters.ebsi.EbsiTirSourceFactory;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class EbsiTirSourceTest {

    static final String BASE = "https://api.example/trusted-issuers-registry/v5";

    static String accreditation() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).generate();
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder()
                .claim("vc", Map.of("type", List.of("VerifiableCredential", "VerifiableAccreditationToAttest"),
                        "credentialSubject", Map.of("id", "did:ebsi:zIssuer",
                                "accreditedFor", List.of(Map.of("types", List.of("VerifiableCredential", "VerifiableAttestation", "VerifiableDiploma"))))))
                .build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    @Test
    void crawlsAndResolvesOnDemand() throws Exception {
        var ctx = new TestContext();
        ctx.http.json(BASE + "/issuers?page[size]=50", "{\"items\":[{\"did\":\"did:ebsi:zIssuer\"},{\"did\":\"did:ebsi:zRevoked\"}],\"links\":{},\"total\":2}");
        ctx.http.json(BASE + "/issuers/did%3Aebsi%3AzIssuer?version=deprecated", """
                {"did":"did:ebsi:zIssuer","attributes":[{"hash":"h","body":"%s","issuerType":"TI","tao":"did:ebsi:zTao","rootTao":"did:ebsi:zRoot"}]}"""
                .formatted(accreditation()));
        ctx.http.json(BASE + "/issuers/did%3Aebsi%3AzRevoked?version=deprecated",
                "{\"did\":\"did:ebsi:zRevoked\",\"attributes\":[{\"hash\":\"h\",\"body\":\"x\",\"issuerType\":\"Revoked\"}]}");
        var src = new EbsiTirSourceFactory().create(new SourceDefinition("ebsi", "ebsi-tir", "ebsi", null, true,
                Map.of("baseUrl", BASE, "crawl", true)), ctx);
        var r = src.load();
        assertThat(r.entities()).hasSize(2);
        var ti = r.entities().getFirst();
        assertThat(ti.hasRole(EntityRole.CREDENTIAL_ISSUER)).isTrue();
        assertThat(ti.isAuthorizedFor(null, "VerifiableDiploma", true)).isTrue();
        assertThat(ti.attributes()).containsEntry("tao", "did:ebsi:zTao");
        assertThat(r.entities().get(1).status()).isEqualTo(EntityStatus.REVOKED);
        var od = (OnDemandResolver) src;
        assertThat(od.canResolve(Identifier.did("did:ebsi:zIssuer"))).isTrue();
        assertThat(od.resolve(Identifier.did("did:ebsi:zIssuer"))).isPresent();
        assertThat(od.resolve(Identifier.did("did:ebsi:zMissing"))).isEmpty();
    }
}
