package io.vctrust.trust.server.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.metadata.IssuerMetadataResolver;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.FakeHttp;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.ServiceException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The signer of signed issuer metadata, on a service with trust.revocation.enabled: false, as TrustCoreConfiguration wires
 * the metadata proxy. Its revocation status is unknown, as every certificate's is on such a service: a client that
 * requires a known status does not get the signed metadata as verified (and one that also requires signed metadata is
 * refused), exactly as its devices, which always check, would refuse the signer. A lenient client gets it.
 */
class SignedMetadataRevocationTest {

    static final String ISSUER = "https://signed.example";

    final TestPki.Issued ca = TestPki.rootCa("CN=Metadata CA,C=UT");
    final TestPki.Issued signer = TestPki.leaf("CN=Metadata signer,C=UT", ca, List.of("signed.example"), null);

    final ClientProfile lenient = new ClientProfile("wallet", "Wallet", Set.of("fw"), false, true, false, false, false);
    final ClientProfile strict = new ClientProfile("strict", "Strict", Set.of("fw"), false, true, false, true, false);
    final ClientProfile strictSigned = new ClientProfile("strict-signed", "Strict, signed only", Set.of("fw"), false, true, false, true, true);

    /** The metadata proxy as the configuration builds it, over an issuer that serves metadata signed by {@link #signer}. */
    MetadataService proxy() throws Exception {
        TrustProperties props = new TrustProperties();
        props.getRevocation().setEnabled(false);
        TrustRegistry registry = new TrustRegistry();
        Provenance prov = Provenance.of("test", "static", "fw", null, Instant.now());
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("fw", "Framework", null, null, null)), List.of(),
                List.of(new TrustAnchor("metadata-ca", TrustDomain.CREDENTIAL_ISSUER, ca.certificate(), "fw", null, null, null, prov))));
        Clock clock = Clock.systemUTC();
        X509PathValidator validator = new X509PathValidator();
        TrustCoreConfiguration config = new TrustCoreConfiguration();
        // With revocation switched off the checker reads no CRL source, so none is given.
        RevocationChecker revocation = config.revocationChecker(null, props);
        IssuerMetadataResolver resolver = config.issuerMetadataResolver(signedIssuer(), clock, props, registry, validator);
        TrustEvaluator evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of()), validator, clock, Duration.ofHours(1), revocation);
        return config.metadataService(resolver, registry, evaluator, props, clock, validator, revocation);
    }

    /** openidvci-issuer-metadata+jwt signed by {@link #signer}, with its certificate in x5c. */
    FakeHttp signedIssuer() throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>(Map.of("credential_issuer", ISSUER, "credential_endpoint", ISSUER + "/credential",
                "credential_configurations_supported", Map.of("pid", Map.of("format", "dc+sd-jwt")), "sub", ISSUER,
                "iat", Instant.now().getEpochSecond()));
        JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openidvci-issuer-metadata+jwt"))
                .x509CertChain(List.of(Base64.encode(signer.certificate().getEncoded()))).build(), new Payload(claims));
        jws.sign(new ECDSASigner((ECPrivateKey) signer.keys().getPrivate()));
        return new FakeHttp()
                .respond(ISSUER + "/.well-known/openid-credential-issuer", 200, "application/jwt", jws.serialize().getBytes(StandardCharsets.UTF_8))
                .json(ISSUER + "/.well-known/oauth-authorization-server", "{\"issuer\":\"" + ISSUER + "\"}");
    }

    @Test
    void aClientThatRequiresAKnownStatusDoesNotGetTheSignerVerified() throws Exception {
        MetadataService proxy = proxy();
        MetadataService.IssuerMetadataEnvelope env = proxy.issuer(ISSUER, strict);
        assertThat(env.signedMetadataVerified()).isFalse();
        assertThat(env.signedMetadata()).isNull();
        assertThat(env.warnings()).anyMatch(w -> w.startsWith("Signed metadata signer is not trusted for client strict")
                && w.contains("revocation checking is switched off on this service"));

        assertThatThrownBy(() -> proxy.issuer(ISSUER, strictSigned)).isInstanceOfSatisfying(ServiceException.class,
                e -> assertThat(e.code()).isEqualTo("signed_metadata_required"));
    }

    @Test
    void aLenientClientGetsTheSignedMetadata() throws Exception {
        MetadataService.IssuerMetadataEnvelope env = proxy().issuer(ISSUER, lenient);
        assertThat(env.signedMetadataVerified()).isTrue();
        assertThat(env.signedMetadata()).isNotNull();
        // The proxy reports only a signer it does not accept; an accepted one with an unknown status is not flagged.
        assertThat(env.warnings()).noneMatch(w -> w.contains("not trusted"));
    }
}
