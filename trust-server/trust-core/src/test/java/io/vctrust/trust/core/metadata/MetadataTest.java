package io.vctrust.trust.core.metadata;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import io.vctrust.trust.core.testing.FakeHttp;
import io.vctrust.trust.core.testing.TestPki;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MetadataTest {

    @Test
    void wellKnownInsertionAndAppend() {
        assertThat(WellKnown.inserted("https://issuer.example", WellKnown.CREDENTIAL_ISSUER).toString())
                .isEqualTo("https://issuer.example/.well-known/openid-credential-issuer");
        assertThat(WellKnown.inserted("https://issuer.example/tenant/1", WellKnown.CREDENTIAL_ISSUER).toString())
                .isEqualTo("https://issuer.example/.well-known/openid-credential-issuer/tenant/1");
        assertThat(WellKnown.inserted("https://issuer.example/", WellKnown.OAUTH_AUTHORIZATION_SERVER).toString())
                .isEqualTo("https://issuer.example/.well-known/oauth-authorization-server");
        assertThat(WellKnown.appended("https://op.example/realm/", WellKnown.OPENID_CONFIGURATION).toString())
                .isEqualTo("https://op.example/realm/.well-known/openid-configuration");
    }

    @Test
    void policyOperators() {
        Map<String, Object> md = Map.of("grant_types", List.of("authorization_code", "implicit"), "scope", "a");
        Map<String, Object> policy = Map.of(
                "grant_types", Map.of("subset_of", List.of("authorization_code", "refresh_token")),
                "token_endpoint", Map.of("default", "https://as/token"),
                "authorization_servers", Map.of("add", List.of("https://as")),
                "scope", Map.of("one_of", List.of("a", "b"), "essential", true));
        var out = MetadataPolicy.apply(md, policy);
        assertThat(out.get("grant_types")).isEqualTo(List.of("authorization_code"));
        assertThat(out.get("token_endpoint")).isEqualTo("https://as/token");
        assertThat(out.get("authorization_servers")).isEqualTo(List.of("https://as"));
        assertThatThrownBy(() -> MetadataPolicy.apply(Map.of("scope", "c"), policy)).isInstanceOf(MetadataPolicy.PolicyException.class);
        assertThatThrownBy(() -> MetadataPolicy.apply(Map.of(), Map.of("x", Map.of("essential", true))))
                .isInstanceOf(MetadataPolicy.PolicyException.class);
    }

    @Test
    void policyMergeDetectsConflicts() {
        assertThatThrownBy(() -> MetadataPolicy.merge(Map.of("a", Map.of("value", 1)), Map.of("a", Map.of("value", 2))))
                .isInstanceOf(MetadataPolicy.PolicyException.class);
        var merged = MetadataPolicy.merge(Map.of("a", Map.of("subset_of", List.of(1, 2, 3))), Map.of("a", Map.of("subset_of", List.of(2, 3, 4))));
        assertThat(((Map<?, ?>) merged.get("a")).get("subset_of")).isEqualTo(List.of(2, 3));
    }

    private static final String ISSUER_MD = """
            {"credential_issuer":"https://issuer.example/tenant","credential_endpoint":"https://issuer.example/tenant/credential",
             "authorization_servers":["https://as.example"],
             "credential_configurations_supported":{"mdl":{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}}}""";

    @Test
    void resolvesIssuerAndAuthorizationServer() throws Exception {
        var http = new FakeHttp()
                .json("https://issuer.example/.well-known/openid-credential-issuer/tenant", ISSUER_MD)
                .json("https://as.example/.well-known/oauth-authorization-server", "{\"issuer\":\"https://as.example\",\"token_endpoint\":\"https://as.example/token\"}");
        var r = new IssuerMetadataResolver(http, Clock.systemUTC(), Duration.ofMinutes(1), Duration.ofHours(1), false)
                .resolve("https://issuer.example/tenant", null);
        assertThat(r.credentialIssuer()).isEqualTo("https://issuer.example/tenant");
        assertThat(r.authorizationServers()).containsKey("https://as.example");
        assertThat(r.warnings()).isEmpty();
    }

    @Test
    void rejectsIssuerMismatch() {
        var http = new FakeHttp().json("https://other.example/.well-known/openid-credential-issuer/tenant", ISSUER_MD);
        assertThatThrownBy(() -> new IssuerMetadataResolver(http, Clock.systemUTC(), Duration.ofMinutes(1), Duration.ofHours(1), false)
                .resolve("https://other.example/tenant", null))
                .isInstanceOfSatisfying(MetadataException.class, e -> assertThat(e.code()).isEqualTo("issuer_mismatch"));
    }

    @Test
    void appliesRegistryPolicyToAuthorizationServers() throws Exception {
        var http = new FakeHttp()
                .json("https://issuer.example/.well-known/openid-credential-issuer/tenant", ISSUER_MD)
                .json("https://as.example/.well-known/oauth-authorization-server", "{\"issuer\":\"https://as.example\"}");
        var policy = Map.<String, Map<String, Object>>of("oauth_authorization_server",
                Map.of("token_endpoint", Map.of("default", "https://issuer.example/tenant/token"),
                        "grant_types_supported", Map.of("add", List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"))));
        var r = new IssuerMetadataResolver(http, Clock.systemUTC(), Duration.ofMinutes(1), Duration.ofHours(1), false)
                .resolve("https://issuer.example/tenant", policy);
        assertThat(r.policyApplied()).isTrue();
        assertThat(r.authorizationServers().get("https://as.example").get("token_endpoint")).isEqualTo("https://issuer.example/tenant/token");
    }

    private static final String SIGNED_ISSUER = "https://signed.example";

    /** openidvci-issuer-metadata+jwt by {@code signer} (x5c: just the signer), and a JSON fallback at the same URL. */
    private static FakeHttp signedIssuer(TestPki.Issued signer, String typ, String sub) throws Exception {
        Map<String, Object> claims = new java.util.LinkedHashMap<>(Map.of("credential_issuer", SIGNED_ISSUER,
                "credential_endpoint", SIGNED_ISSUER + "/credential", "credential_configurations_supported", Map.of("pid", Map.of("format", "dc+sd-jwt")),
                "sub", sub, "iat", java.time.Instant.now().getEpochSecond()));
        JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ))
                .x509CertChain(List.of(Base64.encode(signer.certificate().getEncoded()))).build(), new Payload(claims));
        jws.sign(new ECDSASigner((ECPrivateKey) signer.keys().getPrivate()));
        return new FakeHttp()
                .respond(SIGNED_ISSUER + "/.well-known/openid-credential-issuer", 200, "application/jwt", jws.serialize().getBytes(StandardCharsets.UTF_8))
                .json(SIGNED_ISSUER + "/.well-known/oauth-authorization-server", "{\"issuer\":\"" + SIGNED_ISSUER + "\"}");
    }

    @Test
    void verifiesSignedMetadataWithATrustedSigner() throws Exception {
        var ca = TestPki.rootCa("CN=Metadata CA,C=NL");
        var signer = TestPki.leaf("CN=Metadata signer,C=NL", ca, List.of("signed.example"), null);
        IssuerMetadataResolver.SignerTrust trustCa = chain -> chain.getFirst().getIssuerX500Principal().equals(ca.certificate().getSubjectX500Principal()) ? null : "unknown CA";
        var r = new IssuerMetadataResolver(signedIssuer(signer, "openidvci-issuer-metadata+jwt", SIGNED_ISSUER), Clock.systemUTC(),
                Duration.ofMinutes(1), Duration.ofHours(1), true, trustCa).resolve(SIGNED_ISSUER, null);
        assertThat(r.signedMetadataVerified()).isTrue();
        assertThat(r.signedMetadata()).isNotNull();
        assertThat(r.issuer()).containsKey("credential_endpoint").doesNotContainKeys("sub", "iat");
        assertThat(r.warnings()).anyMatch(w -> w.startsWith("Signed metadata verified"));
    }

    @Test
    void rejectsSignedMetadataFromUntrustedSelfSignedOrMismatchedSigners() throws Exception {
        var ca = TestPki.rootCa("CN=Metadata CA,C=NL");
        var signer = TestPki.leaf("CN=Metadata signer,C=NL", ca, List.of("signed.example"), null);
        IssuerMetadataResolver.SignerTrust signerOnly = chain -> chain.getFirst().equals(signer.certificate()) ? null : "untrusted";
        var unbound = TestPki.leaf("CN=Other signer,C=NL", ca, List.of("other.example"), null);
        IssuerMetadataResolver.SignerTrust anyUnderCa = chain -> null;
        assertThatThrownBy(() -> new IssuerMetadataResolver(signedIssuer(unbound, "openidvci-issuer-metadata+jwt", SIGNED_ISSUER), Clock.systemUTC(),
                Duration.ofMinutes(1), Duration.ofHours(1), true, anyUnderCa).resolve(SIGNED_ISSUER, null))
                .hasMessageContaining("not bound to " + SIGNED_ISSUER);
        for (var http : List.of(signedIssuer(ca, "openidvci-issuer-metadata+jwt", SIGNED_ISSUER),
                signedIssuer(signer, "JWT", SIGNED_ISSUER),
                signedIssuer(signer, "openidvci-issuer-metadata+jwt", "https://other.example"))) {
            // No JSON to fall back to at this fake URL, so resolution fails with the reason.
            assertThatThrownBy(() -> new IssuerMetadataResolver(http, Clock.systemUTC(), Duration.ofMinutes(1), Duration.ofHours(1), true, signerOnly)
                    .resolve(SIGNED_ISSUER, null))
                    .isInstanceOf(MetadataException.class).hasMessageContaining("Signed metadata rejected");
        }
        // An untrusted signer: the signed answer is rejected and the plain JSON metadata is used, flagged as not verified.
        var http = signedIssuer(signer, "openidvci-issuer-metadata+jwt", SIGNED_ISSUER).jsonForPlainAccept(SIGNED_ISSUER + "/.well-known/openid-credential-issuer",
                "{\"credential_issuer\":\"" + SIGNED_ISSUER + "\",\"credential_endpoint\":\"" + SIGNED_ISSUER + "/credential\",\"credential_configurations_supported\":{}}");
        var r = new IssuerMetadataResolver(http, Clock.systemUTC(), Duration.ofMinutes(1), Duration.ofHours(1), true, chain -> "no anchor")
                .resolve(SIGNED_ISSUER, null);
        assertThat(r.signedMetadataVerified()).isFalse();
        assertThat(r.signedMetadata()).isNull();
        assertThat(r.warnings()).anyMatch(w -> w.contains("signer is not trusted: no anchor"));
    }
}
