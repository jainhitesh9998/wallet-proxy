package io.vctrust.trust.adapters;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.adapters.federation.OpenIdFederationSourceFactory;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class FederationSourceTest {

    static final String TA = "https://ta.example";
    static final String INT = "https://int.example";
    static final String LEAF = "https://issuer.example";
    static final String ORPHAN = "https://orphan.example";

    ECKey taKey, intKey, leafKey, orphanKey;
    TestContext ctx;

    static String sign(ECKey signer, Map<String, Object> claims) throws Exception {
        JWTClaimsSet.Builder b = new JWTClaimsSet.Builder()
                .issueTime(Date.from(Instant.now().minusSeconds(10)))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)));
        claims.forEach(b::claim);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("entity-statement+jwt"))
                .keyID(signer.getKeyID()).build(), b.build());
        jwt.sign(new ECDSASigner(signer));
        return jwt.serialize();
    }

    static Map<String, Object> jwks(ECKey k) {
        return new JWKSet(k.toPublicJWK()).toJSONObject();
    }

    @BeforeEach
    void setUp() throws Exception {
        taKey = new ECKeyGenerator(Curve.P_256).keyID("ta").generate();
        intKey = new ECKeyGenerator(Curve.P_256).keyID("int").generate();
        leafKey = new ECKeyGenerator(Curve.P_256).keyID("leaf").generate();
        orphanKey = new ECKeyGenerator(Curve.P_256).keyID("orphan").generate();
        ctx = new TestContext();
        Map<String, Object> taFed = Map.of("federation_fetch_endpoint", TA + "/fetch", "federation_list_endpoint", TA + "/list");
        Map<String, Object> intFed = Map.of("federation_fetch_endpoint", INT + "/fetch", "federation_list_endpoint", INT + "/list");
        ctx.http.respond(TA + "/.well-known/openid-federation", 200, "application/entity-statement+jwt",
                sign(taKey, Map.of("iss", TA, "sub", TA, "jwks", jwks(taKey), "metadata", Map.of("federation_entity", taFed))).getBytes());
        ctx.http.json(TA + "/list", "[\"" + INT + "\"]");
        ctx.http.respond(TA + "/fetch?sub=https%3A%2F%2Fint.example", 200, "application/entity-statement+jwt",
                sign(taKey, Map.of("iss", TA, "sub", INT, "jwks", jwks(intKey),
                        "metadata_policy", Map.of("openid_credential_issuer",
                                Map.of("credential_signing_alg_values_supported", Map.of("subset_of", List.of("ES256")))))).getBytes());
        ctx.http.respond(INT + "/.well-known/openid-federation", 200, "application/entity-statement+jwt",
                sign(intKey, Map.of("iss", INT, "sub", INT, "jwks", jwks(intKey), "authority_hints", List.of(TA),
                        "metadata", Map.of("federation_entity", intFed))).getBytes());
        ctx.http.json(INT + "/list", "[\"" + LEAF + "\"]");
        ctx.http.respond(INT + "/fetch?sub=https%3A%2F%2Fissuer.example", 200, "application/entity-statement+jwt",
                sign(intKey, Map.of("iss", INT, "sub", LEAF, "jwks", jwks(leafKey))).getBytes());
        ctx.http.respond(LEAF + "/.well-known/openid-federation", 200, "application/entity-statement+jwt",
                sign(leafKey, Map.of("iss", LEAF, "sub", LEAF, "jwks", jwks(leafKey), "authority_hints", List.of(INT),
                        "metadata", Map.of(
                                "federation_entity", Map.of("organization_name", "Federated Issuer"),
                                "openid_credential_issuer", Map.of("credential_issuer", LEAF,
                                        "credential_signing_alg_values_supported", List.of("ES256", "RS256"),
                                        "credential_configurations_supported", Map.of("pid", Map.of("format", "dc+sd-jwt", "vct", "urn:eudi:pid:1"))))))
                        .getBytes());
        // An entity claiming the intermediate as superior but not registered there
        ctx.http.respond(ORPHAN + "/.well-known/openid-federation", 200, "application/entity-statement+jwt",
                sign(orphanKey, Map.of("iss", ORPHAN, "sub", ORPHAN, "jwks", jwks(orphanKey), "authority_hints", List.of(INT),
                        "metadata", Map.of("openid_credential_issuer", Map.of("credential_issuer", ORPHAN)))).getBytes());
    }

    SourceDefinition def(Map<String, Object> extra) {
        var props = new java.util.HashMap<String, Object>(Map.of("trustAnchor", TA,
                "trustAnchorJwks", new JWKSet(taKey.toPublicJWK()).toString()));
        props.putAll(extra);
        return new SourceDefinition("fed", "openid-federation", "fed-fw", null, true, props);
    }

    @Test
    void crawlsAndAppliesPolicy() throws Exception {
        var r = new OpenIdFederationSourceFactory().create(def(Map.of()), ctx).load();
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).singleElement().satisfies(e -> {
            assertThat(e.id()).isEqualTo("oidf:" + LEAF);
            assertThat(e.hasRole(EntityRole.CREDENTIAL_ISSUER)).isTrue();
            assertThat(e.displayName("en")).isEqualTo("Federated Issuer");
            assertThat(e.metadata().get("openid_credential_issuer").get("credential_signing_alg_values_supported")).isEqualTo(List.of("ES256"));
            assertThat(e.attributes()).containsEntry("trustAnchor", TA);
            assertThat(e.isAuthorizedFor("dc+sd-jwt", "urn:eudi:pid:1", true)).isTrue();
        });
    }

    @Test
    void resolvesOnDemandAndRejectsOrphans() throws Exception {
        var src = new OpenIdFederationSourceFactory().create(def(Map.of("crawl", false)), ctx);
        var resolver = (OnDemandResolver) src;
        assertThat(resolver.resolve(Identifier.of(IdentifierType.FEDERATION_ENTITY, LEAF))).isPresent();
        assertThat(resolver.resolve(Identifier.of(IdentifierType.FEDERATION_ENTITY, ORPHAN))).isEmpty();
    }

    @Test
    void wrongPinnedTrustAnchorKeyFailsLoad() throws Exception {
        var other = new ECKeyGenerator(Curve.P_256).keyID("ta").generate();
        var d = new SourceDefinition("fed", "openid-federation", "fed-fw", null, true,
                Map.of("trustAnchor", TA, "trustAnchorJwks", new JWKSet(other.toPublicJWK()).toString()));
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new OpenIdFederationSourceFactory().create(d, ctx).load())
                .hasMessageContaining("signature");
    }
}
