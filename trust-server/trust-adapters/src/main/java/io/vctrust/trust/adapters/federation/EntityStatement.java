package io.vctrust.trust.adapters.federation;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.vctrust.trust.core.json.Json;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** A parsed OpenID Federation entity statement ({@code typ: entity-statement+jwt}). */
public record EntityStatement(String jwt, JWSObject jws, Map<String, Object> claims) {

    static final Duration SKEW = Duration.ofSeconds(60);

    public static EntityStatement parse(String jwt) throws FederationException {
        try {
            JWSObject jws = JWSObject.parse(jwt.trim());
            if (jws.getHeader().getType() == null || !"entity-statement+jwt".equals(jws.getHeader().getType().toString())) {
                throw new FederationException("invalid_trust_chain", "Entity statement typ must be entity-statement+jwt");
            }
            if (jws.getHeader().getKeyID() == null) {
                throw new FederationException("invalid_trust_chain", "Entity statement header lacks kid");
            }
            return new EntityStatement(jwt.trim(), jws, jws.getPayload().toJSONObject());
        } catch (FederationException e) {
            throw e;
        } catch (Exception e) {
            throw new FederationException("invalid_trust_chain", "Malformed entity statement: " + e.getMessage());
        }
    }

    public String iss() {
        return Json.string(claims, "iss");
    }

    public String sub() {
        return Json.string(claims, "sub");
    }

    public Instant exp() {
        Object v = claims.get("exp");
        return v instanceof Number n ? Instant.ofEpochSecond(n.longValue()) : null;
    }

    public Instant iat() {
        Object v = claims.get("iat");
        return v instanceof Number n ? Instant.ofEpochSecond(n.longValue()) : null;
    }

    public boolean isSelfSigned() {
        return iss() != null && iss().equals(sub());
    }

    public JWKSet jwks() throws FederationException {
        Map<String, Object> j = Json.object(claims.get("jwks"));
        if (j == null) {
            throw new FederationException("invalid_trust_chain", "Entity statement for " + sub() + " lacks jwks");
        }
        try {
            return JWKSet.parse(j);
        } catch (Exception e) {
            throw new FederationException("invalid_trust_chain", "Bad jwks: " + e.getMessage());
        }
    }

    public Map<String, Object> metadata() {
        Map<String, Object> m = Json.object(claims.get("metadata"));
        return m == null ? Map.of() : m;
    }

    public Map<String, Object> metadataPolicy() {
        Map<String, Object> m = Json.object(claims.get("metadata_policy"));
        return m == null ? Map.of() : m;
    }

    public List<String> authorityHints() {
        return Json.strings(claims.get("authority_hints"));
    }

    public Map<String, Object> federationEntity() {
        Map<String, Object> fe = Json.object(metadata().get("federation_entity"));
        return fe == null ? Map.of() : fe;
    }

    /** Checks iat/exp and verifies the signature with a key from {@code keys} selected by kid. */
    public void verify(JWKSet keys, Instant now) throws FederationException {
        Instant exp = exp();
        if (exp == null || now.isAfter(exp.plus(SKEW))) {
            throw new FederationException("invalid_trust_chain", "Entity statement " + iss() + " → " + sub() + " is expired");
        }
        Instant iat = iat();
        if (iat == null || iat.isAfter(now.plus(SKEW))) {
            throw new FederationException("invalid_trust_chain", "Entity statement " + iss() + " → " + sub() + " has invalid iat");
        }
        String kid = jws.getHeader().getKeyID();
        JWK key = keys.getKeyByKeyId(kid);
        if (key == null) {
            throw new FederationException("invalid_trust_chain", "No key " + kid + " to verify statement " + iss() + " → " + sub());
        }
        try {
            boolean ok = jws.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jws.getHeader(), key.toPublicJWK()
                    instanceof com.nimbusds.jose.jwk.AsymmetricJWK a ? a.toPublicKey() : null));
            if (!ok) {
                throw new FederationException("invalid_trust_chain", "Bad signature on statement " + iss() + " → " + sub());
            }
        } catch (FederationException e) {
            throw e;
        } catch (Exception e) {
            throw new FederationException("invalid_trust_chain", "Cannot verify statement: " + e.getMessage());
        }
    }
}
