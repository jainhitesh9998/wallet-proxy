package io.vctrust.trust.server.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.vctrust.trust.server.config.TrustProperties;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Validates OAuth 2.0 JWT access tokens (RFC 9068) from the configured authorization server: signature against its
 * JWKS, {@code typ}, {@code iss}, {@code aud}, {@code exp}/{@code nbf} with clock skew, and the required scope.
 */
public class AccessTokenVerifier {

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    private final String requiredScope;

    public AccessTokenVerifier(TrustProperties.OAuth cfg, String serviceIssuer) {
        this(cfg, serviceIssuer, jwkSource(cfg.getJwksUri()));
    }

    AccessTokenVerifier(TrustProperties.OAuth cfg, String serviceIssuer, JWKSource<SecurityContext> keys) {
        if (cfg.getIssuer() == null || cfg.getIssuer().isBlank()) {
            throw new IllegalArgumentException("trust.auth.oauth.issuer is required");
        }
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        for (String a : cfg.getAlgorithms()) {
            JWSAlgorithm alg = JWSAlgorithm.parse(a);
            if (!JWSAlgorithm.Family.RSA.contains(alg) && !JWSAlgorithm.Family.EC.contains(alg) && !JWSAlgorithm.EdDSA.equals(alg)) {
                throw new IllegalArgumentException("trust.auth.oauth.algorithms: unsupported " + a);
            }
            algs.add(alg);
        }
        Set<String> types = new LinkedHashSet<>();
        cfg.getTokenTypes().forEach(t -> types.add(normalizeType(t)));
        processor.setJWSTypeVerifier((JOSEObjectType typ, SecurityContext c) -> {
            String t = typ == null ? "jwt" : normalizeType(typ.getType());
            if (!types.contains(t)) {
                throw new BadJOSEException("Token type " + (typ == null ? "(none)" : typ.getType()) + " is not accepted");
            }
        });
        processor.setJWSKeySelector(new EdDsaAwareKeySelector(algs, keys));
        processor.setJWSVerifierFactory(new EdDsaAwareVerifierFactory());
        Set<String> audiences = new LinkedHashSet<>(cfg.getAudiences().isEmpty() ? List.of(serviceIssuer) : cfg.getAudiences());
        DefaultJWTClaimsVerifier<SecurityContext> claims = new DefaultJWTClaimsVerifier<>(audiences,
                new JWTClaimsSet.Builder().issuer(cfg.getIssuer()).build(), Set.of("exp", "iss", "aud"), null);
        claims.setMaxClockSkew((int) cfg.getClockSkew().toSeconds());
        processor.setJWTClaimsSetVerifier(claims);
        this.requiredScope = cfg.getRequiredScope() == null || cfg.getRequiredScope().isBlank() ? null : cfg.getRequiredScope().trim();
    }

    /** {@code at+jwt}, {@code application/at+jwt} → {@code at+jwt}; case-insensitive. */
    private static String normalizeType(String t) {
        String s = t.trim().toLowerCase(Locale.ROOT);
        return s.startsWith("application/") ? s.substring("application/".length()) : s;
    }

    /** A token that failed validation; {@code bearerError} is the RFC 6750 error code. */
    public static class InvalidTokenException extends Exception {
        private final String bearerError;

        InvalidTokenException(String bearerError, String message) {
            super(message);
            this.bearerError = bearerError;
        }

        public String bearerError() {
            return bearerError;
        }
    }

    public JWTClaimsSet verify(String token) throws InvalidTokenException {
        JWTClaimsSet claims;
        try {
            claims = processor.process(token, null);
        } catch (BadJWTException e) {
            throw new InvalidTokenException("invalid_token", e.getMessage());
        } catch (BadJOSEException | JOSEException | java.text.ParseException e) {
            throw new InvalidTokenException("invalid_token", "Access token rejected: " + e.getMessage());
        }
        if (requiredScope != null && !scopes(claims).contains(requiredScope)) {
            throw new InvalidTokenException("insufficient_scope", "Access token lacks scope " + requiredScope);
        }
        return claims;
    }

    static Set<String> scopes(JWTClaimsSet claims) {
        Set<String> out = new LinkedHashSet<>();
        Object scope = claims.getClaim("scope");
        if (scope instanceof String s) {
            out.addAll(List.of(s.trim().split("\\s+")));
        }
        Object scp = claims.getClaim("scp");
        if (scp instanceof List<?> l) {
            l.forEach(v -> out.add(String.valueOf(v)));
        } else if (scp instanceof String s) {
            out.addAll(List.of(s.trim().split("\\s+")));
        }
        return out;
    }

    /** RFC 8705 {@code cnf.x5t#S256} as lowercase hex, or null when the token is not certificate-bound. */
    static String certificateBinding(JWTClaimsSet claims) {
        Object cnf = claims.getClaim("cnf");
        if (cnf instanceof Map<?, ?> m && m.get("x5t#S256") instanceof String t) {
            return HexFormat.of().formatHex(new Base64URL(t).decode());
        }
        return null;
    }

    static JWKSource<SecurityContext> jwkSource(String uri) {
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("trust.auth.oauth.jwks-uri is required");
        }
        try {
            if (uri.startsWith("classpath:")) {
                try (InputStream in = AccessTokenVerifier.class.getClassLoader().getResourceAsStream(uri.substring(10).replaceFirst("^/", ""))) {
                    if (in == null) {
                        throw new IllegalArgumentException("JWKS not found: " + uri);
                    }
                    return new ImmutableJWKSet<>(JWKSet.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
                }
            }
            if (uri.startsWith("file:")) {
                return new ImmutableJWKSet<>(JWKSet.parse(Files.readString(Path.of(URI.create(uri)))));
            }
            return JWKSourceBuilder.create(URI.create(uri).toURL(), new DefaultResourceRetriever(5_000, 5_000, 512 * 1024))
                    .cache(true)
                    .rateLimited(true)
                    .build();
        } catch (IOException | java.text.ParseException e) {
            throw new IllegalArgumentException("Cannot load JWKS " + uri + ": " + e.getMessage(), e);
        }
    }

    /** Standard key selection, plus Ed25519 JWKs (which nimbus cannot turn into JCA keys without Tink). */
    private static final class EdDsaAwareKeySelector implements JWSKeySelector<SecurityContext> {
        private final JWSVerificationKeySelector<SecurityContext> standard;
        private final JWKSource<SecurityContext> keys;
        private final boolean edDsa;

        EdDsaAwareKeySelector(Set<JWSAlgorithm> algs, JWKSource<SecurityContext> keys) {
            Set<JWSAlgorithm> std = new LinkedHashSet<>(algs);
            this.edDsa = std.remove(JWSAlgorithm.EdDSA);
            this.standard = std.isEmpty() ? null : new JWSVerificationKeySelector<>(std, keys);
            this.keys = keys;
        }

        @Override
        public List<? extends Key> selectJWSKeys(JWSHeader header, SecurityContext context) throws com.nimbusds.jose.KeySourceException {
            if (!JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
                return standard == null ? List.of() : standard.selectJWSKeys(header, context);
            }
            if (!edDsa) {
                return List.of();
            }
            JWKMatcher m = new JWKMatcher.Builder().keyID(header.getKeyID()).keyType(com.nimbusds.jose.jwk.KeyType.OKP)
                    .curve(com.nimbusds.jose.jwk.Curve.Ed25519).build();
            List<Key> out = new ArrayList<>();
            for (JWK jwk : keys.get(new JWKSelector(m), context)) {
                out.add(ed25519PublicKey(((OctetKeyPair) jwk).getDecodedX()));
            }
            return out;
        }
    }

    static PublicKey ed25519PublicKey(byte[] x) {
        try {
            byte[] prefix = HexFormat.of().parseHex("302a300506032b6570032100");
            byte[] spki = new byte[prefix.length + x.length];
            System.arraycopy(prefix, 0, spki, 0, prefix.length);
            System.arraycopy(x, 0, spki, prefix.length, x.length);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** nimbus' verifiers, plus EdDSA through the JDK's Ed25519 provider. */
    private static final class EdDsaAwareVerifierFactory implements JWSVerifierFactory {
        private final DefaultJWSVerifierFactory standard = new DefaultJWSVerifierFactory();

        @Override
        public JWSVerifier createJWSVerifier(JWSHeader header, Key key) throws JOSEException {
            if (JWSAlgorithm.EdDSA.equals(header.getAlgorithm()) && key instanceof PublicKey pub) {
                return new JcaEd25519Verifier(pub);
            }
            return standard.createJWSVerifier(header, key);
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            Set<JWSAlgorithm> s = new LinkedHashSet<>(standard.supportedJWSAlgorithms());
            s.add(JWSAlgorithm.EdDSA);
            return s;
        }

        @Override
        public JCAContext getJCAContext() {
            return standard.getJCAContext();
        }
    }

    private record JcaEd25519Verifier(PublicKey key) implements JWSVerifier {
        @Override
        public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
            try {
                Signature s = Signature.getInstance("Ed25519");
                s.initVerify(key);
                s.update(signingInput);
                return s.verify(signature.decode());
            } catch (GeneralSecurityException e) {
                throw new JOSEException("Ed25519 verification failed: " + e.getMessage(), e);
            }
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            return Set.of(JWSAlgorithm.EdDSA);
        }

        @Override
        public JCAContext getJCAContext() {
            return new JCAContext();
        }
    }
}
