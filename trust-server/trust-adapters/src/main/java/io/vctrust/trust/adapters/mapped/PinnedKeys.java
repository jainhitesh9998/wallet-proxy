package io.vctrust.trust.adapters.mapped;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.vctrust.trust.adapters.support.AdapterSupport;
import io.vctrust.trust.adapters.support.SignerVerification;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.PathValidationResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The keys a JWS list must be signed with, pinned in the configuration ({@code verify}): a JWKS ({@code jwks} inline,
 * or {@code jwksLocation}), or certificates ({@code certificates}, or {@code certificateLocation}) that the JWS's
 * {@code x5c} chain must validate to. Never fetched from the network: a key served from where the list is served would
 * prove nothing about the list.
 *
 * <p>Only asymmetric algorithms are accepted ({@code none} and HMAC never: a symmetric key would have to be known to
 * whoever verifies, so it cannot tell the list's signer from anyone else holding the configuration). A header that
 * marks a parameter critical ({@code crit}) is refused, since this verifier understands none. A {@code kid} selects
 * the key; {@code jwk}, {@code jku} and {@code x5u} are never used.
 */
final class PinnedKeys {

    static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512, JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512);
    static final Set<String> MEMBERS = Set.of("jwks", "jwksLocation", "certificates", "certificateLocation", "typ", "audience");
    private static final Pattern COMPACT = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    private static final int MAX_CHAIN = 10;
    private static final int MIN_RSA_BITS = 2048;

    private final List<JWK> keys;
    private final SignerVerification certificates;
    private final String typ;
    private final String audience;

    private PinnedKeys(List<JWK> keys, SignerVerification certificates, String typ, String audience) {
        this.keys = keys;
        this.certificates = certificates;
        this.typ = typ;
        this.audience = audience;
    }

    /** No keys: for {@code format: json}, or a JWS list loaded with {@code allowUnverified}. */
    static PinnedKeys none() {
        return new PinnedKeys(null, null, null, null);
    }

    static PinnedKeys read(Map<String, Object> verify, ResourceLoader loader) throws IOException {
        List<String> given = new ArrayList<>();
        for (String k : List.of("jwks", "jwksLocation", "certificates", "certificateLocation")) {
            if (verify.get(k) != null) {
                given.add(k);
            }
        }
        if (given.size() > 1) {
            throw new IllegalArgumentException("verify: give one of jwks, jwksLocation, certificates, certificateLocation, not " + given);
        }
        String typ = optionalText(verify, "typ");
        String audience = optionalText(verify, "audience");
        if (given.isEmpty()) {
            return new PinnedKeys(null, null, typ, audience);
        }
        String which = given.getFirst();
        Object raw = verify.get(which);
        switch (which) {
            case "jwks", "jwksLocation" -> {
                String json = which.equals("jwks")
                        ? (raw instanceof Map<?, ?> ? Json.write(raw) : String.valueOf(raw))
                        : new String(local(loader, String.valueOf(raw), "verify.jwksLocation"), StandardCharsets.UTF_8);
                return new PinnedKeys(jwks(json, "verify." + which), null, typ, audience);
            }
            default -> {
                List<X509Certificate> certs = new ArrayList<>();
                if (which.equals("certificates")) {
                    for (Object c : raw instanceof List<?> l ? l : List.of(raw)) {
                        certs.addAll(AdapterSupport.parseCertificateText(String.valueOf(c)));
                    }
                } else {
                    certs.addAll(Certificates.fromPemBundle(local(loader, String.valueOf(raw), "verify.certificateLocation")));
                }
                if (certs.isEmpty()) {
                    throw new IllegalArgumentException("verify." + which + " holds no certificate");
                }
                return new PinnedKeys(null, SignerVerification.of(certs), typ, audience);
            }
        }
    }

    /** A pinned key is read from this host (a file, the classpath), never fetched. */
    private static byte[] local(ResourceLoader loader, String location, String what) throws IOException {
        if (ResourceLoader.isRemote(location)) {
            throw new IllegalArgumentException(what + " must be a file: or classpath: location: a key fetched from the network "
                    + "would be served by whoever serves the list");
        }
        return loader.load(location);
    }

    private static List<JWK> jwks(String json, String what) {
        JWKSet set;
        try {
            set = JWKSet.parse(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(what + " is not a JWKS");
        }
        if (set.getKeys().isEmpty()) {
            throw new IllegalArgumentException(what + " holds no key");
        }
        for (JWK k : set.getKeys()) {
            if (!(k instanceof ECKey) && !(k instanceof RSAKey)) {
                throw new IllegalArgumentException(what + " holds a " + k.getKeyType() + " key; only EC and RSA public keys are accepted");
            }
            if (k.isPrivate()) {
                throw new IllegalArgumentException(what + " holds a private key; pin the public key only");
            }
        }
        return List.copyOf(set.getKeys());
    }

    private static String optionalText(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) {
            return null;
        }
        if (!(v instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException("verify." + key + " must be text");
        }
        return s;
    }

    /** Whether keys or certificates are pinned. */
    boolean configured() {
        return keys != null || certificates != null;
    }

    /** The audience this service has at the list's issuer ({@code verify.audience}), or null. */
    String audience() {
        return audience;
    }

    /**
     * Verifies a compact JWS against the pinned keys before anything of it is read.
     *
     * @return the payload
     * @throws TrustSourceException when it is not a compact JWS, its header asks for what is refused, or no pinned key
     *                              verifies it
     */
    byte[] verify(String compact, Instant now) throws TrustSourceException {
        JWSObject jws = parse(compact);
        JWSHeader h = jws.getHeader();
        if (!ALGORITHMS.contains(h.getAlgorithm())) {
            throw new TrustSourceException("The list is signed with " + h.getAlgorithm() + ", which is not accepted (one of "
                    + ALGORITHMS.stream().map(JWSAlgorithm::getName).sorted().toList() + ")");
        }
        if (h.getCriticalParams() != null && !h.getCriticalParams().isEmpty()) {
            throw new TrustSourceException("The list's JWS header marks parameters critical (crit), which this service does not process");
        }
        if (typ != null && !normalized(typ).equals(h.getType() == null ? "" : normalized(h.getType().getType()))) {
            throw new TrustSourceException("The list's JWS typ is " + (h.getType() == null ? "absent" : "'" + h.getType() + "'")
                    + ", not '" + typ + "' (verify.typ)");
        }
        List<PublicKey> candidates = keys != null ? fromJwks(h) : fromChain(h, now);
        for (PublicKey key : candidates) {
            JWSVerifier verifier = verifier(h.getAlgorithm(), key);
            try {
                if (verifier != null && verifier.verify(h, jws.getSigningInput(), jws.getSignature())) {
                    return jws.getPayload().toBytes();
                }
            } catch (Exception e) {
                // a key that cannot check this signature is a key that did not verify it
            }
        }
        throw new TrustSourceException("The list's signature does not verify with " + (keys != null ? "the pinned keys" : "its x5c certificate"));
    }

    /** The payload of a JWS loaded with {@code allowUnverified}: read, not verified. */
    static byte[] unverifiedPayload(String compact) throws TrustSourceException {
        return parse(compact).getPayload().toBytes();
    }

    private static JWSObject parse(String compact) throws TrustSourceException {
        if (!COMPACT.matcher(compact).matches()) {
            throw new TrustSourceException("The list is not a compact JWS");
        }
        try {
            return JWSObject.parse(compact);
        } catch (Exception e) {
            throw new TrustSourceException("The list is not a JWS: its header cannot be read");
        }
    }

    private static String normalized(String typ) {
        String t = typ.toLowerCase(Locale.ROOT);
        return t.startsWith("application/") ? t.substring("application/".length()) : t;
    }

    private List<PublicKey> fromJwks(JWSHeader h) throws TrustSourceException {
        List<PublicKey> out = new ArrayList<>();
        String kid = h.getKeyID();
        boolean kidKnown = false;
        for (JWK k : keys) {
            if (kid != null && !kid.equals(k.getKeyID())) {
                continue;
            }
            kidKnown = true;
            if ((k.getAlgorithm() != null && !k.getAlgorithm().equals(h.getAlgorithm()))
                    || (k.getKeyUse() != null && !KeyUse.SIGNATURE.equals(k.getKeyUse()))) {
                continue;
            }
            try {
                out.add(k instanceof ECKey ec ? ec.toECPublicKey() : ((RSAKey) k).toRSAPublicKey());
            } catch (Exception e) {
                // not usable; another key may be
            }
        }
        if (kid != null && !kidKnown) {
            throw new TrustSourceException("No pinned key has the kid the list names");
        }
        return out;
    }

    private List<PublicKey> fromChain(JWSHeader h, Instant now) throws TrustSourceException {
        List<com.nimbusds.jose.util.Base64> x5c = h.getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new TrustSourceException("The list's JWS carries no x5c chain to check against the pinned certificates");
        }
        if (x5c.size() > MAX_CHAIN) {
            throw new TrustSourceException("The list's x5c chain is longer than " + MAX_CHAIN);
        }
        List<X509Certificate> chain = new ArrayList<>();
        try {
            for (com.nimbusds.jose.util.Base64 c : x5c) {
                chain.add(Certificates.fromDer(c.decode()));
            }
        } catch (Exception e) {
            throw new TrustSourceException("The list's x5c chain holds something that is not a certificate");
        }
        PathValidationResult pv = certificates.validate(chain, now);
        if (!pv.valid()) {
            throw new TrustSourceException("The list's signer does not validate to a pinned certificate: " + pv.issues());
        }
        return List.of(chain.getFirst().getPublicKey());
    }

    /** A verifier only for a key of the algorithm's family, curve and strength. */
    private static JWSVerifier verifier(JWSAlgorithm alg, PublicKey key) {
        try {
            if (JWSAlgorithm.Family.EC.contains(alg) && key instanceof ECPublicKey ec
                    && Curve.forJWSAlgorithm(alg).contains(Curve.forECParameterSpec(ec.getParams()))) {
                return new ECDSAVerifier(ec);
            }
            if (JWSAlgorithm.Family.RSA.contains(alg) && key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= MIN_RSA_BITS) {
                return new RSASSAVerifier(rsa);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}
