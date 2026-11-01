package io.vctrust.trust.core.metadata;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.util.Base64;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.x509.Certificates;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fetches and validates OpenID4VCI 1.0 Credential Issuer metadata (§12.2) and the RFC 8414 metadata of its
 * Authorization Servers. Applies the identifier checks that wallets must perform, so that clients of the
 * proxy receive metadata that is already safe to use.
 */
public class IssuerMetadataResolver {

    private final HttpFetcher http;
    private final Clock clock;
    private final Duration minTtl;
    private final Duration maxTtl;
    private final boolean requestSigned;
    private final SignerTrust signerTrust;

    /**
     * Trust in the certificate chain (leaf first) that signed issuer metadata (OID4VCI §12.2.3: the Wallet MUST establish
     * trust in the signer). Returns null when trusted, else why not.
     */
    @FunctionalInterface
    public interface SignerTrust {
        String untrustedReason(List<X509Certificate> chain);
    }

    private static final List<String> JWT_CLAIMS = List.of("iss", "sub", "aud", "iat", "nbf", "exp", "jti");

    public IssuerMetadataResolver(HttpFetcher http, Clock clock, Duration minTtl, Duration maxTtl, boolean requestSigned) {
        this(http, clock, minTtl, maxTtl, requestSigned, null);
    }

    /**
     * @param requestSigned ask for signed metadata ({@code Accept: application/jwt, application/json;q=0.9})
     * @param signerTrust   trust in signers; without it signed metadata is never accepted
     */
    public IssuerMetadataResolver(HttpFetcher http, Clock clock, Duration minTtl, Duration maxTtl, boolean requestSigned,
                                  SignerTrust signerTrust) {
        this.http = http;
        this.clock = clock;
        this.minTtl = minTtl;
        this.maxTtl = maxTtl;
        this.requestSigned = requestSigned;
        this.signerTrust = signerTrust;
    }

    public IssuerMetadata resolve(String credentialIssuer, Map<String, Map<String, Object>> policy)
            throws MetadataException {
        List<String> warnings = new ArrayList<>();
        URI url = WellKnown.inserted(credentialIssuer, WellKnown.CREDENTIAL_ISSUER);
        HttpFetcher.Response r = fetch(url, requestSigned ? "application/jwt, application/json;q=0.9" : "application/json");
        if (!r.isSuccess()) {
            // Some deployments still serve the pre-1.0 appended location; accept it with a warning.
            URI legacy = WellKnown.appended(credentialIssuer, WellKnown.CREDENTIAL_ISSUER);
            if (!legacy.equals(url)) {
                HttpFetcher.Response lr = fetch(legacy, "application/json");
                if (lr.isSuccess()) {
                    warnings.add("Metadata served only at the legacy appended location " + legacy);
                    r = lr;
                }
            }
        }
        if (!r.isSuccess()) {
            throw new MetadataException("metadata_not_found", "HTTP " + r.status() + " fetching " + url);
        }
        String signed = null;
        Boolean signedVerified = null;
        Map<String, Object> md;
        if ("application/jwt".equals(r.contentType())) {
            try {
                md = verifySigned(r.bodyAsString().trim(), credentialIssuer, warnings);
                signed = r.bodyAsString().trim();
                signedVerified = true;
            } catch (MetadataException e) {
                // Signed metadata whose signer cannot be trusted is rejected (OID4VCI §12.2.3); the plain JSON stands
                // on TLS alone, and clients that require signed metadata see signedMetadataVerified = false.
                warnings.add("Signed metadata rejected: " + e.getMessage());
                signedVerified = false;
                r = fetch(url, "application/json");
                if (!r.isSuccess() || "application/jwt".equals(r.contentType())) {
                    throw new MetadataException("metadata_invalid", "Signed metadata rejected (" + e.getMessage() + ") and no JSON metadata served");
                }
                md = parseJson(r);
            }
        } else {
            md = parseJson(r);
        }
        String declared = Json.string(md, "credential_issuer");
        if (declared == null) {
            throw new MetadataException("metadata_invalid", "credential_issuer is missing");
        }
        if (!declared.equals(credentialIssuer)) {
            if (Identifier.normalizeUrl(declared).equals(Identifier.normalizeUrl(credentialIssuer))) {
                warnings.add("credential_issuer '" + declared + "' differs from '" + credentialIssuer + "' only by normalization");
            } else {
                throw new MetadataException("issuer_mismatch",
                        "credential_issuer '" + declared + "' does not match the requested issuer '" + credentialIssuer + "'");
            }
        }
        boolean policyApplied = false;
        if (policy != null && policy.get("openid_credential_issuer") != null) {
            try {
                md = MetadataPolicy.apply(md, policy.get("openid_credential_issuer"));
                policyApplied = true;
            } catch (MetadataPolicy.PolicyException e) {
                throw new MetadataException("policy_violation", "Issuer metadata violates registry policy: " + e.getMessage());
            }
        }
        if (Json.string(md, "credential_endpoint") == null) {
            throw new MetadataException("metadata_invalid", "credential_endpoint is missing");
        }
        if (!(md.get("credential_configurations_supported") instanceof Map<?, ?>)) {
            throw new MetadataException("metadata_invalid", "credential_configurations_supported is missing");
        }
        Duration ttl = clamp(r.maxAge().orElse(maxTtl));

        Map<String, Map<String, Object>> asMetadata = new LinkedHashMap<>();
        List<String> servers = Json.strings(md.get("authorization_servers"));
        if (servers.isEmpty()) {
            servers = List.of(declared);
        }
        for (String as : servers) {
            try {
                Map<String, Object> asMd = resolveAuthorizationServer(as, warnings);
                if (policy != null && policy.get("oauth_authorization_server") != null) {
                    asMd = MetadataPolicy.apply(asMd, policy.get("oauth_authorization_server"));
                    policyApplied = true;
                }
                asMetadata.put(as, asMd);
            } catch (MetadataException e) {
                warnings.add("Authorization server " + as + ": " + e.getMessage());
            } catch (MetadataPolicy.PolicyException e) {
                warnings.add("Authorization server " + as + " violates registry policy: " + e.getMessage());
            }
        }
        Instant now = clock.instant();
        return new IssuerMetadata(declared, md, asMetadata, signed, signedVerified, policyApplied, now, now.plus(ttl), warnings);
    }

    /** RFC 8414 metadata with OpenID Connect Discovery as fallback; validates {@code issuer}. */
    public Map<String, Object> resolveAuthorizationServer(String issuer, List<String> warnings) throws MetadataException {
        for (URI url : List.of(WellKnown.inserted(issuer, WellKnown.OAUTH_AUTHORIZATION_SERVER),
                WellKnown.appended(issuer, WellKnown.OPENID_CONFIGURATION))) {
            HttpFetcher.Response r = fetch(url, "application/json");
            if (!r.isSuccess()) {
                continue;
            }
            Map<String, Object> md;
            try {
                md = Json.parseObject(r.body());
            } catch (RuntimeException e) {
                continue;
            }
            String declared = Json.string(md, "issuer");
            if (declared == null || !Identifier.normalizeUrl(declared).equals(Identifier.normalizeUrl(issuer))) {
                throw new MetadataException("issuer_mismatch", "AS metadata issuer '" + declared + "' does not match " + issuer);
            }
            if (!declared.equals(issuer)) {
                warnings.add("AS issuer '" + declared + "' differs from '" + issuer + "' only by normalization");
            }
            return md;
        }
        throw new MetadataException("metadata_not_found", "No authorization server metadata for " + issuer);
    }

    /** JWT VC Issuer Metadata (SD-JWT VC §5); returns null when absent. */
    public Map<String, Object> resolveJwtVcIssuer(String issuer) throws MetadataException {
        HttpFetcher.Response r = fetch(WellKnown.inserted(issuer, WellKnown.JWT_VC_ISSUER), "application/json");
        if (r.status() == 404) {
            return null;
        }
        if (!r.isSuccess()) {
            throw new MetadataException("metadata_not_found", "HTTP " + r.status() + " fetching jwt-vc-issuer metadata");
        }
        Map<String, Object> md = Json.parseObject(r.body());
        if (!issuer.equals(md.get("issuer"))) {
            throw new MetadataException("issuer_mismatch", "jwt-vc-issuer metadata issuer does not match " + issuer);
        }
        return md;
    }

    private static Map<String, Object> parseJson(HttpFetcher.Response r) throws MetadataException {
        try {
            return Json.parseObject(r.body());
        } catch (RuntimeException e) {
            throw new MetadataException("metadata_invalid", "Issuer metadata is not a JSON object");
        }
    }

    /**
     * {@code openidvci-issuer-metadata+jwt}: typ, an asymmetric alg, x5c key resolution with a signer certificate that is
     * not self-signed (HAIP 1.0 §4.1) and is bound to the issuer (SAN dNSName = its host, or SAN URI = its identifier),
     * the signature, {@code sub} and {@code credential_issuer} = the Credential Issuer, {@code iat}, expiry, and trust in
     * the signer. Returns the metadata parameters (JWT claims removed).
     */
    private Map<String, Object> verifySigned(String jwt, String credentialIssuer, List<String> warnings) throws MetadataException {
        try {
            JWSObject jws = JWSObject.parse(jwt);
            if (!"openidvci-issuer-metadata+jwt".equals(String.valueOf(jws.getHeader().getType()))) {
                throw new MetadataException("metadata_invalid", "Signed metadata has wrong typ " + jws.getHeader().getType());
            }
            if (JWSAlgorithm.Family.HMAC_SHA.contains(jws.getHeader().getAlgorithm())) {
                throw new MetadataException("metadata_invalid", "Signed metadata uses a symmetric algorithm");
            }
            Map<String, Object> claims = new LinkedHashMap<>(jws.getPayload().toJSONObject());
            if (!(claims.get("sub") instanceof String sub) || !Identifier.normalizeUrl(sub).equals(Identifier.normalizeUrl(credentialIssuer))) {
                throw new MetadataException("issuer_mismatch", "Signed metadata sub does not match the issuer");
            }
            if (!(claims.get("credential_issuer") instanceof String ci) || !Identifier.normalizeUrl(ci).equals(Identifier.normalizeUrl(credentialIssuer))) {
                throw new MetadataException("issuer_mismatch", "Signed metadata credential_issuer does not match the issuer");
            }
            if (!(claims.get("iat") instanceof Number)) {
                throw new MetadataException("metadata_invalid", "Signed metadata has no iat");
            }
            if (claims.get("exp") instanceof Number exp && exp.longValue() < clock.instant().getEpochSecond()) {
                throw new MetadataException("metadata_invalid", "Signed metadata has expired");
            }
            List<Base64> x5c = jws.getHeader().getX509CertChain();
            if (x5c == null || x5c.isEmpty()) {
                throw new MetadataException("untrusted_signer", "Signed metadata carries no x5c; its signer cannot be established");
            }
            List<X509Certificate> chain = new ArrayList<>();
            for (Base64 c : x5c) {
                chain.add(Certificates.fromDer(c.decode()));
            }
            X509Certificate leaf = chain.getFirst();
            if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
                throw new MetadataException("untrusted_signer", "Signed metadata is signed with a self-signed certificate");
            }
            String host = URI.create(credentialIssuer).getHost();
            boolean bound = Certificates.dnsNames(leaf).stream().anyMatch(n -> n.equalsIgnoreCase(host))
                    || Certificates.uriNames(leaf).stream().anyMatch(u -> Identifier.normalizeUrl(u).equals(Identifier.normalizeUrl(credentialIssuer)));
            if (!bound) {
                throw new MetadataException("untrusted_signer", "Signed metadata signer " + leaf.getSubjectX500Principal().getName()
                        + " is not bound to " + credentialIssuer + " (no matching SAN)");
            }
            if (!jws.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jws.getHeader(), leaf.getPublicKey()))) {
                throw new MetadataException("metadata_invalid", "Signed metadata signature does not verify");
            }
            String untrusted = signerTrust == null ? "no signer trust is configured" : signerTrust.untrustedReason(chain);
            if (untrusted != null) {
                throw new MetadataException("untrusted_signer", "Signed metadata signer is not trusted: " + untrusted);
            }
            warnings.add("Signed metadata verified (signer " + leaf.getSubjectX500Principal().getName() + ")");
            JWT_CLAIMS.forEach(claims::remove);
            return claims;
        } catch (MetadataException e) {
            throw e;
        } catch (Exception e) {
            throw new MetadataException("metadata_invalid", "Malformed signed metadata: " + e.getMessage(), e);
        }
    }

    private HttpFetcher.Response fetch(URI url, String accept) throws MetadataException {
        try {
            return http.get(url, accept);
        } catch (HttpFetcher.BlockedException e) {
            throw new MetadataException("url_not_allowed", e.getMessage(), e);
        } catch (IOException e) {
            throw new MetadataException("fetch_failed", "Fetching " + url + " failed: " + e.getMessage(), e);
        }
    }

    private Duration clamp(Duration d) {
        if (d.compareTo(minTtl) < 0) {
            return minTtl;
        }
        return d.compareTo(maxTtl) > 0 ? maxTtl : d;
    }
}
