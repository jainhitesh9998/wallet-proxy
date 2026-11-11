package io.vctrust.trust.server.service;

import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.IssuerMetadata;
import io.vctrust.trust.core.metadata.IssuerMetadataResolver;
import io.vctrust.trust.core.metadata.MetadataException;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;

import com.nimbusds.jose.JWSObject;
import io.vctrust.trust.core.x509.Certificates;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The OpenID4VCI metadata proxy: validated, cached issuer + AS metadata, curated by the registry's metadata
 * policy for registered issuers, returned together with a trust decision.
 */
public class MetadataService {

    /** Proxy response. */
    public record IssuerMetadataEnvelope(String credentialIssuer, Map<String, Object> credentialIssuerMetadata,
                                         Map<String, Map<String, Object>> authorizationServers, String signedMetadata,
                                         Boolean signedMetadataVerified, boolean policyApplied, Instant fetchedAt,
                                         Instant expiresAt, boolean stale, List<String> warnings, String entityId,
                                         TrustDecision trust) {
    }

    /**
     * Whether a metadata signer chain (leaf first) is trusted for one client: its frameworks' credential-issuer anchors, its
     * relaxed-profile and revocation policy. Null when trusted, else why not.
     */
    @FunctionalInterface
    public interface ClientSignerTrust {
        String untrustedReason(List<X509Certificate> chain, ClientProfile client);
    }

    private final IssuerMetadataResolver resolver;
    private final ClientSignerTrust signerTrust;
    private final TrustRegistry registry;
    private final TrustEvaluator evaluator;
    private final ResourceCache<IssuerMetadata> cache;
    private final int maxDocumentBytes;
    private final Clock clock;

    public MetadataService(IssuerMetadataResolver resolver, TrustRegistry registry, TrustEvaluator evaluator,
                           TrustProperties.Cache cfg, Clock clock, ClientSignerTrust signerTrust) {
        this.resolver = resolver;
        this.signerTrust = signerTrust;
        this.registry = registry;
        this.evaluator = evaluator;
        this.clock = clock;
        this.maxDocumentBytes = cfg.getMaxDocumentBytes();
        // Anything but a failed fetch is the issuer's answer (no metadata, wrong issuer, invalid): it replaces a cached copy.
        this.cache = new ResourceCache<>(cfg.settings(false), MetadataService::weight,
                e -> e instanceof MetadataException m && !"fetch_failed".equals(m.code()), clock);
    }

    private static int weight(IssuerMetadata md) {
        return Json.write(md.issuer()).length() + Json.write(md.authorizationServers()).length()
                + (md.signedMetadata() == null ? 0 : md.signedMetadata().length());
    }

    public IssuerMetadataEnvelope issuer(String credentialIssuer, ClientProfile client) {
        if (credentialIssuer == null || !(credentialIssuer.startsWith("https://") || credentialIssuer.startsWith("http://"))) {
            throw ServiceException.invalidRequest("invalid_request", "credential_issuer must be an https URL");
        }
        TrustedEntity entity = registry.snapshot().byIdentifier(Identifier.url(credentialIssuer)).stream()
                .filter(e -> client.accepts(e.frameworkId()))
                .filter(e -> e.hasRole(EntityRole.CREDENTIAL_ISSUER))
                .findFirst().orElse(null);
        if (entity == null && !client.allowUnregisteredMetadata()) {
            throw new ServiceException(ServiceException.Kind.FORBIDDEN, "issuer_not_registered",
                    "Issuer is not registered in the frameworks accepted by client " + client.clientId());
        }
        Map<String, Map<String, Object>> policy = entity == null ? null : entity.metadataPolicy();
        // The registry's metadata policy is part of the cached result, so a changed policy is a different entry.
        String key = credentialIssuer + "|" + (entity == null ? "-" : entity.id() + "|" + (policy == null ? 0 : policy.hashCode()));
        ResourceCache.Hit<IssuerMetadata> hit;
        try {
            hit = cache.get(key, () -> {
                IssuerMetadata md = resolver.resolve(credentialIssuer, policy);
                if (weight(md) > maxDocumentBytes) {
                    throw new MetadataException("metadata_invalid", "Issuer metadata exceeds " + maxDocumentBytes + " bytes");
                }
                return md;
            }, md -> Duration.between(clock.instant(), md.expiresAt()));
        } catch (MetadataException e) {
            ServiceException.Kind kind = switch (e.code()) {
                case "metadata_not_found" -> ServiceException.Kind.NOT_FOUND;
                case "url_not_allowed" -> ServiceException.Kind.INVALID_REQUEST;
                case "fetch_failed" -> ServiceException.Kind.UPSTREAM_FAILED;
                default -> ServiceException.Kind.UNPROCESSABLE;
            };
            throw new ServiceException(kind, e.code(), e.getMessage());
        } catch (ServiceException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof HttpFetcher.BlockedException b) {
                throw ServiceException.invalidRequest("url_not_allowed", b.getMessage());
            }
            throw ServiceException.upstreamFailed("fetch_failed", e.getMessage());
        }
        IssuerMetadata md = hit.value();
        // The cached result says the signer chains to some anchor; whether it is trusted is this client's question.
        String signed = md.signedMetadata();
        Boolean verified = md.signedMetadataVerified();
        List<String> warnings = md.warnings();
        if (signed != null && Boolean.TRUE.equals(verified) && signerTrust != null) {
            String reason = signerTrust.untrustedReason(signerChain(signed), client);
            if (reason != null) {
                signed = null;
                verified = false;
                warnings = new ArrayList<>(warnings);
                warnings.add("Signed metadata signer is not trusted for client " + client.clientId() + ": " + reason);
            }
        }
        if (client.requireSignedIssuerMetadata() && !Boolean.TRUE.equals(verified)) {
            throw new ServiceException(ServiceException.Kind.UNPROCESSABLE, "signed_metadata_required", credentialIssuer
                    + (verified == null ? " serves no signed metadata" : " serves signed metadata whose signer is not trusted")
                    + ", which client " + client.clientId() + " requires");
        }
        TrustDecision decision = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(credentialIssuer, null, null, null),
                new TrustQuery.Context("oid4vci", null, null, null, null, null)), client);
        return new IssuerMetadataEnvelope(md.credentialIssuer(), md.issuer(), md.authorizationServers(),
                signed, verified, md.policyApplied(), md.fetchedAt(), hit.expiresAt(),
                hit.stale(), warnings, entity == null ? null : entity.id(), decision);
    }

    private static List<X509Certificate> signerChain(String jwt) {
        try {
            List<X509Certificate> chain = new ArrayList<>();
            for (com.nimbusds.jose.util.Base64 c : JWSObject.parse(jwt).getHeader().getX509CertChain()) {
                chain.add(Certificates.fromDer(c.decode()));
            }
            return chain;
        } catch (Exception e) {
            throw new IllegalStateException("Verified signed metadata no longer parses", e);
        }
    }

    public void clear() {
        cache.invalidateAll();
    }

    /** Remaining freshness in seconds, for Cache-Control. */
    public long maxAgeSeconds(IssuerMetadataEnvelope env) {
        return Math.max(0, Duration.between(clock.instant(), env.expiresAt()).toSeconds());
    }

    public static String jsonString(Object o) {
        return Json.write(o);
    }
}
