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
import io.vctrust.trust.server.api.ApiException;
import io.vctrust.trust.server.cache.TtlCache;
import io.vctrust.trust.server.config.TrustProperties;
import org.springframework.http.HttpStatus;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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

    private final IssuerMetadataResolver resolver;
    private final TrustRegistry registry;
    private final TrustEvaluator evaluator;
    private final TtlCache<String, IssuerMetadata> cache;
    private final Clock clock;

    public MetadataService(IssuerMetadataResolver resolver, TrustRegistry registry, TrustEvaluator evaluator,
                           TrustProperties.Cache cfg, Clock clock) {
        this.resolver = resolver;
        this.registry = registry;
        this.evaluator = evaluator;
        this.clock = clock;
        this.cache = new TtlCache<>(cfg.getMaxEntries(), cfg.getStaleIfError(), clock);
        registry.onChange(s -> cache.invalidateAll());
    }

    public IssuerMetadataEnvelope issuer(String credentialIssuer, ClientProfile client) {
        if (credentialIssuer == null || !(credentialIssuer.startsWith("https://") || credentialIssuer.startsWith("http://"))) {
            throw ApiException.badRequest("invalid_request", "credential_issuer must be an https URL");
        }
        TrustedEntity entity = registry.snapshot().byIdentifier(Identifier.url(credentialIssuer)).stream()
                .filter(e -> client.accepts(e.frameworkId()))
                .filter(e -> e.hasRole(EntityRole.CREDENTIAL_ISSUER))
                .findFirst().orElse(null);
        if (entity == null && !client.allowUnregisteredMetadata()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "issuer_not_registered",
                    "Issuer is not registered in the frameworks accepted by client " + client.clientId());
        }
        Map<String, Map<String, Object>> policy = entity == null ? null : entity.metadataPolicy();
        String key = credentialIssuer + "|" + (entity == null ? "-" : entity.id());
        TtlCache.Hit<IssuerMetadata> hit;
        try {
            hit = cache.get(key, () -> resolver.resolve(credentialIssuer, policy),
                    md -> Duration.between(clock.instant(), md.expiresAt()));
        } catch (MetadataException e) {
            HttpStatus status = switch (e.code()) {
                case "metadata_not_found" -> HttpStatus.NOT_FOUND;
                case "url_not_allowed" -> HttpStatus.BAD_REQUEST;
                case "fetch_failed" -> HttpStatus.BAD_GATEWAY;
                default -> HttpStatus.UNPROCESSABLE_CONTENT;
            };
            throw new ApiException(status, e.code(), e.getMessage());
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof io.vctrust.trust.server.http.SafeHttpFetcher.BlockedRequestException b) {
                throw ApiException.badRequest("url_not_allowed", b.getMessage());
            }
            throw new ApiException(HttpStatus.BAD_GATEWAY, "fetch_failed", e.getMessage());
        }
        IssuerMetadata md = hit.value();
        TrustDecision decision = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                new TrustQuery.Subject(credentialIssuer, null, null, null),
                new TrustQuery.Context("oid4vci", null, null, null, null, null)), client);
        return new IssuerMetadataEnvelope(md.credentialIssuer(), md.issuer(), md.authorizationServers(),
                md.signedMetadata(), md.signedMetadataVerified(), md.policyApplied(), md.fetchedAt(), hit.expiresAt(),
                hit.stale(), md.warnings(), entity == null ? null : entity.id(), decision);
    }

    /** Remaining freshness in seconds, for Cache-Control. */
    public long maxAgeSeconds(IssuerMetadataEnvelope env) {
        return Math.max(0, Duration.between(clock.instant(), env.expiresAt()).toSeconds());
    }

    public static String jsonString(Object o) {
        return Json.write(o);
    }
}
