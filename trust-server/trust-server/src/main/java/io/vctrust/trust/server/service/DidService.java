package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.Did;
import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cached DID resolution. A document is fresh for its own max-age (at most {@code did-ttl}); "not found" and other
 * answers of the method are cached briefly; an outage (the method could not be asked) leaves the last good
 * document in place, flagged stale, and is itself remembered so that it is not retried on every call.
 */
public class DidService {

    /** The method could not be asked: an outage, not an answer about the DID. */
    private static final class Unavailable extends Exception {
        final DidResolutionResult result;

        Unavailable(DidResolutionResult result) {
            super(result.error().orElse("error"));
            this.result = result;
        }
    }

    /** What a client is told about one DID: the resolution result, and for how long it may be reused. */
    public record Answer(DidResolutionResult result, Duration maxAge) {
    }

    private final DidResolver resolver;
    private final ResourceCache<DidResolutionResult> cache;
    private final TrustProperties.Cache cfg;
    private final Clock clock;

    public DidService(DidResolver resolver, TrustProperties.Cache cfg, Clock clock) {
        this.resolver = resolver;
        this.cfg = cfg;
        this.clock = clock;
        // Documents are refreshed in the background: a snapshot build or an evaluation never waits on a slow host
        // for a DID it already knows.
        this.cache = new ResourceCache<>(cfg.settings(true), DidService::weight, e -> false, clock);
    }

    public DidResolutionResult resolve(String didOrUrl) {
        String did;
        try {
            did = Did.parse(didOrUrl).did();
        } catch (IllegalArgumentException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        }
        try {
            ResourceCache.Hit<DidResolutionResult> hit = cache.get(did, () -> {
                DidResolutionResult r = resolver.resolve(did);
                if (r.error().filter(DidResolutionResult.INTERNAL_ERROR::equals).isPresent()) {
                    throw new Unavailable(r);
                }
                if (weight(r) > cfg.getMaxDocumentBytes()) {
                    // Larger than any document this service passes on: the host gave nothing usable, like any other
                    // answer that is not a DID document.
                    return DidResolutionResult.upstreamError(DidResolutionResult.INVALID_DID_DOCUMENT,
                            "The DID document exceeds " + cfg.getMaxDocumentBytes() + " bytes");
                }
                return r;
            }, this::ttl);
            Map<String, Object> cacheInfo = new LinkedHashMap<>();
            cacheInfo.put("storedAt", hit.storedAt().toString());
            cacheInfo.put("expiresAt", hit.expiresAt().toString());
            cacheInfo.put("stale", hit.stale());
            return hit.value().withResolutionMetadata("cache", cacheInfo);
        } catch (Unavailable e) {
            return e.result;
        } catch (Exception e) {
            // A failure of this code, not of where the DID lives.
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, e.getMessage());
        }
    }

    /**
     * Resolves a DID as a client names it in a URL path: as it stands, or percent-encoded as a whole
     * ({@code did%3Aweb%3A...}).
     *
     * <p>What the method says about the DID is the answer, also when it is an error: the DID does not exist, is not
     * valid, or is of a method this service does not resolve. When where the DID lives gave no usable answer (its
     * host, registry or resolver could not be reached, failed, or served something that is not the DID's document) and
     * no earlier document stands in, the relay failed upstream, and says so as every relay of this service does: the
     * service works, and the client may ask where the DID lives itself. A failure of this service's own code stays an
     * internal error of the DID resolution.
     *
     * @throws ServiceException {@code upstream_unavailable} when where the DID lives gave no usable answer
     */
    public Answer resolveFromPath(String did) {
        if (did.startsWith("did%3A") || did.startsWith("did%3a")) {
            did = URLDecoder.decode(did, StandardCharsets.UTF_8);
        }
        DidResolutionResult r = resolve(did);
        if (r.upstreamFailed()) {
            throw ServiceException.upstreamFailed("upstream_unavailable",
                    "DID document unavailable: " + r.errorDetail().orElse(r.error().orElse("no answer")));
        }
        return new Answer(r, maxAge(r));
    }

    private Duration maxAge(DidResolutionResult r) {
        if (!r.isSuccess()) {
            return Duration.ofSeconds(30);
        }
        if (r.didResolutionMetadata().get("cache") instanceof Map<?, ?> m && m.get("expiresAt") instanceof String exp) {
            return Freshness.remaining(Instant.parse(exp), clock);
        }
        return Duration.ofMinutes(5);
    }

    private Duration ttl(DidResolutionResult r) {
        if (!r.isSuccess()) {
            return cfg.getNegativeTtl();
        }
        Object maxAge = r.didResolutionMetadata().get("maxAgeSeconds");
        if (maxAge instanceof Number n) {
            Duration d = Duration.ofSeconds(n.longValue());
            return d.compareTo(cfg.getDidTtl()) < 0 ? d : cfg.getDidTtl();
        }
        return cfg.getDidTtl();
    }

    private static int weight(DidResolutionResult r) {
        return r.didDocument() == null ? 256 : Json.write(r.didDocument()).length();
    }

    public void clear() {
        cache.invalidateAll();
    }

    public long cacheSize() {
        return cache.size();
    }
}
