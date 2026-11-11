package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.Did;
import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;

import java.time.Clock;
import java.time.Duration;
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

    private final DidResolver resolver;
    private final ResourceCache<DidResolutionResult> cache;
    private final TrustProperties.Cache cfg;

    public DidService(DidResolver resolver, TrustProperties.Cache cfg, Clock clock) {
        this.resolver = resolver;
        this.cfg = cfg;
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
                    return DidResolutionResult.error(DidResolutionResult.INVALID_DID_DOCUMENT, "The DID document exceeds " + cfg.getMaxDocumentBytes() + " bytes");
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
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, e.getMessage());
        }
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
