package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.Did;
import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.server.cache.TtlCache;
import io.vctrust.trust.server.config.TrustProperties;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/** Cached DID resolution: honours document max-age, caches negative results briefly, serves stale on outage. */
public class DidService {

    private final DidResolver resolver;
    private final TtlCache<String, DidResolutionResult> cache;
    private final TrustProperties.Cache cfg;

    public DidService(DidResolver resolver, TrustProperties.Cache cfg, Clock clock) {
        this.resolver = resolver;
        this.cfg = cfg;
        this.cache = new TtlCache<>(cfg.getMaxEntries(), cfg.getStaleIfError(), clock);
    }

    private static final class TransientFailure extends Exception {
        final DidResolutionResult result;

        TransientFailure(DidResolutionResult result) {
            super(result.error().orElse("error"));
            this.result = result;
        }
    }

    public DidResolutionResult resolve(String didOrUrl) {
        String did;
        try {
            did = Did.parse(didOrUrl).did();
        } catch (IllegalArgumentException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        }
        try {
            TtlCache.Hit<DidResolutionResult> hit = cache.get(did, () -> {
                DidResolutionResult r = resolver.resolve(did);
                if (r.error().filter(DidResolutionResult.INTERNAL_ERROR::equals).isPresent()) {
                    throw new TransientFailure(r);
                }
                return r;
            }, this::ttl);
            Map<String, Object> cacheInfo = new LinkedHashMap<>();
            cacheInfo.put("storedAt", hit.storedAt().toString());
            cacheInfo.put("expiresAt", hit.expiresAt().toString());
            cacheInfo.put("stale", hit.stale());
            return hit.value().withResolutionMetadata("cache", cacheInfo);
        } catch (TransientFailure e) {
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

    public void clear() {
        cache.invalidateAll();
    }

    public long cacheSize() {
        return cache.size();
    }
}
