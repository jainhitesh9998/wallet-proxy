package io.vctrust.trust.server.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Cache with per-entry expiry and stale-if-error: an expired entry is refreshed on access; if the refresh
 * fails the stale value is served (flagged) for up to {@code staleIfError}. Concurrent loads of one key are
 * collapsed.
 */
public class TtlCache<K, V> {

    @FunctionalInterface
    public interface Loader<V> {
        V load() throws Exception;
    }

    /** A cached value with its freshness. */
    public record Hit<V>(V value, Instant storedAt, Instant expiresAt, boolean stale) {
    }

    private record Entry<V>(V value, Instant storedAt, Instant expiresAt) {
    }

    private final Cache<K, Entry<V>> cache;
    private final ConcurrentHashMap<K, Object> locks = new ConcurrentHashMap<>();
    private final Clock clock;

    public TtlCache(long maxEntries, Duration staleIfError, Clock clock) {
        this.clock = clock;
        this.cache = Caffeine.newBuilder().maximumSize(maxEntries).expireAfterWrite(staleIfError).recordStats().build();
    }

    public Hit<V> get(K key, Loader<V> loader, Function<V, Duration> ttl) throws Exception {
        Entry<V> e = cache.getIfPresent(key);
        Instant now = clock.instant();
        if (e != null && e.expiresAt().isAfter(now)) {
            return new Hit<>(e.value(), e.storedAt(), e.expiresAt(), false);
        }
        Object lock = locks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            try {
                e = cache.getIfPresent(key);
                now = clock.instant();
                if (e != null && e.expiresAt().isAfter(now)) {
                    return new Hit<>(e.value(), e.storedAt(), e.expiresAt(), false);
                }
                try {
                    V v = loader.load();
                    Instant exp = now.plus(ttl.apply(v));
                    cache.put(key, new Entry<>(v, now, exp));
                    return new Hit<>(v, now, exp, false);
                } catch (Exception ex) {
                    if (e != null) {
                        return new Hit<>(e.value(), e.storedAt(), e.expiresAt(), true);
                    }
                    throw ex;
                }
            } finally {
                locks.remove(key, lock);
            }
        }
    }

    public void invalidateAll() {
        cache.invalidateAll();
    }

    public long size() {
        return cache.estimatedSize();
    }

    public com.github.benmanes.caffeine.cache.stats.CacheStats stats() {
        return cache.stats();
    }
}
