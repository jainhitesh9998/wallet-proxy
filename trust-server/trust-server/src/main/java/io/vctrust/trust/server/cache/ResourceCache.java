package io.vctrust.trust.server.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;

/**
 * The proxy's cache. Everything the service fetches on behalf of clients (issuer metadata, DID documents, CRLs,
 * status lists, JSON-LD contexts) goes through one of these, so every kind of resource behaves the same way:
 *
 * <ul>
 * <li>one fetch per key at a time: callers that arrive meanwhile share its outcome, success or failure;</li>
 * <li>a failure is remembered for a short while, so an outage upstream does not become a queue of retries;</li>
 * <li>a value past its expiry keeps being served, flagged stale, while a refresh fails with a transient error, up
 *     to {@code staleIfError}; a definitive answer such as "not found" replaces it;</li>
 * <li>optionally a stale value is returned at once and refreshed in the background;</li>
 * <li>the cache is bounded by weight in bytes, not by the number of entries, so large documents cannot fill it.</li>
 * </ul>
 */
public final class ResourceCache<V> {

    @FunctionalInterface
    public interface Loader<V> {
        V load() throws Exception;
    }

    /** A cached value; {@code stale}: past its expiry and served because it could not be refreshed (yet). */
    public record Hit<V>(V value, Instant storedAt, Instant expiresAt, boolean stale) {
    }

    /**
     * @param maxBytes            bound on the summed weights of the entries
     * @param negativeTtl         how long a failure is remembered, and how long a failed refresh is not retried
     * @param staleIfError        how long past its expiry a value may stand in for one that cannot be fetched
     * @param refreshInBackground serve a stale value at once and refresh it off the request
     */
    public record Settings(long maxBytes, Duration negativeTtl, Duration staleIfError, boolean refreshInBackground) {
    }

    private sealed interface Entry<V> permits Value, Failure {
    }

    /** @param retryAfter a refresh failed: not before this instant is another one attempted */
    private record Value<V>(V value, Instant storedAt, Instant expiresAt, Instant retryAfter, int weight) implements Entry<V> {
    }

    private record Failure<V>(Exception error, Instant until) implements Entry<V> {
    }

    private static final int FAILURE_WEIGHT = 512;

    private final Cache<String, Entry<V>> cache;
    private final ConcurrentHashMap<String, CompletableFuture<Entry<V>>> inFlight = new ConcurrentHashMap<>();
    private final Settings settings;
    private final ToIntFunction<V> weigher;
    private final Predicate<Exception> definitive;
    private final Clock clock;

    /**
     * @param weigher    approximate size of a value in bytes
     * @param definitive failures that are an answer rather than an outage (the resource does not exist): they replace
     *                   a cached value instead of leaving it to be served stale
     */
    public ResourceCache(Settings settings, ToIntFunction<V> weigher, Predicate<Exception> definitive, Clock clock) {
        this.settings = settings;
        this.weigher = weigher;
        this.definitive = definitive;
        this.clock = clock;
        // Entries are evicted by weight; whether one may still be used is decided against the clock on every read.
        this.cache = Caffeine.newBuilder().maximumWeight(settings.maxBytes())
                .weigher((String k, Entry<V> e) -> k.length() + (e instanceof Value<V> v ? v.weight() : FAILURE_WEIGHT))
                .expireAfterWrite(settings.staleIfError().plusDays(1)).recordStats().build();
    }

    /**
     * @param ttl how long a loaded value is fresh; zero or negative means it is not cached at all
     * @throws Exception the loader's failure, also for callers that shared the load and for the negative TTL after it
     */
    public Hit<V> get(String key, Loader<V> loader, Function<V, Duration> ttl) throws Exception {
        Instant now = clock.instant();
        Entry<V> entry = cache.getIfPresent(key);
        if (entry instanceof Value<V> v) {
            if (v.expiresAt().isAfter(now)) {
                return new Hit<>(v.value(), v.storedAt(), v.expiresAt(), false);
            }
            if (usableStale(v, now)) {
                if (now.isBefore(v.retryAfter())) {
                    return new Hit<>(v.value(), v.storedAt(), v.expiresAt(), true);
                }
                if (settings.refreshInBackground()) {
                    Thread.ofVirtual().name("resource-refresh").start(() -> load(key, loader, ttl));
                    return new Hit<>(v.value(), v.storedAt(), v.expiresAt(), true);
                }
            }
        } else if (entry instanceof Failure<V> f && f.until().isAfter(now)) {
            throw f.error();
        }
        Entry<V> loaded;
        try {
            loaded = load(key, loader, ttl).get();
        } catch (ExecutionException e) {
            throw e.getCause() instanceof Exception ex ? ex : e;
        }
        if (loaded instanceof Failure<V> f) {
            throw f.error();
        }
        Value<V> v = (Value<V>) loaded;
        // A value kept through a failed refresh carries the instant before which no retry is made.
        return new Hit<>(v.value(), v.storedAt(), v.expiresAt(), v.retryAfter() != Instant.MIN);
    }

    /**
     * Starts a load unless one is running for the key; the first caller runs it on its own thread. A caller decides to
     * load from what it read before it got here, and a load may have finished in between (a refresh in the background
     * is asked for by every read of the stale value, and starts when its thread does). A load stores its value before
     * it gives up its place, so whoever holds the place sees what the last load stored: a value that is fresh by then
     * is that load's answer, and the resource is not fetched a second time.
     */
    private CompletableFuture<Entry<V>> load(String key, Loader<V> loader, Function<V, Duration> ttl) {
        CompletableFuture<Entry<V>> mine = new CompletableFuture<>();
        CompletableFuture<Entry<V>> running = inFlight.putIfAbsent(key, mine);
        if (running != null) {
            return running;
        }
        try {
            mine.complete(cache.getIfPresent(key) instanceof Value<V> v && v.expiresAt().isAfter(clock.instant())
                    ? v : fetch(key, loader, ttl));
        } catch (RuntimeException | Error e) {
            mine.completeExceptionally(e);
        } finally {
            inFlight.remove(key, mine);
        }
        return mine;
    }

    private Entry<V> fetch(String key, Loader<V> loader, Function<V, Duration> ttl) {
        Instant now = clock.instant();
        try {
            V loaded = loader.load();
            Duration fresh = ttl.apply(loaded);
            if (fresh == null || fresh.isNegative()) {
                fresh = Duration.ZERO;
            }
            Value<V> value = new Value<>(loaded, now, now.plus(fresh), Instant.MIN, weigher.applyAsInt(loaded));
            if (fresh.isPositive()) {
                cache.put(key, value);
            } else {
                cache.invalidate(key);
            }
            return value;
        } catch (Exception e) {
            if (cache.getIfPresent(key) instanceof Value<V> old && usableStale(old, now) && !definitive.test(e)) {
                Value<V> kept = new Value<>(old.value(), old.storedAt(), old.expiresAt(), now.plus(settings.negativeTtl()), old.weight());
                cache.put(key, kept);
                return kept;
            }
            Failure<V> failure = new Failure<>(e, now.plus(settings.negativeTtl()));
            if (settings.negativeTtl().isPositive()) {
                cache.put(key, failure);
            } else {
                cache.invalidate(key);
            }
            return failure;
        }
    }

    private boolean usableStale(Value<V> v, Instant now) {
        return !now.isAfter(v.expiresAt().plus(settings.staleIfError()));
    }

    public void invalidate(String key) {
        cache.invalidate(key);
    }

    public void invalidateAll() {
        cache.invalidateAll();
    }

    public long size() {
        return cache.estimatedSize();
    }

    public CacheStats stats() {
        return cache.stats();
    }
}
