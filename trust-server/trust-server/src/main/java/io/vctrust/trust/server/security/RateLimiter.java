package io.vctrust.trust.server.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.Optional;
import java.util.function.LongSupplier;

/** Token buckets per caller key: {@code burst} requests at once, refilled at {@code requestsPerMinute}. */
public class RateLimiter {

    private final int defaultPerMinute;
    private final int burst;
    private final LongSupplier nanos;
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterAccess(Duration.ofMinutes(10))
            .build();

    public RateLimiter(int defaultPerMinute, int burst) {
        this(defaultPerMinute, burst, System::nanoTime);
    }

    RateLimiter(int defaultPerMinute, int burst, LongSupplier nanos) {
        if (defaultPerMinute <= 0 || burst <= 0) {
            throw new IllegalArgumentException("trust.auth.rate-limit: requests-per-minute and burst must be positive");
        }
        this.defaultPerMinute = defaultPerMinute;
        this.burst = burst;
        this.nanos = nanos;
    }

    /** Takes one token; empty when allowed, otherwise how long until the next token. */
    public Optional<Duration> acquire(String key, Integer perMinute) {
        int rate = perMinute == null || perMinute <= 0 ? defaultPerMinute : perMinute;
        Bucket b = buckets.get(key, k -> new Bucket(burst, nanos.getAsLong()));
        return b.take(rate, burst, nanos.getAsLong());
    }

    /** Whether {@code key} has no token left right now, without taking one. */
    public boolean exhausted(String key, Integer perMinute) {
        int rate = perMinute == null || perMinute <= 0 ? defaultPerMinute : perMinute;
        Bucket b = buckets.getIfPresent(key);
        return b != null && b.empty(rate, burst, nanos.getAsLong());
    }

    private static final class Bucket {
        private double tokens;
        private long last;

        Bucket(int burst, long now) {
            this.tokens = burst;
            this.last = now;
        }

        synchronized boolean empty(int perMinute, int burst, long now) {
            return Math.min(burst, tokens + (now - last) * (perMinute / 60e9)) < 1;
        }

        synchronized Optional<Duration> take(int perMinute, int burst, long now) {
            double perNano = perMinute / 60e9;
            tokens = Math.min(burst, tokens + (now - last) * perNano);
            last = now;
            if (tokens >= 1) {
                tokens -= 1;
                return Optional.empty();
            }
            return Optional.of(Duration.ofNanos((long) Math.ceil((1 - tokens) / perNano)));
        }
    }
}
