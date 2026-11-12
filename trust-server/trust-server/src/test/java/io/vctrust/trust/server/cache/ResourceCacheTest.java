package io.vctrust.trust.server.cache;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResourceCacheTest {

    /** A clock the test moves. */
    static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-11-01T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }
    }

    static final class NotFound extends IOException {
        NotFound() {
            super("not found");
        }
    }

    final TestClock clock = new TestClock();
    final AtomicInteger loads = new AtomicInteger();

    ResourceCache<String> cache(boolean background) {
        return new ResourceCache<>(new ResourceCache.Settings(10_000, Duration.ofSeconds(30), Duration.ofHours(24), background),
                String::length, NotFound.class::isInstance, clock);
    }

    String get(ResourceCache<String> c, String value) throws Exception {
        return c.get("k", () -> { loads.incrementAndGet(); return value; }, v -> Duration.ofMinutes(10)).value();
    }

    @Test
    void servesFromCacheUntilExpiry() throws Exception {
        var c = cache(false);
        assertThat(get(c, "a")).isEqualTo("a");
        clock.advance(Duration.ofMinutes(9));
        assertThat(get(c, "b")).isEqualTo("a");
        clock.advance(Duration.ofMinutes(2));
        assertThat(get(c, "b")).isEqualTo("b");
        assertThat(loads).hasValue(2);
    }

    @Test
    void concurrentCallersShareOneLoadAndItsFailure() throws Exception {
        var c = cache(false);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<Thread> threads = new ArrayList<>();
        AtomicInteger failed = new AtomicInteger();
        for (int i = 0; i < 10; i++) {
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    c.get("k", () -> { loads.incrementAndGet(); entered.countDown(); release.await(); throw new IOException("upstream down"); },
                            v -> Duration.ofMinutes(10));
                } catch (Exception e) {
                    if (e.getMessage().equals("upstream down")) failed.incrementAndGet();
                }
            }));
        }
        entered.await();
        Thread.sleep(100);
        release.countDown();
        for (Thread t : threads) t.join();
        assertThat(failed).hasValue(10);
        assertThat(loads).hasValue(1);
    }

    @Test
    void remembersAFailureForTheNegativeTtl() {
        var c = cache(false);
        ResourceCache.Loader<String> failing = () -> { loads.incrementAndGet(); throw new IOException("upstream down"); };
        assertThatThrownBy(() -> c.get("k", failing, v -> Duration.ofMinutes(10))).hasMessage("upstream down");
        assertThatThrownBy(() -> c.get("k", failing, v -> Duration.ofMinutes(10))).hasMessage("upstream down");
        assertThat(loads).hasValue(1);
        clock.advance(Duration.ofSeconds(31));
        assertThatThrownBy(() -> c.get("k", failing, v -> Duration.ofMinutes(10))).hasMessage("upstream down");
        assertThat(loads).hasValue(2);
    }

    @Test
    void keepsServingAStaleValueThroughAnOutageButNotForever() throws Exception {
        var c = cache(false);
        get(c, "good");
        clock.advance(Duration.ofMinutes(11));
        ResourceCache.Loader<String> failing = () -> { loads.incrementAndGet(); throw new IOException("upstream down"); };
        var stale = c.get("k", failing, v -> Duration.ofMinutes(10));
        assertThat(stale.value()).isEqualTo("good");
        assertThat(stale.stale()).isTrue();
        // The failed refresh is not repeated until the negative TTL has passed.
        assertThat(c.get("k", failing, v -> Duration.ofMinutes(10)).stale()).isTrue();
        assertThat(loads).hasValue(2);
        clock.advance(Duration.ofHours(25));
        assertThatThrownBy(() -> c.get("k", failing, v -> Duration.ofMinutes(10))).hasMessage("upstream down");
    }

    @Test
    void aDefinitiveAnswerReplacesTheCachedValue() throws Exception {
        var c = cache(false);
        get(c, "good");
        clock.advance(Duration.ofMinutes(11));
        assertThatThrownBy(() -> c.get("k", () -> { throw new NotFound(); }, v -> Duration.ofMinutes(10))).isInstanceOf(NotFound.class);
    }

    @Test
    void refreshesInTheBackgroundWhenAskedTo() throws Exception {
        var c = cache(true);
        get(c, "old");
        clock.advance(Duration.ofMinutes(11));
        CountDownLatch refreshed = new CountDownLatch(1);
        var hit = c.get("k", () -> { try { return "new"; } finally { refreshed.countDown(); } }, v -> Duration.ofMinutes(10));
        assertThat(hit.value()).isEqualTo("old");
        assertThat(hit.stale()).isTrue();
        refreshed.await();
        // The refresh stores its value after the loader returns: wait for that, not for a fixed time.
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (!"new".equals(get(c, "unused")) && System.nanoTime() < deadline) Thread.sleep(10);
        assertThat(get(c, "unused")).isEqualTo("new");
    }

    @Test
    void aRefreshThatStartsAfterAnotherFinishedDoesNotLoadAgain() throws Exception {
        // Every read of a stale value asks for a refresh. One asked for before a refresh finished may start after it:
        // it must find the value fresh and leave it. Loading again would fetch the resource a second time, and here,
        // where the late loader returns something else, replace what the refresh stored.
        for (int round = 0; round < 300; round++) {
            var c = cache(true);
            AtomicInteger late = new AtomicInteger();
            c.get("k", () -> "old", v -> Duration.ofMinutes(10));
            clock.advance(Duration.ofMinutes(11));
            CountDownLatch refreshing = new CountDownLatch(1);
            c.get("k", () -> { refreshing.countDown(); return "new"; }, v -> Duration.ofMinutes(10));
            refreshing.await();
            long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
            String seen;
            do {
                seen = c.get("k", () -> { late.incrementAndGet(); return "late"; }, v -> Duration.ofMinutes(10)).value();
            } while ("old".equals(seen) && System.nanoTime() < deadline);
            Thread.sleep(2);  // the refreshes those reads asked for run now, if they run at all
            assertThat(c.get("k", () -> "unused", v -> Duration.ofMinutes(10)).value()).as("round %d", round).isEqualTo("new");
            assertThat(late).as("round %d", round).hasValue(0);
        }
    }

    @Test
    void doesNotCacheWhatMustNotBeStored() throws Exception {
        var c = cache(false);
        assertThat(c.get("k", () -> { loads.incrementAndGet(); return "a"; }, v -> Duration.ZERO).stale()).isFalse();
        c.get("k", () -> { loads.incrementAndGet(); return "a"; }, v -> Duration.ZERO);
        assertThat(loads).hasValue(2);
    }

    @Test
    void isBoundedByBytes() throws Exception {
        var c = cache(false);
        String big = "x".repeat(4_000);
        for (int i = 0; i < 20; i++) {
            c.get("k" + i, () -> big, v -> Duration.ofMinutes(10));
        }
        for (int i = 0; i < 50 && c.size() > 2; i++) Thread.sleep(20);
        assertThat(c.size()).isLessThanOrEqualTo(2);
    }
}
