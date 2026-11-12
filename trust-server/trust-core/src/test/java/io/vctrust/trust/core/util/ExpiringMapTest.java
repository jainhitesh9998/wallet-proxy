package io.vctrust.trust.core.util;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class ExpiringMapTest {

    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-12T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    @Test
    void anEntryIsServedUntilItExpiresAndTheLeastRecentlyUsedGoesWhenFull() {
        MutableClock clock = new MutableClock();
        ExpiringMap<String, String> map = new ExpiringMap<>(2, clock);
        map.put("a", "A", clock.now.plusSeconds(60));
        map.put("b", "B", clock.now.plusSeconds(60));
        assertThat(map.get("a")).contains("A");
        map.put("c", "C", clock.now.plusSeconds(60));   // b was used least recently
        assertThat(map.get("b")).isEmpty();
        assertThat(map.get("a")).contains("A");
        clock.now = clock.now.plusSeconds(60);
        assertThat(map.get("a")).isEmpty();
    }

    @Test
    void expiredEntriesAreDroppedWhenSomethingIsPutNotOnlyWhenTheirKeyIsAskedAgain() {
        // The keys are chosen by callers: entries nobody asks about again would otherwise stay until the map is full,
        // and hold what they hold for as long.
        MutableClock clock = new MutableClock();
        ExpiringMap<String, String> map = new ExpiringMap<>(1_000, clock);
        for (int i = 0; i < 500; i++) {
            map.put("short-" + i, "v", clock.now.plusSeconds(30));
        }
        map.put("long", "v", clock.now.plusSeconds(600));
        assertThat(map.size()).isEqualTo(501);
        clock.now = clock.now.plusSeconds(31);
        map.put("next", "v", clock.now.plusSeconds(30));
        assertThat(map.size()).isEqualTo(2);
        assertThat(map.get("long")).contains("v");
        assertThat(map.get("next")).contains("v");
    }
}
