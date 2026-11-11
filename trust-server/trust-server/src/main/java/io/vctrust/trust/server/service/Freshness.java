package io.vctrust.trust.server.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** For how long a client may reuse what the proxy holds. */
final class Freshness {

    private Freshness() {
    }

    /** The time left until {@code expiresAt}, zero when it has passed. */
    static Duration remaining(Instant expiresAt, Clock clock) {
        Duration d = Duration.between(clock.instant(), expiresAt);
        return d.isNegative() ? Duration.ZERO : d;
    }
}
