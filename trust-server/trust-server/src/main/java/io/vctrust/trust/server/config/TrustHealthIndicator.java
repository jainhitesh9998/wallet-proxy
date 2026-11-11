package io.vctrust.trust.server.config;

import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code /actuator/health} component "trust": DOWN until every required source has loaded once (no snapshot is served
 * before that), then UP with each source's state. A required source that keeps failing after its first load shows as
 * an error while the service goes on serving its last good data.
 *
 * <p>The health endpoint is public and by default shows the status only ({@code management.endpoint.health.show-details});
 * the same states are served to admin clients at {@code GET /admin/v1/sources}.
 */
@Component("trust")
public class TrustHealthIndicator implements HealthIndicator {

    private final TrustSourceManager manager;
    private final TrustRegistry registry;

    public TrustHealthIndicator(TrustSourceManager manager, TrustRegistry registry) {
        this.manager = manager;
        this.registry = registry;
    }

    @Override
    public Health health() {
        Map<String, Object> sources = new LinkedHashMap<>();
        for (SourceState s : manager.states()) {
            sources.put(s.id(), s.healthy() ? "UP" : s.enabled() ? (s.lastError() == null ? "PENDING" : "ERROR: " + s.lastError()) : "DISABLED");
        }
        Health.Builder b = manager.ready() ? Health.up() : Health.down().withDetail("waitingFor", manager.waitingFor());
        return b.withDetail("registryVersion", registry.snapshot().version())
                .withDetail("entities", registry.snapshot().entities().size())
                .withDetail("anchors", registry.snapshot().allAnchors().size())
                .withDetail("sources", sources)
                .build();
    }
}
