package io.vctrust.trust.server.config;

import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/** {@code /actuator/health} component "trust": DOWN until the first load, then per-source status. */
@Component("trust")
public class TrustHealthIndicator implements HealthIndicator {

    private final SourceBootstrap bootstrap;
    private final TrustSourceManager manager;
    private final TrustRegistry registry;

    public TrustHealthIndicator(SourceBootstrap bootstrap, TrustSourceManager manager, TrustRegistry registry) {
        this.bootstrap = bootstrap;
        this.manager = manager;
        this.registry = registry;
    }

    @Override
    public Health health() {
        Map<String, Object> sources = new LinkedHashMap<>();
        for (SourceState s : manager.states()) {
            sources.put(s.id(), s.healthy() ? "UP" : s.enabled() ? (s.lastError() == null ? "PENDING" : "ERROR: " + s.lastError()) : "DISABLED");
        }
        Health.Builder b = bootstrap.isReady() ? Health.up() : Health.down().withDetail("reason", "loading trust sources");
        return b.withDetail("registryVersion", registry.snapshot().version())
                .withDetail("entities", registry.snapshot().entities().size())
                .withDetail("anchors", registry.snapshot().allAnchors().size())
                .withDetail("sources", sources)
                .build();
    }
}
