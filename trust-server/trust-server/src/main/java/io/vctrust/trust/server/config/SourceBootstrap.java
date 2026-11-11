package io.vctrust.trust.server.config;

import io.vctrust.trust.core.registry.TrustSourceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;

/** Loads all trust sources once the application is ready, off the startup thread. */
@Component
public class SourceBootstrap {

    private static final Logger log = LoggerFactory.getLogger(SourceBootstrap.class);
    private final TrustSourceManager manager;
    private final TrustProperties props;
    private final Environment environment;

    public SourceBootstrap(TrustSourceManager manager, TrustProperties props, Environment environment) {
        this.manager = manager;
        this.props = props;
        this.environment = environment;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start() {
        if (environment.matchesProfiles("demo")) {
            log.warn("The demo profile is active: its API keys, the admin key included, are published with the source code. "
                    + "Anyone who can reach this service can change what it trusts. Do not expose it.");
        } else if (props.getClients().isEmpty() && !props.getAnonymous().isEnabled()) {
            log.warn("No clients are configured (trust.clients): every API request will be refused. "
                    + "For the demo configuration start with --spring.profiles.active=demo.");
        }
        Thread t = new Thread(() -> {
            long t0 = System.currentTimeMillis();
            manager.start();
            if (manager.ready()) {
                log.info("Trust registry ready in {} ms", System.currentTimeMillis() - t0);
            } else {
                log.warn("Trust registry not ready: required sources {} have not loaded; they are retried", manager.waitingFor());
            }
        }, "trust-bootstrap");
        t.setDaemon(true);
        t.start();
    }
}
