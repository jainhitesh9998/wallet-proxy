package io.vctrust.trust.server.config;

import io.vctrust.trust.core.registry.TrustSourceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;

/** Loads all trust sources once the application is ready, off the startup thread. */
@Component
public class SourceBootstrap {

    private static final Logger log = LoggerFactory.getLogger(SourceBootstrap.class);
    private final TrustSourceManager manager;

    public SourceBootstrap(TrustSourceManager manager) {
        this.manager = manager;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start() {
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
