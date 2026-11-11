package io.vctrust.trust.server.service;

import io.vctrust.trust.core.registry.TrustSourceManager;

/**
 * Whether the registry may be served: not until every required trust source has loaded. A registry that lacks a
 * source looks, to a client, like that source's parties having been delisted: a snapshot built from it would take
 * trust away from wallets that had it.
 */
public class RegistryReadiness {

    private final TrustSourceManager sources;

    public RegistryReadiness(TrustSourceManager sources) {
        this.sources = sources;
    }

    /** @throws ServiceException {@code not_ready} while a required source has not loaded */
    public void requireReady() {
        if (!sources.ready()) {
            throw new ServiceException(ServiceException.Kind.UNAVAILABLE, "not_ready",
                    "Trust sources are still loading: " + String.join(", ", sources.waitingFor()));
        }
    }
}
