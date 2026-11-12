package io.vctrust.trust.server.service;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;

/**
 * The JSON-LD context relay: a context document at a URL a client names, byte for byte as its host served it.
 *
 * <p>The relay neither signs nor vouches. A context decides what a Data Integrity signature covers, and a device
 * takes one as genuine only when its SHA-256 is the digest its snapshot carries for that URL; a context the snapshot
 * does not know stays "not vouched for" whichever way it came. That is why the bytes are passed on unchanged: a
 * re-serialized document would have another digest.
 *
 * <p>Only what has the shape of a context is passed on: a JSON object with an {@code @context} member, no larger
 * than {@code trust.cache.max-document-bytes} ({@link ContextService}). The relay is otherwise a way to read any
 * JSON from where the service stands. Decides whether the relay is on, which URLs may be asked for, and what a
 * failed fetch means to the caller.
 */
public class ContextRelay {

    /** A relayed context document, and for how long the copy may be reused. */
    public record Relayed(byte[] body, Duration maxAge) {
    }

    private final ContextService contexts;
    private final TrustProperties.Cache cfg;
    private final Clock clock;

    public ContextRelay(ContextService contexts, TrustProperties.Cache cfg, Clock clock) {
        this.contexts = contexts;
        this.cfg = cfg;
        this.clock = clock;
    }

    public Relayed relay(String url) {
        if (!cfg.isRelayContexts()) {
            throw ServiceException.notFound("The JSON-LD context relay is disabled");
        }
        RelayTarget.check(url);
        ContextService.Relayed r;
        try {
            r = contexts.relay(url);
        } catch (HttpFetcher.BlockedException e) {
            throw ServiceException.invalidRequest("invalid_request", e.getMessage());
        } catch (IllegalArgumentException e) {
            throw ServiceException.upstreamFailed("invalid_context", e.getMessage());
        } catch (IOException e) {
            throw ServiceException.upstreamFailed("upstream_unavailable", "JSON-LD context unavailable: " + e.getMessage());
        }
        return new Relayed(r.body(), Freshness.remaining(r.expiresAt(), clock));
    }
}
