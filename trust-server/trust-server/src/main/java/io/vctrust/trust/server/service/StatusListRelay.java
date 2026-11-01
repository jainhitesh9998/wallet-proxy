package io.vctrust.trust.server.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

/**
 * Relays credential status lists (IETF Token Status List as JWT / CWT, W3C Bitstring Status List credentials)
 * for clients that opt in, so the issuer does not see the holder's network address. The lists are signed by
 * their issuer and verified on the device; the relay passes them through byte for byte, caching them as the
 * upstream allows (bounded by {@code status-list-max-ttl}). The service learns which status list was fetched, so
 * clients use the relay only by choice.
 */
public class StatusListRelay {

    private static final Logger log = LoggerFactory.getLogger(StatusListRelay.class);
    public static final Set<String> TYPES = Set.of("application/statuslist+jwt", "application/statuslist+cwt",
            "application/vc+ld+json", "application/vc", "application/vc+jwt", "application/ld+json", "application/json");
    static final String DEFAULT_ACCEPT = "application/statuslist+jwt, application/statuslist+cwt, application/vc+ld+json, "
            + "application/vc+jwt, application/vc, application/ld+json;q=0.9, application/json;q=0.9";

    /** A relayed status list with the instant the cached copy expires ({@code expiresAt} = fetch time: not cached). */
    public record Relayed(byte[] body, String contentType, Instant expiresAt) {
    }

    /** The upstream answered with something that is not a status list. */
    public static class InvalidStatusListException extends IOException {
        public InvalidStatusListException(String message) {
            super(message);
        }
    }

    private final HttpFetcher http;
    private final TrustProperties.Revocation cfg;
    private final Clock clock;
    private final Cache<String, Relayed> cache;

    public StatusListRelay(HttpFetcher http, TrustProperties.Revocation cfg, Clock clock) {
        this.http = http;
        this.cfg = cfg;
        this.clock = clock;
        this.cache = Caffeine.newBuilder().maximumSize(1_000).expireAfterWrite(cfg.getStatusListMaxTtl()).build();
    }

    /** The client's Accept header when it asks only for status list types; otherwise a default. */
    static String accept(String requested) {
        if (requested == null || requested.isBlank()) {
            return DEFAULT_ACCEPT;
        }
        boolean allowed = Arrays.stream(requested.split(",")).map(t -> t.split(";")[0].trim().toLowerCase(Locale.ROOT))
                .allMatch(t -> TYPES.contains(t) || "*/*".equals(t));
        return allowed ? requested : DEFAULT_ACCEPT;
    }

    public Relayed fetch(String uri, String requestedAccept) throws IOException {
        String accept = accept(requestedAccept);
        String key = uri + "|" + accept;
        Instant now = clock.instant();
        Relayed hit = cache.getIfPresent(key);
        if (hit != null && hit.expiresAt().isAfter(now)) {
            return hit;
        }
        log.debug("Relaying status list {}", uri);
        HttpFetcher.Response r = http.fetchOk(HttpFetcher.Request.get(URI.create(uri), accept));
        String type = r.contentType();
        if (!TYPES.contains(type)) {
            throw new InvalidStatusListException("Upstream returned " + (type.isEmpty() ? "no content type" : type)
                    + ", not a status list");
        }
        if (r.body().length > cfg.getMaxStatusListBytes()) {
            throw new InvalidStatusListException("Status list exceeds " + cfg.getMaxStatusListBytes() + " bytes");
        }
        Duration ttl = r.maxAge().orElse(cfg.getStatusListDefaultTtl());
        if (ttl.compareTo(cfg.getStatusListMaxTtl()) > 0) {
            ttl = cfg.getStatusListMaxTtl();
        }
        Relayed out = new Relayed(r.body(), r.header("Content-Type").orElse(type), now.plus(ttl.isNegative() ? Duration.ZERO : ttl));
        if (ttl.isPositive()) {
            cache.put(key, out);
        }
        return out;
    }
}
