package io.vctrust.trust.server.service;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Relay for credential status lists (IETF Token Status List, W3C Bitstring Status List). Lists are signed by
 * their issuer and verified on the device; the relay passes them through byte for byte, caching them as the
 * upstream allows (bounded by {@code status-list-max-ttl}). Through the relay the issuer does not see the device;
 * the service sees which list was asked for.
 */
public class StatusListRelay {

    /** In the order the relay prefers them. */
    public static final List<String> TYPES = List.of("application/statuslist+jwt", "application/statuslist+cwt",
            "application/vc+ld+json", "application/vc+jwt", "application/vc", "application/ld+json", "application/json");
    private static final Set<String> SPECIFIC = Set.copyOf(TYPES.subList(0, 5));

    /** A relayed status list with the instant the cached copy expires ({@code expiresAt} = fetch time: not cached). */
    public record Relayed(byte[] body, String contentType, Instant expiresAt) {
    }

    /** The upstream answered with something that is not a status list. */
    public static class InvalidStatusListException extends IOException {
        public InvalidStatusListException(String message) {
            super(message);
        }
    }

    /** What is cached: the list as fetched, and for how long the upstream lets it be reused. */
    private record Fetched(byte[] body, String contentType, Duration ttl) {
    }

    private final HttpFetcher http;
    private final TrustProperties.Revocation cfg;
    private final ResourceCache<Fetched> cache;

    public StatusListRelay(HttpFetcher http, TrustProperties.Revocation cfg, ResourceCache.Settings cache, Clock clock) {
        this.http = http;
        this.cfg = cfg;
        this.cache = new ResourceCache<>(cache, f -> f.body().length,
                e -> e instanceof InvalidStatusListException || (e instanceof HttpFetcher.HttpStatusException h && h.status() >= 400 && h.status() < 500), clock);
    }

    /**
     * The Accept header sent upstream: the status list types the client named, in the relay's own order, or all of
     * them. Only known types pass, so the cache is keyed by one of a handful of strings, never by caller-chosen text.
     */
    static String accept(String requested) {
        List<String> named = requested == null ? List.of() : Arrays.stream(requested.split(","))
                .map(t -> t.split(";")[0].trim().toLowerCase(Locale.ROOT)).filter(SPECIFIC::contains).toList();
        return TYPES.stream().filter(t -> named.isEmpty() || named.contains(t) || !SPECIFIC.contains(t))
                .map(t -> SPECIFIC.contains(t) ? t : t + ";q=0.9").collect(Collectors.joining(", "));
    }

    public Relayed fetch(String uri, String requestedAccept) throws IOException {
        String accept = accept(requestedAccept);
        try {
            ResourceCache.Hit<Fetched> hit = cache.get(uri + "|" + accept, () -> download(uri, accept), Fetched::ttl);
            return new Relayed(hit.value().body(), hit.value().contentType(), hit.expiresAt());
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    public void clear() {
        cache.invalidateAll();
    }

    private Fetched download(String uri, String accept) throws IOException {
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
        return new Fetched(r.body(), r.header("Content-Type").orElse(type), ttl);
    }
}
