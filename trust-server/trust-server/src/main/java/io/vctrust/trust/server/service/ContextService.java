package io.vctrust.trust.server.service;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The JSON-LD contexts of the parties the registry lists. Verifying a Data Integrity proof means loading every
 * context a credential names, and a context fetched at that moment is an unauthenticated input that decides what the
 * signature covers. The service fetches each context once, and the snapshot carries it with its SHA-256, so a wallet
 * verifies against the bytes the service saw and never contacts the context's host.
 *
 * <p>An operator can pin a context's digest ({@code contexts: [{url, sha256}]} on an entity). A pinned context whose
 * content no longer matches is not shipped; the pin still is, so a wallet that fetches the context itself can refuse
 * it. An unpinned listing of the same URL does not replace a pin. An unpinned context that changes is shipped as it
 * now is, and the change is logged.
 *
 * <p>The snapshot's map is one per client, from URL to digest, not per issuer: a device takes a context as genuine
 * when it has the digest stated for its URL. A pin is therefore never replaced by another entity's: when the entities
 * a client sees pin one URL to different digests (a framework's issuer and another framework's, say), the context is
 * left out of that client's snapshot and the conflict is logged; a client that sees only one of them is told its pin.
 *
 * <p>A context the snapshot does not carry, or carries by its digest only, a wallet asks the context relay for
 * ({@link ContextRelay}), which answers from the same cache.
 */
public class ContextService {

    private static final Logger log = LoggerFactory.getLogger(ContextService.class);

    /** Contexts every client library carries itself (W3C credentials, Data Integrity, DID): never shipped. */
    public static final Set<String> WELL_KNOWN = Set.of(
            "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/data-integrity/v1", "https://w3id.org/security/data-integrity/v2",
            "https://w3id.org/security/multikey/v1", "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/jws-2020/v1", "https://www.w3.org/ns/did/v1",
            "https://w3id.org/vc/status-list/2021/v1");

    /** @param document null when the context could not be fetched, or does not match its pin */
    public record Context(String sha256, Map<String, Object> document, int bytes) {
    }

    /** A context document as its host served it, for the relay, and the instant the copy held expires. */
    public record Relayed(byte[] body, Instant expiresAt) {
    }

    /** @param body the document as served: the digest is of these bytes, and the relay passes them on unchanged */
    private record Fetched(String sha256, Map<String, Object> document, byte[] body) {
        int bytes() {
            return body.length;
        }
    }

    private final HttpFetcher http;
    private final TrustProperties.Cache cfg;
    private final ResourceCache<Fetched> cache;
    private final Map<String, String> lastSeen = new ConcurrentHashMap<>();
    /** Conflicting pins already logged: a URL with the two entities and digests. */
    private final Set<String> reportedDisputes = ConcurrentHashMap.newKeySet();

    public ContextService(HttpFetcher http, TrustProperties.Cache cfg, Clock clock) {
        this.http = http;
        this.cfg = cfg;
        this.cache = new ResourceCache<>(cfg.settings(true), Fetched::bytes,
                e -> e instanceof IllegalArgumentException || (e instanceof HttpFetcher.HttpStatusException h && h.status() >= 400 && h.status() < 500), clock);
    }

    /** Contexts taken from one entity, and in one snapshot: an entity's contexts may be an issuer's own choice. */
    static final int MAX_PER_ENTITY = 20;
    static final int MAX_PER_SNAPSHOT = 200;

    /**
     * The contexts of the given entities, by URL, for a snapshot. Documents are included while they fit
     * {@code maxBytes} in total; past that, and for contexts that cannot be served, only the digest is.
     *
     * <p>Contexts are fetched side by side, and the snapshot waits for them no longer than {@code deadline}: a
     * listed issuer may name contexts on a host that never answers, and snapshots carry revocations and delistings
     * that must not wait for it. A context that is not there in time is left out (clients load it by their own
     * policy); its fetch goes on, and the next snapshot has it.
     */
    public Map<String, Map<String, Object>> forSnapshot(Collection<TrustedEntity> entities, int maxBytes, Duration deadline) {
        Map<String, String> pins = new LinkedHashMap<>();
        Map<String, String> pinnedBy = new LinkedHashMap<>();
        Set<String> disputed = new HashSet<>();
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (TrustedEntity e : entities) {
            if (e.attributes().get(Oid4vciMetadataMapper.CONTEXT_DIGESTS) instanceof Map<?, ?> m) {
                m.forEach((k, v) -> {
                    String url = String.valueOf(k);
                    String held = pins.putIfAbsent(url, String.valueOf(v));
                    if (held == null) {
                        pinnedBy.put(url, e.id());
                    } else if (!held.equals(String.valueOf(v))) {
                        // The map is one per client, not per issuer: whichever pin it carried would decide what the
                        // other party's signatures cover. Neither does; the device reports the context as not vouched for.
                        disputed.add(url);
                        reportDisputed(url, pinnedBy.get(url), held, e.id(), String.valueOf(v));
                    }
                });
            }
        }
        List<String> urls = entities.stream().flatMap(e -> urls(e).stream().limit(MAX_PER_ENTITY)).distinct()
                .filter(url -> !WELL_KNOWN.contains(url) && !disputed.contains(url)).limit(MAX_PER_SNAPSHOT).toList();
        Map<String, Future<Context>> pending = new LinkedHashMap<>();
        ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor();
        try {
            urls.forEach(url -> pending.put(url, exec.submit(() -> context(url, pins.get(url)))));
        } finally {
            exec.shutdown(); // not shutdownNow: a fetch that misses the deadline still fills the cache
        }
        long end = System.nanoTime() + deadline.toNanos();
        int budget = maxBytes;
        for (Map.Entry<String, Future<Context>> p : pending.entrySet()) {
            String url = p.getKey();
            Context c;
            try {
                c = p.getValue().get(Math.max(0, end - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (ExecutionException | TimeoutException e) {
                c = pins.get(url) == null ? null : new Context(pins.get(url), null, 0);
            }
            if (c == null) {
                continue;
            }
            Map<String, Object> claim = new LinkedHashMap<>();
            claim.put("sha256", c.sha256());
            if (c.document() != null && c.bytes() <= budget) {
                claim.put("document", c.document());
                budget -= c.bytes();
            }
            out.put(url, claim);
        }
        return out;
    }

    /** Logs two different pins for one context, once for as long as the service runs, not on every snapshot build. */
    private void reportDisputed(String url, String firstEntity, String firstPin, String secondEntity, String secondPin) {
        String first = firstEntity + "=" + firstPin;
        String second = secondEntity + "=" + secondPin;
        String key = url + "|" + (first.compareTo(second) < 0 ? first + "|" + second : second + "|" + first);
        if (reportedDisputes.add(key)) {
            log.error("JSON-LD context {} is pinned to {} by entity '{}' and to {} by entity '{}'; it is left out of the snapshots of "
                    + "clients that see both", url, firstPin, firstEntity, secondPin, secondEntity);
        }
    }

    private static List<String> urls(TrustedEntity e) {
        return e.attributes().get(Oid4vciMetadataMapper.CONTEXTS) instanceof List<?> l ? l.stream().map(String::valueOf).toList() : List.of();
    }

    /** @return null when the context is neither fetchable nor pinned */
    Context context(String url, String pinnedSha256) {
        Fetched f;
        try {
            f = cache.get(url, () -> fetch(url), x -> cfg.getContextTtl()).value();
        } catch (Exception e) {
            log.warn("JSON-LD context {} is unavailable: {}", url, e.getMessage());
            return pinnedSha256 == null ? null : new Context(pinnedSha256, null, 0);
        }
        String before = lastSeen.put(url, f.sha256());
        if (pinnedSha256 != null && !pinnedSha256.equals(f.sha256())) {
            // Reported when first seen and whenever the served content changes, not on every snapshot.
            if (!f.sha256().equals(before)) {
                log.error("JSON-LD context {} does not match its pinned digest {} (it is {}); it is not served", url, pinnedSha256, f.sha256());
            }
            return new Context(pinnedSha256, null, 0);
        }
        if (before != null && !before.equals(f.sha256())) {
            log.warn("JSON-LD context {} changed: {} is now {}. Credentials signed under the old content no longer verify; pin the digest to refuse such changes", url, before, f.sha256());
        }
        return new Context(f.sha256(), f.document(), f.bytes());
    }

    /**
     * The context at {@code url} for the relay, from the same cache the snapshots are built from: the bytes its host
     * served, never a re-serialization, because a device compares their digest with the one its snapshot carries.
     * Only a JSON object with an {@code @context} member within {@code max-document-bytes} is held; anything else
     * fails with an {@link IllegalArgumentException}.
     */
    public Relayed relay(String url) throws IOException {
        try {
            ResourceCache.Hit<Fetched> hit = cache.get(url, () -> fetch(url), x -> cfg.getContextTtl());
            return new Relayed(hit.value().body(), hit.expiresAt());
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private Fetched fetch(String url) throws IOException {
        HttpFetcher.Response r = http.fetchOk(HttpFetcher.Request.get(URI.create(url), "application/ld+json, application/json;q=0.9"));
        if (r.body().length > cfg.getMaxDocumentBytes()) {
            throw new IllegalArgumentException("JSON-LD context exceeds " + cfg.getMaxDocumentBytes() + " bytes");
        }
        Map<String, Object> document;
        try {
            document = Json.parseObject(r.body());
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Not a JSON object");
        }
        if (!document.containsKey("@context")) {
            throw new IllegalArgumentException("Not a JSON-LD context document: no @context");
        }
        return new Fetched(Base64.getUrlEncoder().withoutPadding().encodeToString(Hashes.sha256(r.body())), document, r.body());
    }

    public void clear() {
        cache.invalidateAll();
    }
}
