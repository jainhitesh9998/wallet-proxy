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
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The JSON-LD contexts of the parties the registry lists. Verifying a Data Integrity proof means loading every
 * context a credential names, and a context fetched at that moment is an unauthenticated input that decides what the
 * signature covers. The service fetches each context once, and the snapshot carries it with its SHA-256, so a wallet
 * verifies against the bytes the service saw and never contacts the context's host.
 *
 * <p>An operator can pin a context's digest ({@code contexts: [{url, sha256}]} on an entity). A pinned context whose
 * content no longer matches is not shipped; the pin still is, so a wallet that fetches the context itself can refuse
 * it. An unpinned context that changes is shipped as it now is, and the change is logged.
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

    private record Fetched(String sha256, Map<String, Object> document, int bytes) {
    }

    private final HttpFetcher http;
    private final TrustProperties.Cache cfg;
    private final ResourceCache<Fetched> cache;
    private final Map<String, String> lastSeen = new ConcurrentHashMap<>();

    public ContextService(HttpFetcher http, TrustProperties.Cache cfg, Clock clock) {
        this.http = http;
        this.cfg = cfg;
        this.cache = new ResourceCache<>(cfg.settings(true), Fetched::bytes,
                e -> e instanceof IllegalArgumentException || (e instanceof HttpFetcher.HttpStatusException h && h.status() >= 400 && h.status() < 500), clock);
    }

    /**
     * The contexts of the given entities, by URL, for a snapshot. Documents are included while they fit
     * {@code maxBytes} in total; past that, and for contexts that cannot be served, only the digest is.
     */
    public Map<String, Map<String, Object>> forSnapshot(Collection<TrustedEntity> entities, int maxBytes) {
        Map<String, String> pins = new LinkedHashMap<>();
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (TrustedEntity e : entities) {
            if (e.attributes().get(Oid4vciMetadataMapper.CONTEXT_DIGESTS) instanceof Map<?, ?> m) {
                m.forEach((k, v) -> pins.put(String.valueOf(k), String.valueOf(v)));
            }
        }
        int budget = maxBytes;
        for (String url : entities.stream().flatMap(e -> urls(e).stream()).distinct().toList()) {
            if (WELL_KNOWN.contains(url)) {
                continue;
            }
            Context c = context(url, pins.get(url));
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
        return new Fetched(Base64.getUrlEncoder().withoutPadding().encodeToString(Hashes.sha256(r.body())), document, r.body().length);
    }

    public void clear() {
        cache.invalidateAll();
    }
}
