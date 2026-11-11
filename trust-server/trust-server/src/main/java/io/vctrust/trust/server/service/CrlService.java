package io.vctrust.trust.server.service;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.RevocationChecker.Crl;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * CRLs for certificate revocation checking.
 *
 * <p>Trust anchor CRLs come from the anchor's {@code constraints.crlUrls}, a CRL pushed with the anchor
 * ({@code constraints.crl}), or — for self-issued anchors without either — the anchor's own CRL distribution points.
 * Each is verified against the anchor (issuer name and signature), refreshed in the background before its
 * {@code nextUpdate}, and shipped in client snapshots so devices check revocation without asking anyone.
 *
 * <p>CRLs at other distribution points (certificates issued by intermediates) are fetched on demand, cached per URL
 * until their next update, for server-side checks and the CRL relay. Those are verified by whoever uses them.
 */
public class CrlService implements RevocationChecker.CrlSource, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(CrlService.class);
    public static final String ACCEPT = "application/pkix-crl, application/x-pkcs7-crl;q=0.5, */*;q=0.1";
    private static final Duration MIN_REFRESH = Duration.ofMinutes(1);
    private static final Duration ERROR_RETRY = Duration.ofMinutes(5);

    /** A trust anchor's CRL: one per anchor certificate and CRL location ({@code url} null when pushed). */
    public record AnchorCrl(String issuer, X509Certificate issuerCertificate, List<TrustAnchor> anchors, String url,
                            Crl crl, Instant fetchedAt, String error, Instant nextFetch) {

        /** Usable for snapshots: verified, and not past its next update. */
        public boolean currentAt(Instant now) {
            return crl != null && (crl.nextUpdate() == null || !crl.nextUpdate().isBefore(now));
        }
    }

    /** A CRL as served by the relay, with the instant the cached copy expires. */
    public record Relayed(byte[] der, Instant expiresAt) {
    }

    private record Target(String issuer, X509Certificate certificate, List<TrustAnchor> anchors, String url, byte[] inline) {
        String key() {
            return issuer + "|" + (url != null ? url : "inline:" + Hashes.sha256B64u(inline));
        }
    }

    private final TrustRegistry registry;
    private final HttpFetcher http;
    private final TrustProperties.Revocation cfg;
    private final Clock clock;
    private final ResourceCache<Crl> byUrl;
    private final ScheduledExecutorService scheduler;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final AtomicLong version = new AtomicLong();
    private volatile Map<String, AnchorCrl> anchorCrls = Map.of();

    public CrlService(TrustRegistry registry, HttpFetcher http, TrustProperties.Revocation cfg, ResourceCache.Settings cache, Clock clock) {
        this.registry = registry;
        this.http = http;
        this.cfg = cfg;
        this.clock = clock;
        // "No such CRL" and "not a CRL" are answers; anything else is an outage, through which the last CRL keeps being served.
        this.byUrl = new ResourceCache<>(cache, crl -> crl.der().length,
                e -> e instanceof IllegalArgumentException || e.getCause() instanceof IllegalArgumentException
                        || (e instanceof HttpFetcher.HttpStatusException h && h.status() >= 400 && h.status() < 500), clock);
        if (cfg.isEnabled()) {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "crl-refresh");
                t.setDaemon(true);
                return t;
            });
            registry.onChange(s -> scheduler.execute(this::refreshQuietly));
            scheduler.scheduleWithFixedDelay(this::refreshQuietly, 0, 1, TimeUnit.MINUTES);
        } else {
            scheduler = null;
        }
    }

    /** Called (on the refresh thread) whenever the held anchor CRLs change. */
    public void onChange(Runnable listener) {
        listeners.add(listener);
    }

    /** Increments whenever the held anchor CRLs change. */
    public long version() {
        return version.get();
    }

    public Collection<AnchorCrl> anchorCrls() {
        return anchorCrls.values();
    }

    @Override
    public List<Crl> heldFor(X509Certificate issuer) {
        String thumb = Certificates.sha256Thumbprint(issuer);
        return anchorCrls.values().stream().filter(a -> a.issuer().equals(thumb) && a.crl() != null).map(AnchorCrl::crl).toList();
    }

    @Override
    public Crl fetch(String url) throws IOException {
        if (!cfg.isFetchOnDemand()) {
            throw new IOException("on-demand CRL fetching is disabled");
        }
        return cachedCrl(url).value();
    }

    /** The CRL at {@code url} for the relay (not verified: the relay does not know the issuer; clients verify). */
    public Relayed relay(String url) throws IOException {
        ResourceCache.Hit<Crl> hit = cachedCrl(url);
        return new Relayed(hit.value().der(), hit.expiresAt());
    }

    private ResourceCache.Hit<Crl> cachedCrl(String url) throws IOException {
        for (AnchorCrl a : anchorCrls.values()) {
            if (url.equals(a.url()) && a.crl() != null) {
                return new ResourceCache.Hit<>(a.crl(), a.fetchedAt(), a.nextFetch(), false);
            }
        }
        try {
            return byUrl.get(url, () -> download(url), crl -> refreshAfter(crl, clock.instant()));
        } catch (IOException | IllegalArgumentException e) {
            throw e instanceof IOException io ? io : new IOException(e.getMessage(), e);
        } catch (Exception e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private Crl download(String url) throws IOException {
        HttpFetcher.Response r = http.fetchOk(HttpFetcher.Request.get(URI.create(url), ACCEPT));
        if (r.body().length > cfg.getMaxCrlBytes()) {
            throw new IOException("CRL at " + url + " exceeds " + cfg.getMaxCrlBytes() + " bytes");
        }
        return Crl.parse(r.body(), url, clock.instant());
    }

    private Duration refreshAfter(Crl crl, Instant now) {
        Duration d = cfg.getRefresh();
        if (crl.nextUpdate() != null) {
            Duration untilNext = Duration.between(now, crl.nextUpdate());
            d = untilNext.compareTo(d) < 0 ? untilNext : d;
        }
        return d.compareTo(MIN_REFRESH) < 0 ? MIN_REFRESH : d;
    }

    private void refreshQuietly() {
        try {
            refresh();
        } catch (Exception e) {
            log.warn("CRL refresh failed: {}", e.toString());
        }
    }

    /** Loads due anchor CRLs (synchronously); runs on the refresh thread, callable directly in tests. */
    public synchronized void refresh() {
        Instant now = clock.instant();
        Map<String, Target> targets = targets(registry.snapshot().allAnchors());
        Map<String, AnchorCrl> old = anchorCrls;
        Map<String, AnchorCrl> next = new LinkedHashMap<>();
        Map<String, Future<AnchorCrl>> pending = new LinkedHashMap<>();
        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            for (Map.Entry<String, Target> e : targets.entrySet()) {
                Target t = e.getValue();
                AnchorCrl prev = old.get(e.getKey());
                if (prev != null && prev.nextFetch().isAfter(now)) {
                    next.put(e.getKey(), new AnchorCrl(prev.issuer(), prev.issuerCertificate(), t.anchors(), prev.url(),
                            prev.crl(), prev.fetchedAt(), prev.error(), prev.nextFetch()));
                } else {
                    pending.put(e.getKey(), exec.submit(() -> load(t, prev, now)));
                }
            }
            for (Map.Entry<String, Future<AnchorCrl>> p : pending.entrySet()) {
                try {
                    next.put(p.getKey(), p.getValue().get());
                } catch (Exception ex) {
                    log.warn("CRL load failed: {}", ex.toString());
                }
            }
        }
        anchorCrls = Map.copyOf(next);
        if (changed(old, next)) {
            version.incrementAndGet();
            listeners.forEach(l -> {
                try {
                    l.run();
                } catch (RuntimeException ex) {
                    log.warn("CRL change listener failed: {}", ex.toString());
                }
            });
        }
    }

    private AnchorCrl load(Target t, AnchorCrl prev, Instant now) {
        String where = t.url() != null ? t.url() : "the CRL pushed with the anchor";
        try {
            Crl crl = t.url() != null ? download(t.url()) : Crl.parse(t.inline(), null, now);
            if (!crl.issuedBy(t.certificate())) {
                throw new IllegalArgumentException("CRL from " + where + " is not issued and signed by the anchor "
                        + t.certificate().getSubjectX500Principal().getName());
            }
            Instant nextFetch = t.url() == null ? now.plus(cfg.getRefresh()) : now.plus(refreshAfter(crl, now));
            log.debug("Loaded CRL {} for {} ({} entries)", where, t.issuer(), crl.revokedCount());
            return new AnchorCrl(t.issuer(), t.certificate(), t.anchors(), t.url(), crl, now, null, nextFetch);
        } catch (Exception e) {
            log.warn("CRL {} for anchor {}: {}", where, t.certificate().getSubjectX500Principal().getName(), e.getMessage());
            Duration retry = cfg.getRefresh().compareTo(ERROR_RETRY) < 0 ? cfg.getRefresh() : ERROR_RETRY;
            // Keep a previously verified CRL while it is still current.
            Crl keep = prev != null && prev.crl() != null && (prev.crl().nextUpdate() == null || prev.crl().nextUpdate().isAfter(now))
                    ? prev.crl() : null;
            return new AnchorCrl(t.issuer(), t.certificate(), t.anchors(), t.url(), keep,
                    keep != null ? prev.fetchedAt() : now, e.getMessage(), now.plus(retry.compareTo(MIN_REFRESH) < 0 ? MIN_REFRESH : retry));
        }
    }

    /** One target per anchor certificate and CRL location. */
    private static Map<String, Target> targets(Collection<TrustAnchor> anchors) {
        Map<String, List<TrustAnchor>> byCert = new LinkedHashMap<>();
        for (TrustAnchor a : anchors) {
            byCert.computeIfAbsent(a.thumbprint(), k -> new ArrayList<>()).add(a);
        }
        Map<String, Target> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<TrustAnchor>> e : byCert.entrySet()) {
            X509Certificate cert = e.getValue().getFirst().certificate();
            Set<String> urls = new LinkedHashSet<>();
            List<byte[]> inline = new ArrayList<>();
            for (TrustAnchor a : e.getValue()) {
                urls.addAll(configuredUrls(a));
                if (a.constraints().get("crl") instanceof String s && !s.isBlank()) {
                    inline.add(s.getBytes(StandardCharsets.US_ASCII));
                }
            }
            if (urls.isEmpty() && inline.isEmpty() && Certificates.isSelfIssued(cert)) {
                Certificates.crlDistributionPoints(cert).stream().filter(CrlService::isHttp).forEach(urls::add);
            }
            List<TrustAnchor> list = List.copyOf(e.getValue());
            for (String url : urls) {
                Target t = new Target(e.getKey(), cert, list, url, null);
                out.put(t.key(), t);
            }
            for (byte[] b : inline) {
                Target t = new Target(e.getKey(), cert, list, null, b);
                out.putIfAbsent(t.key(), t);
            }
        }
        return out;
    }

    static List<String> configuredUrls(TrustAnchor a) {
        Object v = a.constraints().get("crlUrls");
        List<String> out = new ArrayList<>();
        if (v instanceof Collection<?> c) {
            c.forEach(x -> out.add(String.valueOf(x)));
        } else if (v instanceof String s && !s.isBlank()) {
            out.add(s);
        }
        return out.stream().filter(CrlService::isHttp).toList();
    }

    private static boolean isHttp(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        return u.startsWith("https://") || u.startsWith("http://");
    }

    private static boolean changed(Map<String, AnchorCrl> a, Map<String, AnchorCrl> b) {
        if (!a.keySet().equals(b.keySet())) {
            return true;
        }
        for (Map.Entry<String, AnchorCrl> e : a.entrySet()) {
            Crl x = e.getValue().crl();
            Crl y = b.get(e.getKey()).crl();
            if ((x == null) != (y == null) || (x != null && !Arrays.equals(x.der(), y.der()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Snapshot claim {@code crls}: current, verified CRLs of the anchors a client can see, at most
     * {@code maxBytes} each, deduplicated by issuer and location.
     */
    public List<Map<String, Object>> snapshotClaims(Predicate<TrustAnchor> visible, int maxBytes) {
        Instant now = clock.instant();
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (AnchorCrl a : anchorCrls.values()) {
            if (!a.currentAt(now) || a.crl().size() > maxBytes || a.anchors().stream().noneMatch(visible)
                    || !seen.add(a.issuer() + "|" + Objects.toString(a.url(), "") + "|" + Hashes.sha256B64u(a.crl().der()))) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("issuer", a.issuer());
            if (a.url() != null) {
                m.put("url", a.url());
            }
            m.put("crl", Base64.getEncoder().encodeToString(a.crl().der()));
            m.put("thisUpdate", a.crl().thisUpdate().toString());
            if (a.crl().nextUpdate() != null) {
                m.put("nextUpdate", a.crl().nextUpdate().toString());
            }
            a.crl().crlNumber().ifPresent(n -> m.put("crlNumber", n.toString()));
            out.add(m);
        }
        return out;
    }

    /** Operator view of the anchor CRLs visible to a client. */
    public List<Map<String, Object>> listing(Predicate<TrustAnchor> visible) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (AnchorCrl a : anchorCrls.values()) {
            List<String> ids = a.anchors().stream().filter(visible).map(TrustAnchor::id).toList();
            if (ids.isEmpty()) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("issuer", a.issuer());
            m.put("anchorIds", ids);
            m.put("subject", a.issuerCertificate().getSubjectX500Principal().getName());
            m.put("url", a.url());
            if (a.crl() != null) {
                m.put("thisUpdate", a.crl().thisUpdate());
                m.put("nextUpdate", a.crl().nextUpdate());
                a.crl().crlNumber().ifPresent(n -> m.put("crlNumber", n.toString()));
                m.put("revoked", a.crl().revokedCount());
                m.put("bytes", a.crl().size());
            }
            m.put("fetchedAt", a.fetchedAt());
            m.put("error", a.error());
            out.add(m);
        }
        return out;
    }

    @Override
    public void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}
