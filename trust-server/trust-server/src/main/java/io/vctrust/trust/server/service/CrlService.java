package io.vctrust.trust.server.service;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.util.ForeignText;
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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
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
 * That configuration is per framework: the anchor records of one framework decide where its clients' CRL for a
 * certificate comes from, never those of another framework listing the same certificate. Each CRL is verified
 * against the anchor (issuer name and signature), refreshed in the background before its {@code nextUpdate}, and
 * shipped in the snapshots of the clients of the frameworks that use it, so devices check revocation without asking
 * anyone; the service's own decisions for a client use the same CRLs ({@link #heldFor(X509Certificate, Predicate)}).
 *
 * <p>CRLs at other distribution points (certificates issued by intermediates) are fetched on demand, cached per URL
 * until their next update, for server-side checks and the CRL relay. Those are verified by whoever uses them.
 */
public class CrlService implements RevocationChecker.CrlSource, AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(CrlService.class);
    public static final String ACCEPT = "application/pkix-crl, application/x-pkcs7-crl;q=0.5, */*;q=0.1";
    private static final Duration MIN_REFRESH = Duration.ofMinutes(1);
    private static final Duration ERROR_RETRY = Duration.ofMinutes(5);

    /**
     * A trust anchor's CRL: one per anchor certificate and CRL location ({@code url} null when pushed). {@code anchors}
     * are the anchor records that use it: those of the frameworks whose configuration names this location.
     */
    public record AnchorCrl(String issuer, X509Certificate issuerCertificate, List<TrustAnchor> anchors, String url,
                            Crl crl, Instant fetchedAt, String error, Instant nextFetch) {

        /**
         * Usable for snapshots: verified, and not past its next update. A CRL that states no next update is current for
         * {@link RevocationChecker#MAX_AGE_WITHOUT_NEXT_UPDATE} after it was issued, as the checker and the device use it:
         * nothing says when it was superseded, and shown as current or shipped for longer it would stand in for the CA's
         * current CRL forever.
         */
        public boolean currentAt(Instant now) {
            if (crl == null) {
                return false;
            }
            return crl.nextUpdate() != null ? !crl.nextUpdate().isBefore(now)
                    : !Duration.between(crl.thisUpdate(), now).minus(RevocationChecker.MAX_AGE_WITHOUT_NEXT_UPDATE).isPositive();
        }

        /** Shipped in the snapshots of the clients that see one of its anchors: current, and no larger than {@code maxBytes}. */
        public boolean shippedAt(Instant now, int maxBytes) {
            return currentAt(now) && crl.size() <= maxBytes;
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
    /** Per framework and certificate, the CRL locations the last refresh left out: logged when that changes. */
    private Map<String, String> leftOut = Map.of();

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
        return heldFor(issuer, framework -> true);
    }

    /**
     * The CRLs held for {@code issuer} that an anchor of a framework {@code frameworks} accepts uses. A CRL is the
     * issuer's, not one certificate's: it is held for the anchor certificate it was configured with, and counts for
     * every certificate of the same issuer (the same subject name and key), as on the device, which matches a CRL by
     * its issuer's name and signature. A CA reissued with the same name and key has two certificates; a chain validates
     * to whichever an anchor lists first, and the CRLs configured for the other must count all the same.
     */
    @Override
    public List<Crl> heldFor(X509Certificate issuer, Predicate<String> frameworks) {
        return anchorCrls.values().stream().filter(a -> a.crl() != null && sameIssuer(a.issuerCertificate(), issuer)
                && a.anchors().stream().anyMatch(anchor -> frameworks.test(anchor.frameworkId()))).map(AnchorCrl::crl).toList();
    }

    private static boolean sameIssuer(X509Certificate a, X509Certificate b) {
        return a.getSubjectX500Principal().equals(b.getSubjectX500Principal())
                && Arrays.equals(a.getPublicKey().getEncoded(), b.getPublicKey().getEncoded());
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
            log.warn("CRL refresh failed: {}", ForeignText.escape(e.toString()));
        }
    }

    /** Loads due anchor CRLs (synchronously); runs on the refresh thread, callable directly in tests. */
    public synchronized void refresh() {
        Instant now = clock.instant();
        Map<String, String> skipped = new LinkedHashMap<>();
        Map<String, Target> targets = targets(registry.snapshot().allAnchors(), cfg.isFetchAnchorCrls(), skipped);
        if (!skipped.equals(leftOut)) {
            skipped.forEach((key, message) -> {
                if (!message.equals(leftOut.get(key))) {
                    log.warn("{}", ForeignText.escape(message));
                }
            });
            leftOut = Map.copyOf(skipped);
        }
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
                    log.warn("CRL load failed: {}", ForeignText.escape(ex.toString()));
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
            if (prev != null && prev.crl() != null && olderThan(crl, prev.crl())) {
                // Verified, and older than the one held: a CRL from before a revocation, served again by whoever
                // answers at that location (CRLs travel over plain http), would take the revocation back.
                throw new IllegalArgumentException("CRL from " + where + " (issued " + crl.thisUpdate() + ") is older than the one held (issued "
                        + prev.crl().thisUpdate() + ")");
            }
            Instant nextFetch = t.url() == null ? now.plus(cfg.getRefresh()) : now.plus(refreshAfter(crl, now));
            log.debug("Loaded CRL {} for {} ({} entries)", ForeignText.escape(where), t.issuer(), crl.revokedCount());
            return new AnchorCrl(t.issuer(), t.certificate(), t.anchors(), t.url(), crl, now, null, nextFetch);
        } catch (Exception e) {
            // The location is a list's, the subject a CA's, and the message may quote what answered there.
            log.warn("CRL {} for anchor {}: {}", ForeignText.escape(where), ForeignText.escape(t.certificate().getSubjectX500Principal().getName()),
                    ForeignText.escape(e.getMessage()));
            Duration retry = cfg.getRefresh().compareTo(ERROR_RETRY) < 0 ? cfg.getRefresh() : ERROR_RETRY;
            // Keep a previously verified CRL while it is still current.
            Crl keep = prev != null && prev.crl() != null && (prev.crl().nextUpdate() == null || prev.crl().nextUpdate().isAfter(now))
                    ? prev.crl() : null;
            return new AnchorCrl(t.issuer(), t.certificate(), t.anchors(), t.url(), keep,
                    keep != null ? prev.fetchedAt() : now, e.getMessage(), now.plus(retry.compareTo(MIN_REFRESH) < 0 ? MIN_REFRESH : retry));
        }
    }

    /** Whether a CRL was issued before another of the same issuer: an earlier thisUpdate, or a lower CRL number. */
    static boolean olderThan(Crl crl, Crl held) {
        if (crl.thisUpdate() != null && held.thisUpdate() != null && crl.thisUpdate().isBefore(held.thisUpdate())) {
            return true;
        }
        return crl.crlNumber().isPresent() && held.crlNumber().isPresent() && crl.crlNumber().get().compareTo(held.crlNumber().get()) < 0;
    }

    /**
     * One target per anchor certificate and CRL location, with the anchors whose framework uses it. Where a CA
     * publishes is configured per framework: for one framework and certificate, the locations are those its anchor
     * records of the certificate name ({@code crlUrls}, a pushed {@code crl}), and when they name none and the
     * certificate is self-issued, the certificate's own distribution points. What an anchor record of another
     * framework says about the same certificate does not enter: whoever writes one framework's list would otherwise
     * choose the CRL, a stale one say, that the clients of another framework are told and decided by. At most
     * {@link TrustAnchor#MAX_CRL_URLS} locations are fetched per framework and certificate, the first in the order the
     * records name them, however many records there are: a list decides how many requests each refresh makes.
     *
     * @param fetch   whether CRLs are fetched at all; without it only the CRLs pushed with an anchor are targets
     * @param skipped receives, per framework and certificate whose locations were cut, what was left out
     */
    private static Map<String, Target> targets(Collection<TrustAnchor> anchors, boolean fetch, Map<String, String> skipped) {
        Map<List<String>, List<TrustAnchor>> byFrameworkAndCert = new LinkedHashMap<>();
        for (TrustAnchor a : anchors) {
            byFrameworkAndCert.computeIfAbsent(Arrays.asList(a.frameworkId(), a.thumbprint()), k -> new ArrayList<>()).add(a);
        }
        Map<String, Target> found = new LinkedHashMap<>();
        Map<String, List<TrustAnchor>> users = new LinkedHashMap<>();
        for (List<TrustAnchor> group : byFrameworkAndCert.values()) {
            X509Certificate cert = group.getFirst().certificate();
            String issuer = group.getFirst().thumbprint();
            Set<String> urls = new LinkedHashSet<>();
            List<byte[]> inline = new ArrayList<>();
            for (TrustAnchor a : group) {
                urls.addAll(configuredUrls(a));
                if (a.constraints().get("crl") instanceof String s && !s.isBlank()) {
                    inline.add(s.getBytes(StandardCharsets.US_ASCII));
                }
            }
            if (urls.isEmpty() && inline.isEmpty() && Certificates.isSelfIssued(cert)) {
                Certificates.crlDistributionPoints(cert).stream().filter(TrustAnchor::isHttp).forEach(urls::add);
            }
            List<String> counted = urls.stream().limit(TrustAnchor.MAX_CRL_URLS).toList();
            if (fetch && urls.size() > counted.size()) {
                String left = urls.stream().skip(counted.size()).findFirst().orElseThrow();
                skipped.put(group.getFirst().frameworkId() + "|" + issuer, "CRL locations of anchor certificate " + cert.getSubjectX500Principal().getName()
                        + " in framework '" + group.getFirst().frameworkId() + "': its records name " + urls.size() + "; the first "
                        + counted.size() + " are fetched, the other " + (urls.size() - counted.size()) + " are not, from " + left + " on");
            }
            Map<String, Target> own = new LinkedHashMap<>();
            for (String url : fetch ? counted : List.<String>of()) {
                Target t = new Target(issuer, cert, List.of(), url, null);
                own.put(t.key(), t);
            }
            for (byte[] b : inline) {
                Target t = new Target(issuer, cert, List.of(), null, b);
                own.putIfAbsent(t.key(), t);
            }
            // Frameworks that name the same location share one CRL: fetched once, held once, used by each.
            own.forEach((key, t) -> {
                found.putIfAbsent(key, t);
                users.computeIfAbsent(key, k -> new ArrayList<>()).addAll(group);
            });
        }
        Map<String, Target> out = new LinkedHashMap<>();
        found.forEach((key, t) -> out.put(key, new Target(t.issuer(), t.certificate(), List.copyOf(users.get(key)), t.url(), t.inline())));
        return out;
    }

    static List<String> configuredUrls(TrustAnchor a) {
        return a.crlUrls();
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
     * Snapshot claim {@code crls}: current, verified CRLs used by the anchors a client can see (those of its
     * frameworks), at most {@code maxBytes} each, deduplicated by issuer and location.
     */
    public List<Map<String, Object>> snapshotClaims(Predicate<TrustAnchor> visible, int maxBytes) {
        Instant now = clock.instant();
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (AnchorCrl a : anchorCrls.values()) {
            if (!a.shippedAt(now, maxBytes) || a.anchors().stream().noneMatch(visible)
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

    /**
     * Operator view of the anchor CRLs of the anchors {@code visible} selects: one entry per anchor certificate and
     * CRL location, with the anchors and frameworks that use it, what is held, when it was fetched and will be next,
     * the last error, whether it is current and whether snapshots carry it. A member without a value is left out: a
     * pushed CRL has no url, a CRL that never loaded has no dates, a load that went well has no error.
     *
     * @param snapshotMaxBytes the largest CRL a snapshot carries ({@code trust.revocation.snapshot-max-crl-bytes})
     */
    public List<Map<String, Object>> listing(Predicate<TrustAnchor> visible, int snapshotMaxBytes) {
        Instant now = clock.instant();
        List<Map<String, Object>> out = new ArrayList<>();
        for (AnchorCrl a : anchorCrls.values()) {
            List<String> ids = a.anchors().stream().filter(visible).map(TrustAnchor::id).toList();
            if (ids.isEmpty()) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("issuer", a.issuer());
            m.put("anchorIds", ids);
            // The frameworks whose clients get this CRL and are decided by it: those whose anchor records name its location.
            m.put("frameworks", a.anchors().stream().filter(visible).map(TrustAnchor::frameworkId).distinct()
                    .sorted(Comparator.nullsFirst(Comparator.naturalOrder())).toList());
            m.put("subject", a.issuerCertificate().getSubjectX500Principal().getName());
            if (a.url() != null) {
                m.put("url", a.url());
            }
            if (a.crl() != null) {
                m.put("thisUpdate", a.crl().thisUpdate());
                if (a.crl().nextUpdate() != null) {
                    m.put("nextUpdate", a.crl().nextUpdate());
                }
                a.crl().crlNumber().ifPresent(n -> m.put("crlNumber", n.toString()));
                m.put("revoked", a.crl().revokedCount());
                m.put("bytes", a.crl().size());
            }
            m.put("fetchedAt", a.fetchedAt());
            m.put("nextFetch", a.nextFetch());
            if (a.error() != null) {
                // The error quotes the location and what answered there.
                m.put("error", ForeignText.escape(a.error()));
            }
            m.put("current", a.currentAt(now));
            m.put("inSnapshots", a.shippedAt(now, snapshotMaxBytes));
            out.add(m);
        }
        // The CRLs are held in no particular order; an operator comparing two answers wants the same one each time.
        out.sort(Comparator.comparing((Map<String, Object> m) -> (String) m.get("subject"))
                .thenComparing(m -> (String) m.get("url"), Comparator.nullsFirst(Comparator.naturalOrder())));
        return out;
    }

    @Override
    public void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}
