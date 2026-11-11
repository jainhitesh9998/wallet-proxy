package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * Loads trust sources, refreshes them on their schedule (honouring a list's own {@code nextUpdate}), keeps the last
 * good result of a failing source, and publishes the merged registry to the {@link TrustRegistry}.
 *
 * <p>A new registry version is published only when its content changed, so a reload that finds nothing new does not
 * invalidate what was derived from it. The registry is {@link #ready()} once every required source has loaded;
 * before that it must not be served, because a registry missing a source looks like that source's parties being
 * delisted.
 */
public class TrustSourceManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TrustSourceManager.class);
    private static final Duration MIN_REFRESH = Duration.ofSeconds(30);
    private static final Duration RETRY_AFTER_FAILURE = Duration.ofMinutes(2);

    private final TrustRegistry registry;
    private final Collection<TrustFramework> frameworks;
    private final Map<String, TrustSource> sources = new LinkedHashMap<>();
    private final Map<String, SourceLoadResult> results = new ConcurrentHashMap<>();
    private final Map<String, SourceState> states = new ConcurrentHashMap<>();
    private final Clock clock;
    private final AtomicLong version = new AtomicLong();
    private final ScheduledExecutorService scheduler;

    public TrustSourceManager(TrustRegistry registry, Collection<TrustFramework> frameworks,
                              Collection<TrustSource> sources, Clock clock) {
        this.registry = registry;
        this.frameworks = List.copyOf(frameworks);
        sources.forEach(s -> this.sources.put(s.id(), s));
        this.clock = clock;
        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "trust-source-refresh");
            t.setDaemon(true);
            return t;
        });
        for (TrustSource s : this.sources.values()) {
            states.put(s.id(), new SourceState(s.id(), s.type(), s.definition().frameworkId(), s.definition().enabled(),
                    null, null, null, 0, 0, null, List.of(), null));
        }
    }

    /** True once every enabled, required source has loaded successfully at least once. */
    public boolean ready() {
        return waitingFor().isEmpty();
    }

    /** The enabled, required sources that have never loaded: why the registry is not ready. */
    public List<String> waitingFor() {
        return sources.values().stream().filter(s -> s.definition().enabled() && s.definition().required())
                .map(TrustSource::id).filter(id -> !results.containsKey(id)).toList();
    }

    /** Loads every enabled source once, synchronously, then schedules refreshes. */
    public void start() {
        sources.values().stream().filter(s -> s.definition().enabled()).forEach(this::loadQuietly);
        rebuild();
        sources.values().stream().filter(s -> s.definition().enabled()).forEach(this::scheduleNext);
    }

    /** Reloads one source now. */
    public SourceState refresh(String sourceId) {
        TrustSource s = sources.get(sourceId);
        if (s == null) {
            throw new IllegalArgumentException("Unknown source " + sourceId);
        }
        loadQuietly(s);
        rebuild();
        return states.get(sourceId);
    }

    public List<SourceState> states() {
        return sources.keySet().stream().map(states::get).toList();
    }

    public Collection<TrustSource> sources() {
        return sources.values();
    }

    /** Asks on-demand capable sources to resolve an identifier missing from the pre-loaded registry. */
    public Optional<TrustedEntity> resolveOnDemand(Identifier identifier, Predicate<String> acceptsFramework) {
        for (TrustSource s : sources.values()) {
            if (!s.definition().enabled() || !(s instanceof OnDemandResolver r) || !r.canResolve(identifier)) {
                continue;
            }
            if (!acceptsFramework.test(s.definition().frameworkId())) {
                continue;
            }
            try {
                Optional<TrustedEntity> e = r.resolve(identifier);
                if (e.isPresent()) {
                    return e;
                }
            } catch (TrustSourceException e) {
                log.debug("On-demand resolution of {} by {} failed: {}", identifier, s.id(), e.getMessage());
            }
        }
        return Optional.empty();
    }

    private void loadQuietly(TrustSource s) {
        Instant start = clock.instant();
        SourceState prev = states.get(s.id());
        try {
            SourceLoadResult r = s.load();
            results.put(s.id(), r);
            states.put(s.id(), new SourceState(s.id(), s.type(), s.definition().frameworkId(), true, start, clock.instant(),
                    null, r.entities().size(), r.anchors().size(), r.listInfo(), r.warnings(), null));
            log.info("Loaded trust source '{}' ({}): {} entities, {} anchors", s.id(), s.type(),
                    r.entities().size(), r.anchors().size());
        } catch (Exception e) {
            log.warn("Trust source '{}' ({}) failed to load: {}", s.id(), s.type(), e.getMessage());
            SourceLoadResult last = results.get(s.id());
            states.put(s.id(), new SourceState(s.id(), s.type(), s.definition().frameworkId(), true, start,
                    prev == null ? null : prev.lastSuccess(), e.getMessage(),
                    last == null ? 0 : last.entities().size(), last == null ? 0 : last.anchors().size(),
                    last == null ? null : last.listInfo(), last == null ? List.of() : last.warnings(), null));
        }
    }

    private void scheduleNext(TrustSource s) {
        SourceState st = states.get(s.id());
        Duration delay = st != null && st.lastError() != null ? RETRY_AFTER_FAILURE : s.definition().refreshInterval();
        if (st != null && st.listInfo() != null && st.listInfo().nextUpdate() != null) {
            Duration untilNext = Duration.between(clock.instant(), st.listInfo().nextUpdate());
            if (untilNext.compareTo(delay) < 0) {
                delay = untilNext;
            }
        }
        if (delay.compareTo(MIN_REFRESH) < 0) {
            delay = MIN_REFRESH;
        }
        long jitter = ThreadLocalRandom.current().nextLong(Math.max(1, delay.toMillis() / 20));
        long millis = delay.toMillis() + jitter;
        if (st != null) {
            states.put(s.id(), new SourceState(st.id(), st.type(), st.frameworkId(), st.enabled(), st.lastAttempt(),
                    st.lastSuccess(), st.lastError(), st.entityCount(), st.anchorCount(), st.listInfo(), st.warnings(),
                    clock.instant().plusMillis(millis)));
        }
        scheduler.schedule(() -> {
            try {
                loadQuietly(s);
                rebuild();
            } finally {
                scheduleNext(s);
            }
        }, millis, TimeUnit.MILLISECONDS);
    }

    private synchronized void rebuild() {
        List<TrustedEntity> entities = new ArrayList<>();
        List<TrustAnchor> anchors = new ArrayList<>();
        for (String id : sources.keySet()) {
            SourceLoadResult r = results.get(id);
            if (r != null) {
                entities.addAll(r.entities());
                anchors.addAll(r.anchors());
            }
        }
        List<TrustedEntity> merged = RegistrySnapshot.mergeById(entities);
        List<Object> content = List.of(merged.stream().map(TrustSourceManager::withoutRetrievalTime).toList(),
                anchors.stream().map(TrustSourceManager::withoutRetrievalTime).toList());
        if (content.equals(published)) {
            return;
        }
        published = content;
        registry.publish(new RegistrySnapshot(version.incrementAndGet(), clock.instant(), frameworks, merged, anchors));
    }

    /** What the last published registry held, for comparison; when something was fetched is not content. */
    private List<Object> published;

    private static TrustedEntity withoutRetrievalTime(TrustedEntity e) {
        return e.provenance() == null ? e : e.toBuilder().provenance(timeless(e.provenance())).build();
    }

    private static TrustAnchor withoutRetrievalTime(TrustAnchor a) {
        return a.provenance() == null ? a : new TrustAnchor(a.id(), a.domain(), a.certificate(), a.frameworkId(), a.entityId(),
                a.status(), a.constraints(), timeless(a.provenance()));
    }

    private static Provenance timeless(Provenance p) {
        return new Provenance(p.sourceId(), p.sourceType(), p.frameworkId(), p.sourceUri(), null, p.details());
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }
}
