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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
 *
 * <p>A source speaks for its own framework and for nothing else. Whatever it loads is placed in the framework it is
 * configured for; entities of the same id are merged only within a framework; an anchor is tied to an entity only
 * of its own framework. A source of one framework can therefore add nothing to, and take nothing from, what a
 * client of another framework is told. A list that is older than the one already held is not loaded.
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
    /** Per source, what the last registry build could not take from it as it was written. */
    private volatile Map<String, List<String>> conflicts = Map.of();
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
        return state(sourceId);
    }

    public List<SourceState> states() {
        return sources.keySet().stream().map(this::state).toList();
    }

    /** The state of a source, its warnings followed by what the registry could not take from it as written. */
    private SourceState state(String sourceId) {
        SourceState st = states.get(sourceId);
        List<String> more = conflicts.getOrDefault(sourceId, List.of());
        if (st == null || more.isEmpty()) {
            return st;
        }
        List<String> warnings = new ArrayList<>(st.warnings());
        warnings.addAll(more);
        return new SourceState(st.id(), st.type(), st.frameworkId(), st.enabled(), st.lastAttempt(), st.lastSuccess(),
                st.lastError(), st.entityCount(), st.anchorCount(), st.listInfo(), warnings, st.nextRefresh());
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
                    return e.map(found -> inFramework(found, found.id(), s.definition().frameworkId()));
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
            SourceLoadResult held = results.get(s.id());
            if (held != null && r.listInfo().olderThan(held.listInfo())) {
                // Whoever serves the list may serve an old one again, from before an entry was withdrawn.
                throw new TrustSourceException("The list served (sequence " + r.listInfo().sequence() + ", issued "
                        + r.listInfo().issuedAt() + ") is older than the one already loaded (sequence "
                        + held.listInfo().sequence() + ", issued " + held.listInfo().issuedAt() + ")");
            }
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
        Map<String, TrustedEntity> entities = new LinkedHashMap<>();
        Map<String, List<String>> refused = new LinkedHashMap<>();
        // (framework, id as the source wrote it) -> the id the entity has in the registry
        Map<List<String>, String> placed = new HashMap<>();
        for (TrustSource s : sources.values()) {
            SourceLoadResult r = results.get(s.id());
            if (r == null) {
                continue;
            }
            String framework = s.definition().frameworkId();
            for (TrustedEntity e : r.entities()) {
                String id = placed.get(Arrays.asList(framework, e.id()));
                if (id == null) {
                    id = e.id();
                    TrustedEntity other = entities.get(id);
                    if (other != null && !Objects.equals(other.frameworkId(), framework)) {
                        // The id is taken by an entity of another framework: the two are different parties.
                        id = e.id() + "@" + framework;
                        if (entities.containsKey(id)) {
                            refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add("Entity '" + e.id()
                                    + "' is not loaded: its id and '" + id + "' are both taken by entities of other frameworks");
                            continue;
                        }
                        refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add("Entity '" + e.id() + "' is listed as '" + id
                                + "': framework '" + other.frameworkId() + "' already has an entity with that id");
                    }
                    placed.put(Arrays.asList(framework, e.id()), id);
                }
                entities.merge(id, inFramework(e, id, framework), RegistrySnapshot::merge);
            }
        }
        Map<String, TrustAnchor> anchors = new LinkedHashMap<>();
        for (TrustSource s : sources.values()) {
            SourceLoadResult r = results.get(s.id());
            if (r == null) {
                continue;
            }
            String framework = s.definition().frameworkId();
            for (TrustAnchor a : r.anchors()) {
                String entityId = a.entityId();
                if (entityId != null) {
                    String own = placed.get(Arrays.asList(framework, entityId));
                    if (own == null && entities.containsKey(entityId)) {
                        refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add("Anchor '" + a.id() + "' is not tied to entity '"
                                + entityId + "': that entity belongs to another framework");
                    }
                    entityId = own == null && entities.containsKey(entityId) ? null : own == null ? entityId : own;
                }
                String id = a.id();
                TrustAnchor other = anchors.get(id);
                if (other != null && !Objects.equals(other.frameworkId(), framework)) {
                    id = a.id() + "@" + framework;
                }
                anchors.putIfAbsent(id, new TrustAnchor(id, a.domain(), a.certificate(), framework, entityId, a.status(),
                        a.constraints(), a.provenance()));
            }
        }
        if (!refused.equals(conflicts)) {
            refused.forEach((source, messages) -> messages.forEach(m -> log.warn("Trust source '{}': {}", source, m)));
            conflicts = refused;
        }
        List<TrustedEntity> merged = List.copyOf(entities.values());
        List<TrustAnchor> anchored = List.copyOf(anchors.values());
        List<Object> content = List.of(merged.stream().map(TrustSourceManager::withoutRetrievalTime).toList(),
                anchored.stream().map(TrustSourceManager::withoutRetrievalTime).toList());
        if (content.equals(published)) {
            return;
        }
        published = content;
        registry.publish(new RegistrySnapshot(version.incrementAndGet(), clock.instant(), frameworks, merged, anchored));
    }

    /** The entity as an entry of {@code framework} under {@code id}, whatever its source wrote. */
    private static TrustedEntity inFramework(TrustedEntity e, String id, String framework) {
        return e.id().equals(id) && Objects.equals(e.frameworkId(), framework) ? e : e.toBuilder().id(id).framework(framework).build();
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
