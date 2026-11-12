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
import io.vctrust.trust.core.util.ForeignText;
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
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.regex.Pattern;

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
 * of its own framework. An entry whose id another framework already has is listed as {@code <id>@<framework>}, and
 * that name is its framework's, so it is always free ({@link #fallbackNameOf}): an entity of another framework written
 * with it is listed under its own fallback name instead, and such an anchor is not loaded. A source of one framework can therefore add nothing to, and take nothing from, what a
 * client of another framework is told. Two records of one anchor id in one framework that differ (in anything but
 * where and when they were retrieved) are neither loaded: which one counted would depend on the order of the sources.
 * An entry that is not loaded is named in a warning of its source's state. A list that is older than the one already
 * held is not loaded.
 */
public class TrustSourceManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TrustSourceManager.class);
    private static final Duration MIN_REFRESH = Duration.ofSeconds(30);
    private static final Duration RETRY_AFTER_FAILURE = Duration.ofMinutes(2);

    private final TrustRegistry registry;
    private final Collection<TrustFramework> frameworks;
    /** The ids of the configured frameworks and of those a source loads into: each owns the names ending in "@" and its id. */
    private final Set<String> frameworkIds = new TreeSet<>();
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
        this.frameworks.stream().map(TrustFramework::id).filter(Objects::nonNull).forEach(id -> frameworkIds.add(plain(id, "trust.frameworks")));
        this.sources.values().stream().filter(s -> s.definition().frameworkId() != null)
                .forEach(s -> frameworkIds.add(plain(s.definition().frameworkId(), "of source '" + s.id() + "'")));
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

    private static final Pattern PLAIN_ID = Pattern.compile("[A-Za-z0-9._-]+");

    /**
     * A framework id is plain: letters, digits, '.', '_' and '-'. An entry's fallback name is {@code <id>@<framework>},
     * and a name ending in {@code @<framework>} is that framework's alone. With an '@' in a framework id a name could
     * be two frameworks': {@code x@a@b}, the fallback name of an entry {@code x} of framework {@code a@b}, also ends in
     * {@code @b}, and an entry {@code x@a} of framework {@code b} falls back to it too. Such an id is refused at
     * startup, naming the framework; so is any other character outside the plain ones, since an id is a name.
     */
    private static String plain(String id, String where) {
        if (!PLAIN_ID.matcher(id).matches()) {
            throw new IllegalArgumentException("Framework '" + id + "' (" + where + "): a framework id is letters, digits, '.', '_' and '-' only");
        }
        return id;
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

    /**
     * The framework whose fallback name {@code id} is, when that is not {@code framework}. An entry whose id an entry
     * of another framework already has is listed as {@code <id>@<its framework>}; that name belongs to the framework it
     * names, so an entry of any other framework that is written with it does not get it. Otherwise a source loaded
     * earlier could hold the name, and the entry it is the fallback for (a withdrawn issuer, say) would not be loaded
     * at all. Such an entity is listed under its own fallback name instead ({@code acme@other@national} for
     * {@code acme@other} of framework {@code national}): left out, a revoked entry would let its party be trusted through
     * the CA. Such an anchor is not loaded, and the admin API refuses either. The frameworks are those configured and
     * those a source loads into.
     */
    public Optional<String> fallbackNameOf(String id, String framework) {
        if (id == null) {
            return Optional.empty();
        }
        return frameworkIds.stream().filter(f -> !f.equals(framework) && id.endsWith("@" + f)).findFirst();
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
                // The identifier is the asker's, the message may quote the registry's answer.
                log.debug("On-demand resolution of {} by {} failed: {}", ForeignText.escape(identifier.toString()), s.id(),
                        ForeignText.escape(e.getMessage()));
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
                    null, r.entities().size(), r.anchors().size(), r.listInfo(), escaped(r.warnings()), null));
            log.info("Loaded trust source '{}' ({}): {} entities, {} anchors", s.id(), s.type(),
                    r.entities().size(), r.anchors().size());
        } catch (Exception e) {
            // A source's message can quote its list, or whatever answered at the list's location.
            String error = ForeignText.escape(e.getMessage());
            log.warn("Trust source '{}' ({}) failed to load: {}", s.id(), s.type(), error);
            SourceLoadResult last = results.get(s.id());
            states.put(s.id(), new SourceState(s.id(), s.type(), s.definition().frameworkId(), true, start,
                    prev == null ? null : prev.lastSuccess(), error,
                    last == null ? 0 : last.entities().size(), last == null ? 0 : last.anchors().size(),
                    last == null ? null : last.listInfo(), last == null ? List.of() : escaped(last.warnings()), null));
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
                    Optional<String> reserved = fallbackNameOf(id, framework);
                    TrustedEntity other = entities.get(id);
                    if (reserved.isPresent() || (other != null && !Objects.equals(other.frameworkId(), framework))) {
                        // The id is another framework's name, or taken by an entity of another framework: the entity is
                        // listed under the name of its own framework. It is not dropped: an entity is what restricts a
                        // party (a revoked entry left out would let its certificate be trusted through the CA).
                        String why = reserved.isPresent()
                                ? "'" + e.id() + "' is the name an entry of framework '" + reserved.get() + "' is listed under when another framework has its id"
                                : "framework '" + other.frameworkId() + "' already has an entity with that id";
                        id = e.id() + "@" + framework;
                        if (entities.containsKey(id)) {
                            // Only an entry of this framework can hold that name: no other framework may write it.
                            refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add("Entity '" + e.id() + "' is not loaded: " + why
                                    + ", and '" + id + "' is taken too");
                            continue;
                        }
                        refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add("Entity '" + e.id() + "' is listed as '" + id + "': " + why);
                    }
                    placed.put(Arrays.asList(framework, e.id()), id);
                }
                entities.merge(id, inFramework(e, id, framework), RegistrySnapshot::merge);
            }
        }
        // The anchor records placed under each id, with the source of each. An id holds the records of one framework: a
        // record of another framework whose id is taken is placed under <id>@<its framework>.
        Map<String, List<Placed>> placedAnchors = new LinkedHashMap<>();
        for (TrustSource s : sources.values()) {
            SourceLoadResult r = results.get(s.id());
            if (r == null) {
                continue;
            }
            String framework = s.definition().frameworkId();
            for (TrustAnchor a : r.anchors()) {
                Optional<String> reserved = fallbackNameOf(a.id(), framework);
                if (reserved.isPresent()) {
                    refused.computeIfAbsent(s.id(), k -> new ArrayList<>()).add(reservedName(a.id(), reserved.get()));
                    continue;
                }
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
                List<Placed> held = placedAnchors.get(id);
                if (held != null && !Objects.equals(held.getFirst().anchor().frameworkId(), framework)) {
                    id = a.id() + "@" + framework;
                }
                TrustAnchor anchor = new TrustAnchor(id, a.domain(), a.certificate(), framework, entityId, a.status(),
                        boundedCrlUrls(a, s.id(), refused), a.provenance());
                placedAnchors.computeIfAbsent(id, k -> new ArrayList<>()).add(new Placed(s.id(), a.id(), anchor));
            }
        }
        Map<String, TrustAnchor> anchors = new LinkedHashMap<>();
        placedAnchors.forEach((id, records) -> {
            TrustAnchor first = records.getFirst().anchor();
            List<String> differ = records.stream().map(p -> differences(first, p.anchor())).filter(d -> !d.isEmpty())
                    .findFirst().orElse(List.of());
            if (differ.isEmpty()) {
                // The same anchor listed again (by another source of the framework, say) loses nothing.
                anchors.put(id, first);
                return;
            }
            // Records of one anchor that differ: kept first come, which one counted would depend on the order of the
            // sources, and the one left out may be the CA's withdrawal (a status) or constraint. Neither is loaded, and
            // the warning, in the state of each source concerned, names them all.
            List<String> named = records.stream().map(Placed::sourceId).distinct().toList();
            String who = named.size() == 1
                    ? "source '" + named.getFirst() + "' lists it " + (records.size() == 2 ? "twice" : records.size() + " times")
                    : "sources " + quoted(named) + " list it";
            List<String> written = records.stream().map(Placed::writtenId).distinct().toList();
            String message = "Anchor '" + id + "' is not loaded: " + who + " in framework '" + first.frameworkId() + "'"
                    + (written.size() > 1 ? " (written as " + quoted(written) + ")" : "")
                    + " with records that differ (" + String.join(", ", differ) + "), and which one counted would depend on the order of the sources";
            named.forEach(source -> refused.computeIfAbsent(source, k -> new ArrayList<>()).add(message));
        });
        // What the registry could not take quotes ids and locations as the lists wrote them.
        Map<String, List<String>> reported = new LinkedHashMap<>();
        refused.forEach((source, messages) -> reported.put(source, escaped(messages)));
        if (!reported.equals(conflicts)) {
            reported.forEach((source, messages) -> messages.forEach(m -> log.warn("Trust source '{}': {}", source, m)));
            conflicts = reported;
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

    /**
     * The anchor's constraints with at most {@link TrustAnchor#MAX_CRL_URLS} CRL locations: the first http(s) locations
     * of {@code crlUrls}, in the order the record names them. The registry, the snapshots and the devices then see no
     * more; the rest is reported in a warning of the anchor's source. A list decides how many locations there are, and
     * each is fetched by the service and by every device that holds the snapshot.
     */
    private static Map<String, Object> boundedCrlUrls(TrustAnchor a, String sourceId, Map<String, List<String>> refused) {
        List<String> urls = a.crlUrls();
        if (urls.size() <= TrustAnchor.MAX_CRL_URLS) {
            return a.constraints();
        }
        Map<String, Object> bounded = new LinkedHashMap<>(a.constraints());
        bounded.put("crlUrls", List.copyOf(urls.subList(0, TrustAnchor.MAX_CRL_URLS)));
        refused.computeIfAbsent(sourceId, k -> new ArrayList<>()).add("Anchor '" + a.id() + "' names " + urls.size()
                + " CRL locations (crlUrls); an anchor counts with at most " + TrustAnchor.MAX_CRL_URLS + ", and the other "
                + (urls.size() - TrustAnchor.MAX_CRL_URLS) + " are not used, from " + urls.get(TrustAnchor.MAX_CRL_URLS) + " on");
        return bounded;
    }

    /** Warnings as a source's state and the log show them: text from a list, escaped and cut ({@link ForeignText}). */
    private static List<String> escaped(List<String> warnings) {
        return warnings.stream().map(ForeignText::escape).toList();
    }

    private static String reservedName(String id, String owner) {
        return "Anchor '" + id + "' is not loaded: '" + id + "' is the name an entry of framework '" + owner
                + "' is listed under when another framework has its id, and only that framework may use it";
    }

    /** {@code 'a'}, {@code 'a' and 'b'}, {@code 'a', 'b' and 'c'}. */
    private static String quoted(List<String> names) {
        List<String> q = names.stream().map(n -> "'" + n + "'").toList();
        return q.size() == 1 ? q.getFirst() : String.join(", ", q.subList(0, q.size() - 1)) + " and " + q.getLast();
    }

    /**
     * An anchor record placed under its id, the source that listed it and the id it was written with (another framework's
     * anchor of that id places it under {@code <id>@<framework>}).
     */
    private record Placed(String sourceId, String writtenId, TrustAnchor anchor) {
    }

    /**
     * What two records of one anchor say differently: anything but where and when they were retrieved (the provenance).
     * Empty when they say the same, and one placed instead of the other loses nothing.
     */
    private static List<String> differences(TrustAnchor a, TrustAnchor b) {
        List<String> differ = new ArrayList<>();
        if (!Objects.equals(a.frameworkId(), b.frameworkId())) {
            differ.add("framework");
        }
        if (!a.domain().equals(b.domain())) {
            differ.add("domain");
        }
        if (!a.thumbprint().equals(b.thumbprint())) {
            differ.add("certificate");
        }
        if (!Objects.equals(a.entityId(), b.entityId())) {
            differ.add("entity");
        }
        if (a.status() != b.status()) {
            differ.add("status");
        }
        if (!a.constraints().equals(b.constraints())) {
            differ.add("constraints");
        }
        return differ;
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
