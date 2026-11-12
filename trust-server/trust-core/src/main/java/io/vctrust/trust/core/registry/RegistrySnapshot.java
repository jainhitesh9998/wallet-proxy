package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.x509.Certificates;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * An immutable, fully indexed view of all trust information at one point in time. Lookups never block and
 * never observe a half-built registry; a refresh builds a new snapshot and swaps it in.
 */
public final class RegistrySnapshot {

    private final long version;
    private final Instant builtAt;
    private final Map<String, TrustFramework> frameworks;
    private final Map<String, TrustedEntity> entities;
    private final Map<String, List<TrustedEntity>> byIdentifier = new LinkedHashMap<>();
    private final Map<String, List<TrustedEntity>> byCertificate = new LinkedHashMap<>();
    private final Map<String, List<TrustAnchor>> anchorsByDomain = new LinkedHashMap<>();
    private final Map<String, TrustAnchor> anchorsById = new LinkedHashMap<>();

    public RegistrySnapshot(long version, Instant builtAt, Collection<TrustFramework> frameworks,
                            Collection<TrustedEntity> entities, Collection<TrustAnchor> anchors) {
        this.version = version;
        this.builtAt = builtAt;
        Map<String, TrustFramework> fw = new LinkedHashMap<>();
        frameworks.forEach(f -> fw.put(f.id(), f));
        this.frameworks = Map.copyOf(fw);
        Map<String, TrustedEntity> es = new LinkedHashMap<>();
        for (TrustedEntity e : entities) {
            es.put(e.id(), e);
            for (Identifier id : e.identifiers()) {
                byIdentifier.computeIfAbsent(id.key(), k -> new ArrayList<>()).add(e);
            }
            for (X509Certificate c : e.certificates()) {
                byCertificate.computeIfAbsent(Certificates.sha256Thumbprint(c), k -> new ArrayList<>()).add(e);
            }
        }
        this.entities = es;
        for (TrustAnchor a : anchors) {
            if (anchorsById.putIfAbsent(a.id(), a) == null) {
                anchorsByDomain.computeIfAbsent(a.domain().name(), k -> new ArrayList<>()).add(a);
            }
        }
    }

    public static RegistrySnapshot empty() {
        return new RegistrySnapshot(0, Instant.EPOCH, List.of(), List.of(), List.of());
    }

    public long version() {
        return version;
    }

    public Instant builtAt() {
        return builtAt;
    }

    /** Weak validator for HTTP caching of registry-derived responses. */
    public String etag() {
        return "W/\"reg-" + version + "\"";
    }

    public Collection<TrustFramework> frameworks() {
        return frameworks.values();
    }

    public Optional<TrustFramework> framework(String id) {
        return Optional.ofNullable(frameworks.get(id));
    }

    public Collection<TrustedEntity> entities() {
        return entities.values();
    }

    public Optional<TrustedEntity> entity(String id) {
        return Optional.ofNullable(entities.get(id));
    }

    public List<TrustedEntity> find(Predicate<TrustedEntity> filter) {
        return entities.values().stream().filter(filter).toList();
    }

    public List<TrustedEntity> byIdentifier(Identifier id) {
        return byIdentifier.getOrDefault(id.key(), List.of());
    }

    public List<TrustedEntity> byCertificate(X509Certificate cert) {
        return byCertificate.getOrDefault(Certificates.sha256Thumbprint(cert), List.of());
    }

    public List<TrustAnchor> anchors(TrustDomain domain) {
        return anchorsByDomain.getOrDefault(domain.name(), List.of());
    }

    public Collection<TrustAnchor> allAnchors() {
        return anchorsById.values();
    }

    public Set<String> domains() {
        return anchorsByDomain.keySet();
    }

    public Optional<TrustAnchor> anchor(String id) {
        return Optional.ofNullable(anchorsById.get(id));
    }

    /**
     * Merges two entries for one entity, which {@link TrustSourceManager} does only for entries of the same id in
     * the same framework: identifiers, roles, authorizations and metadata are unioned (the earlier source wins on
     * conflicts), the most restrictive status wins, and the merged entry is valid only where both are (the later
     * {@code validFrom} and the earlier {@code validUntil} of those stated; an entry that states none sets no bound).
     * An entry that says the registration ended, or has not begun, restricts the party as a status does: it must not
     * lose to another entry for being listed second. An entry that names no role and whose status is not usable
     * withdraws the party for every role: the merged entry then names no role either.
     */
    static TrustedEntity merge(TrustedEntity a, TrustedEntity b) {
        TrustedEntity.Builder m = a.toBuilder();
        if (a.frameworkId() == null) {
            m.framework(b.frameworkId());
        }
        Set<EntityRole> roles = EnumSet.noneOf(EntityRole.class);
        roles.addAll(a.roles());
        roles.addAll(b.roles());
        // An entry that names no role and is not in good standing withdraws the party whatever it is asked about: the
        // role filter keeps it. Given the roles of the other entry, the merged entry would be dropped by a question of
        // another role, and the chain to the CA would decide. It names no role then either.
        if (withdrawsForEveryRole(a) || withdrawsForEveryRole(b)) {
            roles.clear();
        }
        m.replaceRoles(roles);
        b.identifiers().forEach(m::identifier);
        b.authorizations().forEach(m::authorization);
        if (a.display().isEmpty()) {
            b.display().forEach(m::display);
        }
        b.certificates().stream().filter(c -> !a.certificates().contains(c)).forEach(m::certificate);
        b.metadata().forEach((k, v) -> {
            if (!a.metadata().containsKey(k)) {
                m.metadata(k, v);
            }
        });
        b.metadataPolicy().forEach((k, v) -> {
            if (!a.metadataPolicy().containsKey(k)) {
                m.metadataPolicy(k, v);
            }
        });
        b.attributes().forEach((k, v) -> {
            if (!a.attributes().containsKey(k)) {
                m.attribute(k, v);
            }
        });
        m.status(moreRestrictive(a.status(), b.status()));
        m.validFrom(later(a.validFrom(), b.validFrom()));
        m.validUntil(earlier(a.validUntil(), b.validUntil()));
        Set<String> sources = new LinkedHashSet<>();
        if (a.provenance() != null) sources.add(a.provenance().sourceId());
        if (b.provenance() != null) sources.add(b.provenance().sourceId());
        if (a.attributes().get("mergedFrom") instanceof Collection<?> c) c.forEach(x -> sources.add(String.valueOf(x)));
        m.attribute("mergedFrom", List.copyOf(sources));
        return m.build();
    }

    /** An entry that names no role, with a status that is not usable: it withdraws the party for every role. */
    private static boolean withdrawsForEveryRole(TrustedEntity e) {
        return e.roles().isEmpty() && !e.status().isUsable();
    }

    private static EntityStatus moreRestrictive(EntityStatus a, EntityStatus b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    /** The later of two instants; null only when neither is stated. */
    private static Instant later(Instant a, Instant b) {
        return a == null ? b : b == null || a.isAfter(b) ? a : b;
    }

    /** The earlier of two instants; null only when neither is stated. */
    private static Instant earlier(Instant a, Instant b) {
        return a == null ? b : b == null || a.isBefore(b) ? a : b;
    }
}
