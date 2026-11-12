package io.vctrust.trust.server.service;

import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The entities and anchors an operator maintains at run time. A document is stored only if it parses as what it
 * claims to be, for the framework the managed source loads into, and does not take the name another framework's entry
 * is listed under when its id is taken; every change is audited and published by reloading the managed sources. Like
 * every operator use case it refuses a client that is not an operator.
 */
public class ManagedEntryService {

    private final ManagedEntityStore store;
    private final ResourceLoader loader;
    private final TrustSourceManager sources;

    public ManagedEntryService(ManagedEntityStore store, ResourceLoader loader, TrustSourceManager sources) {
        this.store = store;
        this.loader = loader;
        this.sources = sources;
    }

    /** What an entry may be called: it becomes a path segment, a database key and a field of the audit log. */
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:@~-]{0,127}");

    /** @param kind {@code entities} or {@code anchors} (singular accepted) */
    public List<Map<String, Object>> list(ClientProfile admin, String kind) {
        AdministrationService.requireAdmin(admin, "list-managed");
        return store.list(kind(kind));
    }

    /** Stores {@code doc} under {@code id} and returns it as stored. */
    public Map<String, Object> put(ClientProfile admin, String kind, String id, Map<String, Object> doc) {
        AdministrationService.requireAdmin(admin, "put-managed");
        ManagedEntityStore.Kind k = kind(kind);
        if (!ID.matcher(id).matches()) {
            throw ServiceException.invalidRequest("invalid_document", "An id is 1 to 128 letters, digits or . _ : @ ~ - and starts with a letter or digit");
        }
        Map<String, Object> d = new LinkedHashMap<>(doc);
        d.put("id", id);
        // Parsed as the managed source will parse it: for that source's framework, and naming web locations only.
        String framework = managedFramework(d.get("framework"));
        d.put("framework", framework);
        Provenance probe = Provenance.of("managed", "managed", framework, "admin-api", Instant.now());
        List<String> ids;
        try {
            ids = k == ManagedEntityStore.Kind.ENTITY
                    ? List.of(TrustedEntityParser.entity(d, framework, probe, ResourceLoader.remoteOnly(loader)).id())
                    : TrustedEntityParser.anchors(d, framework, probe, ResourceLoader.remoteOnly(loader)).stream().map(TrustAnchor::id).toList();
        } catch (Exception e) {
            throw ServiceException.invalidRequest("invalid_document", e.getMessage());
        }
        // The registry would not load it (TrustSourceManager.fallbackNameOf): say so now rather than store it.
        for (String loaded : ids) {
            sources.fallbackNameOf(loaded, framework).ifPresent(owner -> {
                throw ServiceException.invalidRequest("invalid_document", "'" + loaded + "' is the name an entry of framework '" + owner
                        + "' is listed under when another framework has its id; an entry of framework '" + framework + "' cannot have it");
            });
        }
        store.put(k, id, d);
        AuditLog.managedPut(admin, k.name().toLowerCase(Locale.ROOT), id, d.get("framework"));
        refreshManaged();
        return d;
    }

    public void delete(ClientProfile admin, String kind, String id) {
        AdministrationService.requireAdmin(admin, "delete-managed");
        if (!store.delete(kind(kind), id)) {
            throw ServiceException.notFound("No managed " + kind + " " + id);
        }
        AuditLog.managedDelete(admin, kind(kind).name().toLowerCase(Locale.ROOT), id);
        refreshManaged();
    }

    /**
     * The framework managed entries load into. An entry that names a framework must name that of a managed source:
     * placing entries elsewhere takes a managed source configured for that framework.
     */
    private String managedFramework(Object named) {
        List<String> frameworks = sources.sources().stream().filter(s -> "managed".equals(s.type()))
                .map(s -> s.definition().frameworkId()).distinct().toList();
        if (frameworks.isEmpty()) {
            throw ServiceException.invalidRequest("invalid_document", "No managed source is configured (trust.sources: type managed)");
        }
        if (named == null) {
            return frameworks.getFirst();
        }
        if (!frameworks.contains(String.valueOf(named))) {
            throw ServiceException.invalidRequest("invalid_document", "Managed entries load into " + frameworks
                    + "; an entry cannot name another framework");
        }
        return String.valueOf(named);
    }

    private void refreshManaged() {
        sources.sources().stream().filter(s -> "managed".equals(s.type())).forEach(s -> sources.refresh(s.id()));
    }

    private static ManagedEntityStore.Kind kind(String kind) {
        return switch (kind.toLowerCase(Locale.ROOT)) {
            case "entities", "entity" -> ManagedEntityStore.Kind.ENTITY;
            case "anchors", "anchor" -> ManagedEntityStore.Kind.ANCHOR;
            default -> throw ServiceException.notFound("Unknown managed kind " + kind);
        };
    }
}
