package io.vctrust.trust.server.service;

import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The entities and anchors an operator maintains at run time. A document is stored only if it parses as what it
 * claims to be; every change is audited and published by reloading the managed sources.
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

    /** @param kind {@code entities} or {@code anchors} (singular accepted) */
    public List<Map<String, Object>> list(String kind) {
        return store.list(kind(kind));
    }

    /** Stores {@code doc} under {@code id} and returns it as stored. */
    public Map<String, Object> put(ClientProfile admin, String kind, String id, Map<String, Object> doc) {
        ManagedEntityStore.Kind k = kind(kind);
        Map<String, Object> d = new LinkedHashMap<>(doc);
        d.put("id", id);
        Provenance probe = Provenance.of("managed", "managed", null, "admin-api", Instant.now());
        try {
            if (k == ManagedEntityStore.Kind.ENTITY) {
                TrustedEntityParser.entity(d, null, probe, loader);
            } else {
                TrustedEntityParser.anchors(d, null, probe, loader);
            }
        } catch (Exception e) {
            throw ServiceException.invalidRequest("invalid_document", e.getMessage());
        }
        store.put(k, id, d);
        AuditLog.managedPut(admin, k.name().toLowerCase(Locale.ROOT), id, d.get("framework"));
        refreshManaged();
        return d;
    }

    public void delete(ClientProfile admin, String kind, String id) {
        if (!store.delete(kind(kind), id)) {
            throw ServiceException.notFound("No managed " + kind + " " + id);
        }
        AuditLog.managedDelete(admin, kind(kind).name().toLowerCase(Locale.ROOT), id);
        refreshManaged();
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
