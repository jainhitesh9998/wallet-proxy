package io.vctrust.trust.server.api;

import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;
import io.vctrust.trust.server.security.ClientRegistry;
import io.vctrust.trust.server.service.ContextService;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.StatusListRelay;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/** Operator API: source health and refresh, managed entities/anchors, caches. Requires an admin client. */
@RestController
@RequestMapping("/admin/v1")
public class AdminController {

    private final TrustSourceManager sources;
    private final TrustRegistry registry;
    private final ManagedEntityStore store;
    private final ResourceLoader loader;
    private final ClientRegistry clients;
    private final DidService dids;
    private final MetadataService metadata;
    private final ContextService contexts;
    private final StatusListRelay statusLists;

    /** Who changed what the service trusts: one line per change, on its own logger so it can be routed and kept. */
    private static final Logger audit = LoggerFactory.getLogger("io.vctrust.trust.audit");

    public AdminController(TrustSourceManager sources, TrustRegistry registry, ManagedEntityStore store,
                           ResourceLoader loader, ClientRegistry clients, DidService dids, MetadataService metadata,
                           ContextService contexts, StatusListRelay statusLists) {
        this.sources = sources;
        this.registry = registry;
        this.store = store;
        this.loader = loader;
        this.clients = clients;
        this.dids = dids;
        this.metadata = metadata;
        this.contexts = contexts;
        this.statusLists = statusLists;
    }

    @GetMapping("/sources")
    public List<SourceState> sourceStates() {
        return sources.states();
    }

    @PostMapping("/sources/{id}/refresh")
    public SourceState refresh(ClientProfile admin, @PathVariable String id) {
        try {
            audit.info("client={} action=refresh-source source={}", admin.clientId(), id);
            return sources.refresh(id);
        } catch (IllegalArgumentException e) {
            throw ApiException.notFound(e.getMessage());
        }
    }

    @GetMapping("/registry")
    public Map<String, Object> registrySummary() {
        RegistrySnapshot s = registry.snapshot();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", s.version());
        out.put("builtAt", s.builtAt());
        Map<String, Long> byFramework = new TreeMap<>();
        s.entities().forEach(e -> byFramework.merge(String.valueOf(e.frameworkId()), 1L, Long::sum));
        Map<String, Long> byRole = new TreeMap<>();
        s.entities().forEach(e -> e.roles().forEach(r -> byRole.merge(r.name(), 1L, Long::sum)));
        Map<String, Integer> byDomain = new TreeMap<>();
        s.domains().forEach(d -> byDomain.put(d, s.anchors(io.vctrust.trust.core.model.TrustDomain.of(d)).size()));
        out.put("entitiesByFramework", byFramework);
        out.put("entitiesByRole", byRole);
        out.put("anchorsByDomain", byDomain);
        out.put("didCacheSize", dids.cacheSize());
        return out;
    }

    @GetMapping("/clients")
    public List<ClientProfile> clientProfiles() {
        return List.copyOf(clients.all());
    }

    @GetMapping("/managed/{kind}")
    public List<Map<String, Object>> listManaged(@PathVariable String kind) {
        return store.list(kind(kind));
    }

    @PutMapping("/managed/{kind}/{id}")
    public ResponseEntity<Map<String, Object>> putManaged(ClientProfile admin, @PathVariable String kind, @PathVariable String id,
                                                          @RequestBody Map<String, Object> doc) {
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
            throw ApiException.badRequest("invalid_document", e.getMessage());
        }
        store.put(k, id, d);
        audit.info("client={} action=put-{} id={} framework={}", admin.clientId(), k.name().toLowerCase(Locale.ROOT), id, d.get("framework"));
        refreshManaged();
        return ResponseEntity.ok(d);
    }

    @DeleteMapping("/managed/{kind}/{id}")
    public ResponseEntity<Void> deleteManaged(ClientProfile admin, @PathVariable String kind, @PathVariable String id) {
        if (!store.delete(kind(kind), id)) {
            throw ApiException.notFound("No managed " + kind + " " + id);
        }
        audit.info("client={} action=delete-{} id={}", admin.clientId(), kind(kind).name().toLowerCase(Locale.ROOT), id);
        refreshManaged();
        return ResponseEntity.noContent().build();
    }

    /** Empties every proxy cache: the next request for anything is fetched anew. */
    @PostMapping("/cache/clear")
    public Map<String, Object> clearCaches(ClientProfile admin) {
        dids.clear();
        metadata.clear();
        contexts.clear();
        statusLists.clear();
        audit.info("client={} action=clear-caches", admin.clientId());
        return Map.of("cleared", List.of("did", "issuer-metadata", "context", "status-list"));
    }

    private void refreshManaged() {
        sources.sources().stream().filter(s -> "managed".equals(s.type())).forEach(s -> sources.refresh(s.id()));
    }

    private static ManagedEntityStore.Kind kind(String kind) {
        return switch (kind.toLowerCase(Locale.ROOT)) {
            case "entities", "entity" -> ManagedEntityStore.Kind.ENTITY;
            case "anchors", "anchor" -> ManagedEntityStore.Kind.ANCHOR;
            default -> throw ApiException.notFound("Unknown managed kind " + kind);
        };
    }
}
