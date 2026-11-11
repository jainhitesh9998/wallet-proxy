package io.vctrust.trust.server.service;

import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * What an operator sees and triggers: the health of the trust sources and their reload, a summary of the registry,
 * the configured clients, and the emptying of the proxy caches. What changes the service's state is audited.
 *
 * <p>Every use case asks for the acting client and refuses one that is not an operator, whatever let the request
 * through to here: the rule does not rest on how requests are routed.
 */
public class AdministrationService {

    private final TrustSourceManager sources;
    private final TrustRegistry registry;
    private final Supplier<Collection<ClientProfile>> clients;
    private final DidService dids;
    private final MetadataService metadata;
    private final ContextService contexts;
    private final StatusListRelay statusLists;

    /** @param clients the configured client profiles */
    public AdministrationService(TrustSourceManager sources, TrustRegistry registry, Supplier<Collection<ClientProfile>> clients,
                                 DidService dids, MetadataService metadata, ContextService contexts, StatusListRelay statusLists) {
        this.sources = sources;
        this.registry = registry;
        this.clients = clients;
        this.dids = dids;
        this.metadata = metadata;
        this.contexts = contexts;
        this.statusLists = statusLists;
    }

    /** Refuses (and records) an operator action by a client that is not an operator. */
    static void requireAdmin(ClientProfile client, String action) {
        if (client == null || !client.admin()) {
            AuditLog.refused(client, action);
            throw ServiceException.forbidden("Admin client required");
        }
    }

    public List<SourceState> sourceStates(ClientProfile admin) {
        requireAdmin(admin, "list-sources");
        return sources.states();
    }

    public SourceState refreshSource(ClientProfile admin, String id) {
        requireAdmin(admin, "refresh-source");
        try {
            AuditLog.sourceRefresh(admin, id);
            return sources.refresh(id);
        } catch (IllegalArgumentException e) {
            throw ServiceException.notFound(e.getMessage());
        }
    }

    public Map<String, Object> registrySummary(ClientProfile admin) {
        requireAdmin(admin, "registry-summary");
        RegistrySnapshot s = registry.snapshot();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", s.version());
        out.put("builtAt", s.builtAt());
        Map<String, Long> byFramework = new TreeMap<>();
        s.entities().forEach(e -> byFramework.merge(String.valueOf(e.frameworkId()), 1L, Long::sum));
        Map<String, Long> byRole = new TreeMap<>();
        s.entities().forEach(e -> e.roles().forEach(r -> byRole.merge(r.name(), 1L, Long::sum)));
        Map<String, Integer> byDomain = new TreeMap<>();
        s.domains().forEach(d -> byDomain.put(d, s.anchors(TrustDomain.of(d)).size()));
        out.put("entitiesByFramework", byFramework);
        out.put("entitiesByRole", byRole);
        out.put("anchorsByDomain", byDomain);
        out.put("didCacheSize", dids.cacheSize());
        return out;
    }

    public List<ClientProfile> clientProfiles(ClientProfile admin) {
        requireAdmin(admin, "list-clients");
        return List.copyOf(clients.get());
    }

    /**
     * Empties every proxy cache: the next request for anything is fetched anew.
     *
     * @return the caches that were emptied
     */
    public List<String> clearCaches(ClientProfile admin) {
        requireAdmin(admin, "clear-caches");
        dids.clear();
        metadata.clear();
        contexts.clear();
        statusLists.clear();
        AuditLog.cachesCleared(admin);
        return List.of("did", "issuer-metadata", "context", "status-list");
    }
}
