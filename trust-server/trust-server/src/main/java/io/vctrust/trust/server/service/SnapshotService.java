package io.vctrust.trust.server.service;

import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Signed offline trust snapshot ({@code typ: trust-snapshot+jwt}): the frameworks, issuer / verifier entities
 * and trust anchors visible to one client. Clients verify it with the pinned service key and use it when the
 * service is unreachable.
 */
public class SnapshotService {

    private static final Set<EntityRole> ROLES = EnumSet.of(EntityRole.CREDENTIAL_ISSUER, EntityRole.VERIFIER,
            EntityRole.WALLET_PROVIDER, EntityRole.ACCREDITATION_AUTHORITY);

    public record Snapshot(String jwt, String etag, long version) {
    }

    private final TrustRegistry registry;
    private final ServiceKeyManager keys;
    private final JsonMapper mapper;
    private final Duration ttl;
    private final Map<String, Snapshot> cache = new ConcurrentHashMap<>();

    public SnapshotService(TrustRegistry registry, ServiceKeyManager keys, JsonMapper mapper, Duration ttl) {
        this.registry = registry;
        this.keys = keys;
        this.mapper = mapper;
        this.ttl = ttl;
        registry.onChange(s -> cache.clear());
    }

    public Snapshot snapshot(ClientProfile client) {
        RegistrySnapshot snap = registry.snapshot();
        String scope = String.join(",", new TreeSet<>(client.frameworks()));
        String key = snap.version() + "|" + scope + "|" + client.clientId();
        return cache.computeIfAbsent(key, k -> build(snap, client, scope));
    }

    @SuppressWarnings("unchecked")
    private Snapshot build(RegistrySnapshot snap, ClientProfile client, String scope) {
        List<Map<String, Object>> frameworks = snap.frameworks().stream().filter(f -> client.accepts(f.id()))
                .map(f -> (Map<String, Object>) mapper.convertValue(f, Map.class)).toList();
        List<Map<String, Object>> entities = snap.entities().stream()
                .filter(e -> client.accepts(e.frameworkId()))
                .filter(e -> e.roles().stream().anyMatch(ROLES::contains))
                .map(e -> (Map<String, Object>) mapper.convertValue(EntityView.of(e), Map.class)).toList();
        List<Map<String, Object>> anchors = snap.allAnchors().stream()
                .filter(a -> client.accepts(a.frameworkId()))
                .map(SnapshotService::anchor).toList();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("version", snap.version());
        claims.put("client_id", client.clientId());
        claims.put("frameworks", frameworks);
        claims.put("entities", entities);
        claims.put("anchors", anchors);
        String jwt = keys.sign("trust-snapshot+jwt", claims, ttl, client.clientId());
        String etag = "\"snap-" + snap.version() + "-" + HexFormat.of().formatHex(
                Hashes.sha256((scope + client.clientId()).getBytes(StandardCharsets.UTF_8))).substring(0, 12) + "\"";
        return new Snapshot(jwt, etag, snap.version());
    }

    static Map<String, Object> anchor(TrustAnchor a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.id());
        m.put("domain", a.domain().name());
        m.put("frameworkId", a.frameworkId());
        m.put("entityId", a.entityId());
        m.put("status", a.status().name());
        m.put("constraints", a.constraints());
        m.put("certificate", Certificates.toBase64(a.certificate()));
        return m;
    }
}
