package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * The signed trust snapshot ({@code typ: trust-snapshot+jwt}): everything one client needs to make trust
 * decisions on its own device — the frameworks, entities, trust anchors and evaluation policy visible to that
 * client, the DID documents of registered DID identifiers, and the trust anchors' CRLs. Clients verify it with
 * the pinned service key and evaluate locally, so the service never learns which issuers or verifiers a user
 * deals with, nor which certificates they check for revocation.
 *
 * <p>Snapshots are cached per registry version, CRL version and client, and re-signed once half their lifetime
 * has passed so that a client polling with {@code If-None-Match} never keeps an expired snapshot.
 */
public class SnapshotService {

    /** Bumped when the claim layout changes incompatibly. */
    public static final int FORMAT = 3;

    public record Snapshot(String jwt, String etag, long version, Instant issuedAt) {
    }

    /** @param maxCrlBytes larger anchor CRLs are left out (clients fetch them per their lookup policy) */
    public record Options(Duration ttl, boolean embedDidDocuments, int maxDidDocuments, Duration didResolutionDeadline,
                          int maxCrlBytes) {
    }

    private final TrustRegistry registry;
    private final ServiceKeyManager keys;
    private final JsonMapper mapper;
    private final DidService dids;
    private final CrlService crls;
    private final Options options;
    private final Clock clock;
    private final Map<String, Snapshot> cache = new ConcurrentHashMap<>();

    /** @param crls anchor CRLs to embed (null: none) */
    public SnapshotService(TrustRegistry registry, ServiceKeyManager keys, JsonMapper mapper, DidService dids,
                           CrlService crls, Options options, Clock clock) {
        this.registry = registry;
        this.keys = keys;
        this.mapper = mapper;
        this.dids = dids;
        this.crls = crls;
        this.options = options;
        this.clock = clock;
        registry.onChange(s -> cache.clear());
        if (crls != null) {
            crls.onChange(cache::clear);
        }
    }

    public Snapshot snapshot(ClientProfile client) {
        RegistrySnapshot snap = registry.snapshot();
        String scope = String.join(",", new TreeSet<>(client.frameworks()));
        String key = snap.version() + "|" + (crls == null ? 0 : crls.version()) + "|" + scope + "|" + client.clientId();
        Instant refreshAfter = clock.instant().minus(options.ttl().dividedBy(2));
        return cache.compute(key, (k, old) -> old != null && old.issuedAt().isAfter(refreshAfter) ? old : build(snap, client, scope));
    }

    @SuppressWarnings("unchecked")
    private Snapshot build(RegistrySnapshot snap, ClientProfile client, String scope) {
        List<Map<String, Object>> frameworks = snap.frameworks().stream().filter(f -> client.accepts(f.id()))
                .map(f -> (Map<String, Object>) mapper.convertValue(f, Map.class)).toList();
        List<TrustedEntity> visible = snap.entities().stream().filter(e -> client.accepts(e.frameworkId())).toList();
        List<Map<String, Object>> entities = visible.stream().map(this::entity).toList();
        List<Map<String, Object>> anchors = snap.allAnchors().stream()
                .filter(a -> client.accepts(a.frameworkId()))
                .map(SnapshotService::anchor).toList();
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("frameworks", new TreeSet<>(client.frameworks()));
        policy.put("strictAuthorization", client.strictAuthorization());
        policy.put("requireRevocationStatus", client.requireRevocationStatus());

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("format", FORMAT);
        claims.put("version", snap.version());
        claims.put("client_id", client.clientId());
        claims.put("policy", policy);
        claims.put("frameworks", frameworks);
        claims.put("entities", entities);
        claims.put("anchors", anchors);
        if (options.embedDidDocuments()) {
            claims.put("didDocuments", didDocuments(visible));
        }
        if (crls != null) {
            claims.put("crls", crls.snapshotClaims(a -> client.accepts(a.frameworkId()), options.maxCrlBytes()));
        }
        Instant issuedAt = clock.instant();
        String jwt = keys.sign("trust-snapshot+jwt", claims, options.ttl(), client.clientId());
        String etag = "\"snap-" + snap.version() + "-" + issuedAt.getEpochSecond() + "-" + HexFormat.of().formatHex(
                Hashes.sha256((scope + client.clientId()).getBytes(StandardCharsets.UTF_8))).substring(0, 12) + "\"";
        return new Snapshot(jwt, etag, snap.version(), issuedAt);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> entity(TrustedEntity e) {
        Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) mapper.convertValue(EntityView.of(e), Map.class));
        // Clients that fetch issuer metadata directly apply the registry's metadata policy themselves.
        if (!e.metadataPolicy().isEmpty()) {
            m.put("metadataPolicy", e.metadataPolicy());
        }
        return m;
    }

    /**
     * Resolves the DID identifiers of visible entities in parallel, bounded by a deadline. Documents that are not
     * ready in time are left out (the client resolves them itself) and will usually be cached by the next build.
     */
    private Map<String, Object> didDocuments(List<TrustedEntity> entities) {
        List<String> list = entities.stream().flatMap(e -> e.identifiers().stream())
                .filter(i -> i.type() == IdentifierType.DID).map(Identifier::value).distinct()
                .limit(Math.max(0, options.maxDidDocuments())).toList();
        Map<String, Object> out = new LinkedHashMap<>();
        if (list.isEmpty() || dids == null) {
            return out;
        }
        ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor();
        try {
            Map<String, Future<DidResolutionResult>> pending = new LinkedHashMap<>();
            list.forEach(did -> pending.put(did, exec.submit(() -> dids.resolve(did))));
            long deadline = System.nanoTime() + options.didResolutionDeadline().toNanos();
            for (Map.Entry<String, Future<DidResolutionResult>> p : pending.entrySet()) {
                try {
                    DidResolutionResult r = p.getValue().get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                    if (r.isSuccess() && r.didDocument() != null) {
                        out.put(p.getKey(), r.didDocument());
                    }
                } catch (Exception e) {
                    // Not resolvable in time: the client resolves it by standard means.
                }
            }
        } finally {
            exec.shutdownNow();
        }
        return out;
    }

    static Map<String, Object> anchor(TrustAnchor a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.id());
        m.put("domain", a.domain().name());
        m.put("frameworkId", a.frameworkId());
        m.put("entityId", a.entityId());
        m.put("status", a.status().name());
        m.put("constraints", publicConstraints(a));
        m.put("certificate", Certificates.toBase64(a.certificate()));
        if (a.provenance() != null) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("sourceId", a.provenance().sourceId());
            p.put("sourceUri", a.provenance().sourceUri());
            m.put("provenance", p);
        }
        return m;
    }

    /** Anchor constraints without a pushed CRL (CRLs ship in the {@code crls} claim). */
    public static Map<String, Object> publicConstraints(TrustAnchor a) {
        if (!a.constraints().containsKey("crl")) {
            return a.constraints();
        }
        Map<String, Object> c = new LinkedHashMap<>(a.constraints());
        c.remove("crl");
        return c;
    }
}
