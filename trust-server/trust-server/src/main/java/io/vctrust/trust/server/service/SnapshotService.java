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
import java.util.Base64;
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
 * client, the DID documents of registered DID identifiers, the JSON-LD contexts their credentials use, and the
 * trust anchors' CRLs. Clients verify it with the pinned service key and evaluate locally, so the service never
 * learns which issuers or verifiers a user deals with, nor which certificates they check for revocation.
 *
 * <p>A snapshot is identified by its content: its ETag is a digest of the claims, so a client polling with
 * {@code If-None-Match} gets 304 for as long as nothing it would see has changed, on any replica. The content is
 * re-derived at most once per {@code recheck} (DID documents rotate without the registry changing), and a snapshot
 * is re-signed once half its lifetime has passed so that a polling client never holds an expiring one.
 */
public class SnapshotService {

    /** Bumped when the claim layout changes incompatibly. */
    public static final int FORMAT = 4;

    public record Snapshot(String jwt, String etag, Instant issuedAt) {
    }

    /**
     * @param maxCrlBytes     larger anchor CRLs are left out (clients fetch them per their lookup policy)
     * @param maxContextBytes JSON-LD context documents are embedded up to this total; past it only their digests are
     * @param recheck         how often a client's snapshot content is re-derived
     */
    public record Options(Duration ttl, boolean embedDidDocuments, int maxDidDocuments, Duration didResolutionDeadline,
                          int maxCrlBytes, int maxContextBytes, Duration recheck) {
    }

    private record Cached(Snapshot snapshot, String digest, Instant checkedAt) {
    }

    private final TrustRegistry registry;
    private final ServiceKeyManager keys;
    private final JsonMapper mapper;
    private final DidService dids;
    private final CrlService crls;
    private final ContextService contexts;
    private final Options options;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    /**
     * @param crls     anchor CRLs to embed (null: none)
     * @param contexts JSON-LD contexts to embed (null: none)
     */
    public SnapshotService(TrustRegistry registry, ServiceKeyManager keys, JsonMapper mapper, DidService dids,
                           CrlService crls, ContextService contexts, Options options, Clock clock) {
        this.registry = registry;
        this.keys = keys;
        this.mapper = mapper;
        this.dids = dids;
        this.crls = crls;
        this.contexts = contexts;
        this.options = options;
        this.clock = clock;
        // A change in the registry or the CRLs is looked at on the next request instead of after the recheck interval.
        registry.onChange(s -> cache.replaceAll((k, c) -> new Cached(c.snapshot(), c.digest(), Instant.MIN)));
        if (crls != null) {
            crls.onChange(() -> cache.replaceAll((k, c) -> new Cached(c.snapshot(), c.digest(), Instant.MIN)));
        }
    }

    public Snapshot snapshot(ClientProfile client) {
        String scope = String.join(",", new TreeSet<>(client.frameworks()));
        Instant now = clock.instant();
        return cache.compute(scope + "|" + client.clientId(), (k, old) -> {
            if (old != null && old.checkedAt().plus(options.recheck()).isAfter(now)) {
                return old;
            }
            Map<String, Object> claims = claims(registry.snapshot(), client);
            String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    Hashes.sha256(mapper.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8))).substring(0, 22);
            boolean resign = old == null || !old.digest().equals(digest)
                    || !old.snapshot().issuedAt().isAfter(now.minus(options.ttl().dividedBy(2)));
            if (!resign) {
                return new Cached(old.snapshot(), digest, now);
            }
            String jwt = keys.sign("trust-snapshot+jwt", claims, options.ttl(), client.clientId());
            return new Cached(new Snapshot(jwt, "\"" + digest + "." + now.getEpochSecond() + "\"", now), digest, now);
        }).snapshot();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(RegistrySnapshot snap, ClientProfile client) {
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
        policy.put("requireSignedIssuerMetadata", client.requireSignedIssuerMetadata());

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("format", FORMAT);
        claims.put("client_id", client.clientId());
        claims.put("policy", policy);
        claims.put("frameworks", frameworks);
        claims.put("entities", entities);
        claims.put("anchors", anchors);
        if (options.embedDidDocuments()) {
            claims.put("didDocuments", didDocuments(visible));
        }
        if (contexts != null) {
            claims.put("contexts", contexts.forSnapshot(visible, options.maxContextBytes()));
        }
        if (crls != null) {
            claims.put("crls", crls.snapshotClaims(a -> client.accepts(a.frameworkId()), options.maxCrlBytes()));
        }
        return claims;
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
