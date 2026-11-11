package io.vctrust.trust.server.service;

import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.util.Enums;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.util.Hashes;

import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * The normalized registry as one client may see it: its frameworks, pages of issuers and verifiers, and the
 * entities behind an identifier, asked of on-demand sources when the registry does not list them.
 */
public class RegistryQueryService {

    /** One page of a listing, with the registry version it was taken from. */
    public record Page<T>(List<T> items, int total, int page, int size, long registryVersion) {
    }

    /**
     * An answer for one client. A {@code cacheable} answer holds until the registry changes; one that sources were
     * asked for on demand is not to be stored.
     */
    public record Answer<T>(T body, String clientId, long registryVersion, boolean cacheable) {

        /**
         * The entity tag of one representation of this answer.
         *
         * @param path   the path asked for
         * @param query  its query string, null when there was none
         * @param signed whether the representation is the signed one
         */
        public String etag(String path, String query, boolean signed) {
            // Body depends on registry version, client scope, path, query and representation.
            String variant = clientId + "|" + path + "?" + query + "|" + signed;
            return "W/\"reg-" + registryVersion + "-" + HexFormat.of().formatHex(
                    Hashes.sha256(variant.getBytes(StandardCharsets.UTF_8))).substring(0, 16) + "\"";
        }
    }

    private final TrustRegistry registry;
    private final TrustSourceManager sources;

    public RegistryQueryService(TrustRegistry registry, TrustSourceManager sources) {
        this.registry = registry;
        this.sources = sources;
    }

    public Answer<List<Map<String, Object>>> frameworks(ClientProfile client) {
        RegistrySnapshot snap = registry.snapshot();
        List<Map<String, Object>> out = snap.frameworks().stream().filter(f -> client.accepts(f.id())).map(f -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.id());
            m.put("name", f.name());
            m.put("description", f.description());
            m.put("governanceUri", f.governanceUri());
            m.put("attributes", f.attributes());
            m.put("entityCount", snap.find(e -> f.id().equals(e.frameworkId())).size());
            m.put("anchorCount", snap.allAnchors().stream().filter(a -> f.id().equals(a.frameworkId())).count());
            return m;
        }).toList();
        return cacheable(snap, client, out);
    }

    /** Credential issuers; every filter is optional (null). */
    public Answer<Page<EntityView>> issuers(ClientProfile client, String framework, String format, String type, String q,
                                            int page, int size) {
        return list(client, EntityRole.CREDENTIAL_ISSUER, framework, format, type, q, page, size);
    }

    /** Verifiers; every filter is optional (null). */
    public Answer<Page<EntityView>> verifiers(ClientProfile client, String framework, String q, int page, int size) {
        return list(client, EntityRole.VERIFIER, framework, null, null, q, page, size);
    }

    /**
     * The entities known by an identifier.
     *
     * @param type     the identifier's type, or null to try the types its form suggests
     * @param onDemand whether sources that resolve on demand are asked when the registry lists nobody
     */
    public Answer<List<EntityView>> lookup(ClientProfile client, String identifier, String type, boolean onDemand) {
        RegistrySnapshot snap = registry.snapshot();
        List<Identifier> ids = type != null
                ? List.of(Identifier.of(Enums.parse(IdentifierType.class, type, "identifier type"), identifier))
                : TrustEvaluator.identifiersFor(identifier);
        Set<TrustedEntity> found = new LinkedHashSet<>();
        ids.forEach(id -> snap.byIdentifier(id).stream().filter(e -> client.accepts(e.frameworkId())).forEach(found::add));
        if (found.isEmpty() && onDemand) {
            // Registries too large for the snapshot (OpenID Federation, EBSI) are asked about this one identifier.
            for (Identifier id : ids) {
                sources.resolveOnDemand(id, client::accepts).filter(e -> client.accepts(e.frameworkId())).ifPresent(found::add);
                if (!found.isEmpty()) {
                    break;
                }
            }
            return new Answer<>(found.stream().map(EntityView::of).toList(), client.clientId(), snap.version(), false);
        }
        return cacheable(snap, client, found.stream().map(EntityView::of).toList());
    }

    private Answer<Page<EntityView>> list(ClientProfile client, EntityRole role, String framework, String format, String type,
                                          String q, int page, int size) {
        if (size < 1 || size > 1000 || page < 0) {
            throw ServiceException.invalidRequest("invalid_request", "page must be >= 0 and size within 1..1000");
        }
        RegistrySnapshot snap = registry.snapshot();
        Predicate<TrustedEntity> p = e -> client.accepts(e.frameworkId());
        if (role != null) p = p.and(e -> e.hasRole(role));
        if (framework != null) p = p.and(e -> framework.equals(e.frameworkId()));
        if (format != null || type != null) {
            String f = CredentialFormats.canonical(format);
            p = p.and(e -> !e.authorizations().isEmpty() && e.isAuthorizedFor(f, type, true));
        }
        if (q != null && !q.isBlank()) {
            String needle = q.toLowerCase(Locale.ROOT);
            p = p.and(e -> e.id().toLowerCase(Locale.ROOT).contains(needle)
                    || e.display().stream().anyMatch(d -> d.name() != null && d.name().toLowerCase(Locale.ROOT).contains(needle))
                    || e.identifiers().stream().anyMatch(i -> i.value().toLowerCase(Locale.ROOT).contains(needle)));
        }
        List<EntityView> all = snap.find(p).stream()
                .sorted(Comparator.comparing((TrustedEntity e) -> String.valueOf(e.frameworkId())).thenComparing(e -> e.displayName("en")))
                .map(EntityView::of).toList();
        int from = (int) Math.min((long) page * size, all.size()); // page * size overflows an int for a large page
        int to = Math.min(from + size, all.size());
        return cacheable(snap, client, new Page<>(all.subList(from, to), all.size(), page, size, snap.version()));
    }

    private static <T> Answer<T> cacheable(RegistrySnapshot snap, ClientProfile client, T body) {
        return new Answer<>(body, client.clientId(), snap.version(), true);
    }
}
