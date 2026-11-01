package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.server.config.TrustJacksonModule;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/** Browsing the normalized registry: frameworks, entities, issuers, verifiers, identifier lookup. */
@RestController
@RequestMapping("/api/v1")
public class RegistryController {

    private final TrustRegistry registry;
    private final TrustSourceManager sources;
    private final ResponseSigner signer;

    public RegistryController(TrustRegistry registry, TrustSourceManager sources, ResponseSigner signer) {
        this.registry = registry;
        this.sources = sources;
        this.signer = signer;
    }

    @GetMapping("/frameworks")
    public ResponseEntity<Object> frameworks(ClientProfile client, HttpServletRequest req) {
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
        return cached(req, client, snap, out);
    }

    @GetMapping("/entities")
    public ResponseEntity<Object> entities(ClientProfile client, HttpServletRequest req,
                                           @RequestParam(required = false) String role,
                                           @RequestParam(required = false) String framework,
                                           @RequestParam(required = false) String format,
                                           @RequestParam(required = false) String type,
                                           @RequestParam(required = false) String q,
                                           @RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "100") int size) {
        return list(client, req, Dtos.parseRole(role), framework, format, type, q, page, size);
    }

    @GetMapping("/issuers")
    public ResponseEntity<Object> issuers(ClientProfile client, HttpServletRequest req,
                                          @RequestParam(required = false) String framework,
                                          @RequestParam(required = false) String format,
                                          @RequestParam(required = false) String type,
                                          @RequestParam(required = false) String q,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "100") int size) {
        return list(client, req, EntityRole.CREDENTIAL_ISSUER, framework, format, type, q, page, size);
    }

    @GetMapping("/verifiers")
    public ResponseEntity<Object> verifiers(ClientProfile client, HttpServletRequest req,
                                            @RequestParam(required = false) String framework,
                                            @RequestParam(required = false) String q,
                                            @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "100") int size) {
        return list(client, req, EntityRole.VERIFIER, framework, null, null, q, page, size);
    }

    @GetMapping("/entities/lookup")
    public ResponseEntity<Object> lookup(ClientProfile client, HttpServletRequest req, @RequestParam String identifier,
                                         @RequestParam(required = false) String type,
                                         @RequestParam(defaultValue = "false") boolean onDemand) {
        RegistrySnapshot snap = registry.snapshot();
        List<Identifier> ids = type != null
                ? List.of(Identifier.of(IdentifierType.valueOf(type.toUpperCase(Locale.ROOT)), identifier))
                : TrustEvaluator.identifiersFor(identifier);
        Set<TrustedEntity> found = new LinkedHashSet<>();
        ids.forEach(id -> snap.byIdentifier(id).stream().filter(e -> client.accepts(e.frameworkId())).forEach(found::add));
        if (found.isEmpty() && onDemand) {
            // Registries too large for the snapshot (OpenID Federation, EBSI) are asked about this one identifier.
            for (Identifier id : ids) {
                sources.resolveOnDemand(id, client.frameworks()).filter(e -> client.accepts(e.frameworkId())).ifPresent(found::add);
                if (!found.isEmpty()) {
                    break;
                }
            }
            return signer.respond(req, client, "trust-registry+jwt", found.stream().map(EntityView::of).toList(),
                    ResponseEntity.ok().cacheControl(CacheControl.noStore()));
        }
        return cached(req, client, snap, found.stream().map(EntityView::of).toList());
    }

    @GetMapping("/entities/by-id")
    public ResponseEntity<Object> byIdParam(ClientProfile client, HttpServletRequest req, @RequestParam String id) {
        return detail(client, req, id);
    }

    @GetMapping("/entities/{id}")
    public ResponseEntity<Object> byId(ClientProfile client, HttpServletRequest req, @PathVariable String id) {
        return detail(client, req, id);
    }

    private ResponseEntity<Object> detail(ClientProfile client, HttpServletRequest req, String id) {
        RegistrySnapshot snap = registry.snapshot();
        TrustedEntity e = snap.entity(id).filter(x -> client.accepts(x.frameworkId()))
                .orElseThrow(() -> ApiException.notFound("No entity " + id));
        List<Map<String, Object>> anchors = snap.allAnchors().stream().filter(a -> id.equals(a.entityId()))
                .map(TrustJacksonModule::anchorView).toList();
        return cached(req, client, snap, new Dtos.EntityDetail(EntityView.of(e), e.metadata(), e.metadataPolicy(), anchors));
    }

    private ResponseEntity<Object> list(ClientProfile client, HttpServletRequest req, EntityRole role, String framework,
                                        String format, String type, String q, int page, int size) {
        if (size < 1 || size > 1000 || page < 0) {
            throw ApiException.badRequest("invalid_request", "page must be >= 0 and size within 1..1000");
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
        int from = Math.min(page * size, all.size());
        int to = Math.min(from + size, all.size());
        return cached(req, client, snap, new Dtos.Page<>(all.subList(from, to), all.size(), page, size, snap.version()));
    }

    private ResponseEntity<Object> cached(HttpServletRequest req, ClientProfile client, RegistrySnapshot snap, Object body) {
        // Body depends on registry version, client scope, path, query and representation.
        String variant = client.clientId() + "|" + req.getRequestURI() + "?" + req.getQueryString() + "|" + ResponseSigner.wantsJwt(req);
        String etag = "W/\"reg-" + snap.version() + "-" + java.util.HexFormat.of().formatHex(
                io.vctrust.trust.core.util.Hashes.sha256(variant.getBytes(java.nio.charset.StandardCharsets.UTF_8))).substring(0, 16) + "\"";
        String inm = req.getHeader("If-None-Match");
        if (etag.equals(inm)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build();
        }
        return signer.respond(req, client, "trust-registry+jwt", body,
                ResponseEntity.ok().eTag(etag).cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate()));
    }
}
