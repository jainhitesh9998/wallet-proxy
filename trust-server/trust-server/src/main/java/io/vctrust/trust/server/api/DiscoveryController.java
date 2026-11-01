package io.vctrust.trust.server.api;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import io.vctrust.trust.server.service.SnapshotService;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Service discovery document and the JWKS clients pin. */
@RestController
public class DiscoveryController {

    private final ServiceKeyManager keys;
    private final TrustRegistry registry;
    private final TrustSourceManager sources;
    private final DidResolver didResolver;
    private final TrustProperties.Revocation revocation;

    public DiscoveryController(ServiceKeyManager keys, TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                               TrustProperties props) {
        this.keys = keys;
        this.registry = registry;
        this.sources = sources;
        this.didResolver = didResolver;
        this.revocation = props.getRevocation();
    }

    @GetMapping(value = "/.well-known/trust-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> discovery() {
        String base = keys.issuer().replaceAll("/+$", "");
        Map<String, Object> endpoints = new LinkedHashMap<>();
        endpoints.put("frameworks", base + "/api/v1/frameworks");
        endpoints.put("entities", base + "/api/v1/entities");
        endpoints.put("issuers", base + "/api/v1/issuers");
        endpoints.put("verifiers", base + "/api/v1/verifiers");
        endpoints.put("entity_lookup", base + "/api/v1/entities/lookup");
        endpoints.put("issuer_metadata", base + "/api/v1/issuers/metadata");
        endpoints.put("evaluate", base + "/api/v1/evaluate");
        endpoints.put("evaluate_batch", base + "/api/v1/evaluate/batch");
        endpoints.put("x509_validate", base + "/api/v1/x509/validate");
        endpoints.put("x509_anchors", base + "/api/v1/x509/anchors");
        endpoints.put("did_resolve", base + "/api/v1/did/{did}");
        endpoints.put("universal_resolver", base + "/1.0/identifiers/{did}");
        endpoints.put("snapshot", base + "/api/v1/snapshot");
        endpoints.put("crls", base + "/api/v1/revocation/crls");
        endpoints.put("crl_relay", base + "/api/v1/revocation/crl");
        endpoints.put("status_list_relay", base + "/api/v1/revocation/status-list");
        endpoints.put("trqp_authorization", base + "/trqp/authorization");
        endpoints.put("trqp_recognition", base + "/trqp/recognition");
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", keys.issuer());
        doc.put("service", "vc-trust-service");
        doc.put("api_version", "v1");
        doc.put("jwks_uri", base + "/.well-known/jwks.json");
        doc.put("signing_key_thumbprint", keys.thumbprint());
        doc.put("endpoints", endpoints);
        doc.put("signed_response_media_type", "application/jwt");
        // Wallets decide locally from the signed snapshot; /evaluate serves verifier backends and thin clients.
        doc.put("decision_modes", List.of("local", "service"));
        doc.put("snapshot_format", SnapshotService.FORMAT);
        // Devices check CRLs (anchor CRLs ship in the snapshot); OCSP is server-side only and opt-in.
        Map<String, Object> rev = new LinkedHashMap<>();
        rev.put("crl", revocation.isEnabled());
        rev.put("ocsp", revocation.isEnabled() && revocation.isOcsp());
        rev.put("crl_relay", revocation.isEnabled() && revocation.isRelayCrls());
        rev.put("status_list_relay", revocation.isEnabled() && revocation.isRelayStatusLists());
        doc.put("revocation", rev);
        doc.put("credential_formats", new TreeSet<>(CredentialFormats.ALL));
        doc.put("did_methods", didResolver.supportedMethods());
        doc.put("trust_domains", new TreeSet<>(registry.snapshot().domains()));
        doc.put("source_types", sources.sources().stream().map(s -> s.type()).distinct().toList());
        doc.put("registry_version", registry.snapshot().version());
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5))).body(doc);
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/jwk-set+json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofHours(1))).body(keys.publicJwks().toJSONObject());
    }
}
