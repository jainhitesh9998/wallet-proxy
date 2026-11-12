package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.signing.ServiceKeyManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * What the service says about itself to a client that has nothing yet: where its endpoints are, which keys sign its
 * answers, how to authenticate, what it supports, and whether it is ready.
 */
public class ServiceDescription {

    private final ServiceKeyManager keys;
    private final TrustRegistry registry;
    private final TrustSourceManager sources;
    private final DidResolver didResolver;
    private final TrustProperties.Revocation revocation;
    private final TrustProperties.Cache cache;
    private final TrustProperties.Auth auth;
    private final boolean anonymous;
    private final TrustMechanisms mechanisms;

    public ServiceDescription(ServiceKeyManager keys, TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                              TrustProperties props, TrustMechanisms mechanisms) {
        this.keys = keys;
        this.registry = registry;
        this.sources = sources;
        this.didResolver = didResolver;
        this.revocation = props.getRevocation();
        this.cache = props.getCache();
        this.auth = props.getAuth();
        this.anonymous = props.getAnonymous().isEnabled();
        this.mechanisms = mechanisms;
    }

    /** The discovery document. */
    public Map<String, Object> document() {
        String base = keys.issuer().replaceAll("/+$", "");
        Map<String, Object> endpoints = new LinkedHashMap<>();
        endpoints.put("snapshot", base + "/api/v1/snapshot");
        endpoints.put("proxy_issuer_metadata", base + "/api/v1/proxy/issuer-metadata");
        endpoints.put("proxy_did", base + "/api/v1/proxy/did/{did}");
        endpoints.put("proxy_crl", base + "/api/v1/proxy/crl");
        endpoints.put("proxy_status_list", base + "/api/v1/proxy/status-list");
        // Listed while it answers: the CRL and status list relays say whether they are on under "revocation", contexts
        // have no such group.
        if (cache.isRelayContexts()) {
            endpoints.put("proxy_context", base + "/api/v1/proxy/context");
        }
        endpoints.put("issuers", base + "/api/v1/issuers");
        endpoints.put("verifiers", base + "/api/v1/verifiers");
        endpoints.put("frameworks", base + "/api/v1/frameworks");
        endpoints.put("entity_lookup", base + "/api/v1/entities/lookup");
        endpoints.put("evaluate", base + "/api/v1/evaluate");
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", keys.issuer());
        doc.put("service", "wallet-proxy");
        doc.put("api_version", "v1");
        doc.put("jwks_uri", base + "/.well-known/jwks.json");
        doc.put("signing_key_thumbprint", keys.thumbprint());
        // Current key first; retired keys stay listed (and in the JWKS) while clients rotate.
        doc.put("signing_key_thumbprints", keys.thumbprints());
        doc.put("endpoints", endpoints);
        doc.put("signed_response_media_type", "application/jwt");
        // 5 once mechanisms are configured: a client that reads only 4 cannot apply them, and must be updated first.
        doc.put("snapshot_format", SnapshotService.format(mechanisms));
        doc.put("ready", sources.ready());
        // Devices check CRLs themselves: anchor CRLs ship in the snapshot, others come from the CA or through the proxy.
        Map<String, Object> rev = new LinkedHashMap<>();
        rev.put("crl", revocation.isEnabled());
        rev.put("crl_proxy", revocation.isEnabled() && revocation.isRelayCrls());
        rev.put("status_list_proxy", revocation.isEnabled() && revocation.isRelayStatusLists());
        doc.put("revocation", rev);
        List<String> methods = new ArrayList<>();
        if (auth.isApiKeys()) {
            methods.add("api_key");
        }
        if (auth.getOauth().isEnabled()) {
            methods.add("oauth2_jwt");
            doc.put("oauth_token_issuer", auth.getOauth().getIssuer());
            doc.put("oauth_audiences", auth.getOauth().getAudiences().isEmpty() ? List.of(keys.issuer()) : auth.getOauth().getAudiences());
            if (auth.getOauth().getRequiredScope() != null && !auth.getOauth().getRequiredScope().isBlank()) {
                doc.put("oauth_required_scope", auth.getOauth().getRequiredScope());
            }
        }
        if (auth.getMtls().isEnabled()) {
            methods.add("mtls");
        }
        if (anonymous) {
            methods.add("anonymous");
        }
        doc.put("auth_methods_supported", methods);
        // RFC 8705: a token carrying cnf.x5t#S256 is honoured only with that TLS client certificate.
        doc.put("tls_client_certificate_bound_access_tokens", true);
        doc.put("credential_formats", new TreeSet<>(CredentialFormats.ALL));
        doc.put("did_methods", didResolver.supportedMethods());
        doc.put("trust_domains", new TreeSet<>(registry.snapshot().domains()));
        doc.put("source_types", sources.sources().stream().map(s -> s.type()).distinct().toList());
        doc.put("registry_version", registry.snapshot().version());
        return doc;
    }

    /** The public keys answers are signed with, as a JWK set: the key in use and the retired ones clients may still hold. */
    public Map<String, Object> jwks() {
        return keys.publicJwks().toJSONObject();
    }
}
