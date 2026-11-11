package io.vctrust.trust.adapters.support;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ResourceLoader;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parses the service's native entity / anchor document format (used by the static source and the admin API).
 * Shape: {@code {entities: [...], anchors: [...]}}; see {@code docs/configuration.md}.
 */
public final class TrustedEntityParser {

    private TrustedEntityParser() {
    }

    @SuppressWarnings("unchecked")
    public static TrustedEntity entity(Map<String, Object> m, String defaultFramework, Provenance provenance,
                                       ResourceLoader loader) throws IOException {
        String id = Json.string(m, "id");
        if (id == null) {
            throw new IllegalArgumentException("Entity without id");
        }
        TrustedEntity.Builder b = TrustedEntity.builder(id)
                .framework(m.get("framework") != null ? String.valueOf(m.get("framework")) : defaultFramework)
                .provenance(provenance);
        for (String r : Json.strings(m.get("roles"))) {
            b.role(EntityRole.valueOf(r.trim().toUpperCase(Locale.ROOT)));
        }
        if (m.get("identifiers") instanceof List<?> ids) {
            for (Object o : ids) {
                if (o instanceof Map<?, ?> im) {
                    Map<String, Object> idm = (Map<String, Object>) im;
                    b.identifier(new Identifier(IdentifierType.valueOf(Json.string(idm, "type").toUpperCase(Locale.ROOT)),
                            Json.string(idm, "value")));
                } else if (o instanceof String s) {
                    b.identifier(guess(s));
                }
            }
        }
        if (m.get("display") instanceof List<?> ds) {
            for (Object o : ds) {
                Map<String, Object> dm = (Map<String, Object>) o;
                b.display(new LocalizedDisplay(Json.string(dm, "locale"), Json.string(dm, "name"),
                        Json.string(dm, "description"), Json.string(dm, "logoUri")));
            }
        } else if (m.get("name") instanceof String name) {
            b.display(LocalizedDisplay.of("en", name));
        }
        if (m.get("authorizations") instanceof List<?> as) {
            for (Object o : as) {
                Map<String, Object> am = (Map<String, Object>) o;
                b.authorization(new CredentialAuthorization(CredentialFormats.canonical(Json.string(am, "format")),
                        Json.string(am, "type"), Json.object(am.get("constraints"))));
            }
        }
        if (m.get("status") != null) {
            b.status(EntityStatus.valueOf(String.valueOf(m.get("status")).toUpperCase(Locale.ROOT)));
        }
        b.validFrom(AdapterSupport.instant(m.get("validFrom")));
        b.validUntil(AdapterSupport.instant(m.get("validUntil")));
        for (X509Certificate c : AdapterSupport.certificates(m, loader)) {
            b.certificate(c);
        }
        if (m.get("metadata") instanceof Map<?, ?> md) {
            ((Map<String, Object>) md).forEach((k, v) -> b.metadata(k, Json.object(v)));
        }
        if (m.get("metadataPolicy") instanceof Map<?, ?> mp) {
            ((Map<String, Object>) mp).forEach((k, v) -> b.metadataPolicy(k, Json.object(v)));
        }
        if (m.get("attributes") instanceof Map<?, ?> attrs) {
            ((Map<String, Object>) attrs).forEach(b::attribute);
        }
        // contexts: the JSON-LD contexts this party's credentials use, as a URL or {url, sha256} (a pinned digest).
        if (m.get("contexts") instanceof List<?> contexts) {
            List<String> urls = new ArrayList<>();
            Map<String, String> pins = new LinkedHashMap<>();
            for (Object c : contexts) {
                Map<String, Object> cm = c instanceof Map<?, ?> ? Json.object(c) : Map.of("url", String.valueOf(c));
                String url = Json.string(cm, "url");
                if (url == null) {
                    throw new IllegalArgumentException("Entity " + id + ": a context needs a url");
                }
                urls.add(url);
                if (Json.string(cm, "sha256") != null) {
                    pins.put(url, Json.string(cm, "sha256"));
                }
            }
            b.attribute(Oid4vciMetadataMapper.CONTEXTS, urls);
            if (!pins.isEmpty()) {
                b.attribute(Oid4vciMetadataMapper.CONTEXT_DIGESTS, pins);
            }
        }
        return b.build();
    }

    public static List<TrustAnchor> anchors(Map<String, Object> m, String defaultFramework, Provenance provenance,
                                            ResourceLoader loader) throws IOException {
        String domain = Json.string(m, "domain");
        if (domain == null) {
            throw new IllegalArgumentException("Anchor without domain");
        }
        List<X509Certificate> certs = AdapterSupport.certificates(m, loader);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("Anchor in domain " + domain + " has no certificate");
        }
        String framework = m.get("framework") != null ? String.valueOf(m.get("framework")) : defaultFramework;
        EntityStatus status = m.get("status") == null ? EntityStatus.ACTIVE
                : EntityStatus.valueOf(String.valueOf(m.get("status")).toUpperCase(Locale.ROOT));
        List<TrustAnchor> out = new ArrayList<>();
        for (int i = 0; i < certs.size(); i++) {
            String id = Json.string(m, "id");
            out.add(new TrustAnchor(id == null ? null : certs.size() == 1 ? id : id + "-" + i, TrustDomain.of(domain),
                    certs.get(i), framework, Json.string(m, "entity"), status, Json.object(m.get("constraints")), provenance));
        }
        return out;
    }

    /** Guesses the identifier type of a bare string. */
    public static Identifier guess(String s) {
        if (s.startsWith("did:")) {
            return Identifier.did(s);
        }
        if (s.startsWith("https://") || s.startsWith("http://")) {
            return Identifier.url(s);
        }
        return Identifier.of(IdentifierType.CLIENT_ID, s);
    }
}
