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
import io.vctrust.trust.core.util.Enums;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses the service's native entity / anchor document format (used by the static source and the admin API).
 * Shape: {@code {entities: [...], anchors: [...]}}; see {@code docs/configuration.md}. Entries take the framework
 * of their source; a {@code framework} key is accepted only when it names that same framework.
 *
 * <p>An entry that cannot be read is refused with an exception that says what is wrong with it, never read in part:
 * an entity entry is what restricts a party whose CA is trusted, and one left out (or read without its status) lets
 * that party be trusted through the CA. The sources that use this parser fail to load on such an entry, naming it
 * ({@link #name}), and keep their last good content.
 */
public final class TrustedEntityParser {

    private TrustedEntityParser() {
    }

    /**
     * How an error names an entry of a list: {@code entity 'acme'} by its id when it has one that can be read,
     * otherwise by its place, {@code entity entities[3]}.
     *
     * @param kind  {@code entity} or {@code anchor}
     * @param list  the name of the list ({@code entities}, {@code anchors})
     * @param index the entry's place in that list, from 0
     */
    public static String name(String kind, String list, int index, Object entry) {
        Object id = entry instanceof Map<?, ?> m ? m.get("id") : null;
        return id instanceof String s && !s.isBlank() ? kind + " '" + shown(s) + "'" : kind + " " + list + "[" + index + "]";
    }

    /** A value from a document as an error quotes it: at most 40 characters, as {@link Enums} quotes one. */
    static String shown(String value) {
        return value.length() <= 40 ? value : value.substring(0, 40) + "…";
    }

    @SuppressWarnings("unchecked")
    public static TrustedEntity entity(Map<String, Object> m, String sourceFramework, Provenance provenance,
                                       ResourceLoader loader) throws IOException {
        String id = Json.string(m, "id");
        if (id == null) {
            throw new IllegalArgumentException("it has no id");
        }
        TrustedEntity.Builder b = TrustedEntity.builder(id).framework(framework(m, sourceFramework))
                .provenance(provenance);
        for (String r : Json.strings(m.get("roles"))) {
            b.role(Enums.parse(EntityRole.class, r, "role"));
        }
        if (m.get("identifiers") instanceof List<?> ids) {
            for (Object o : ids) {
                if (o instanceof Map<?, ?> im) {
                    Map<String, Object> idm = (Map<String, Object>) im;
                    b.identifier(new Identifier(Enums.parse(IdentifierType.class, Json.string(idm, "type"), "identifier type"),
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
            b.status(Enums.parse(EntityStatus.class, String.valueOf(m.get("status")), "status"));
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
                    throw new IllegalArgumentException("a context needs a url");
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

    public static List<TrustAnchor> anchors(Map<String, Object> m, String sourceFramework, Provenance provenance,
                                            ResourceLoader loader) throws IOException {
        String domain = Json.string(m, "domain");
        if (domain == null) {
            throw new IllegalArgumentException("it has no domain");
        }
        List<X509Certificate> certs = AdapterSupport.certificates(m, loader);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("it has no certificate");
        }
        String framework = framework(m, sourceFramework);
        EntityStatus status = m.get("status") == null ? EntityStatus.ACTIVE
                : Enums.parse(EntityStatus.class, String.valueOf(m.get("status")), "status");
        List<TrustAnchor> out = new ArrayList<>();
        for (int i = 0; i < certs.size(); i++) {
            String id = Json.string(m, "id");
            out.add(new TrustAnchor(id == null ? null : certs.size() == 1 ? id : id + "-" + i, TrustDomain.of(domain),
                    certs.get(i), framework, Json.string(m, "entity"), status, Json.object(m.get("constraints")), provenance));
        }
        return out;
    }

    /**
     * An entry belongs to the framework of the source that lists it. A document cannot place an entry in another
     * one: whoever writes a list for one framework would otherwise decide what the clients of any framework trust.
     */
    private static String framework(Map<String, Object> m, String sourceFramework) {
        Object named = m.get("framework");
        if (named != null && !String.valueOf(named).equals(sourceFramework)) {
            throw new IllegalArgumentException("it names framework '" + named + "', but its source loads into "
                    + (sourceFramework == null ? "no framework" : "'" + sourceFramework + "'"));
        }
        return sourceFramework;
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
