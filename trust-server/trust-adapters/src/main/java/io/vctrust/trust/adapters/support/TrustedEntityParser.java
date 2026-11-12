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
import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.util.Enums;
import io.vctrust.trust.core.x509.Certificates;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Parses the service's native entity / anchor document format (used by the static source and the admin API).
 * Shape: {@code {entities: [...], anchors: [...]}}; see {@code docs/configuration.md}. Entries take the framework
 * of their source; a {@code framework} key is accepted only when it names that same framework.
 *
 * <p>An entry that cannot be read is refused with an exception that says what is wrong with it, never read in part:
 * an entity entry is what restricts a party whose CA is trusted, and one left out (or read without its status) lets
 * that party be trusted through the CA. The sources that use this parser fail to load on such an entry, naming it
 * ({@link #name}), and keep their last good content.
 *
 * <p>The format is read strictly. An entry holds only the members the format documents ({@link #ENTITY_MEMBERS},
 * {@link #ANCHOR_MEMBERS}), each of its type, and so do the objects in it that are read member by member (an
 * identifier, a display entry, an authorization, a context). A member nobody reads (a misspelt {@code staus: REVOKED})
 * or one of the wrong shape (a {@code docTypes} that is not a list) would otherwise be read as absent: the entity
 * active, the anchor unconstrained. A member written without a value ({@code status:}) is refused for the same
 * reason. What is free-form stays so: {@code metadata}, {@code metadataPolicy}, {@code attributes}, an anchor's
 * {@code constraints} and an authorization's {@code constraints} may hold any member, though the members of
 * {@code constraints} that the service reads ({@code docTypes}, {@code crlUrls}, {@code crl}) must have their type,
 * and a name that is one of them written another way ({@code doctypes}, {@code crl_urls}) is refused.
 */
public final class TrustedEntityParser {

    /** The members of a registry document. */
    public static final List<String> REGISTRY_MEMBERS = List.of("entities", "anchors");
    /** The members of an entity entry: those this parser reads, which are those "Registry format" documents. */
    public static final List<String> ENTITY_MEMBERS = List.of("id", "framework", "roles", "name", "display", "identifiers",
            "certificates", "certificate", "certificateLocation", "certificateJsonField", "authorizations", "contexts", "status",
            "validFrom", "validUntil", "metadata", "metadataPolicy", "attributes");
    /** The members of an anchor entry. */
    public static final List<String> ANCHOR_MEMBERS = List.of("id", "framework", "domain", "entity", "certificate", "certificates",
            "certificateLocation", "certificateJsonField", "status", "constraints");
    static final List<String> IDENTIFIER_MEMBERS = List.of("type", "value");
    static final List<String> DISPLAY_MEMBERS = List.of("locale", "name", "description", "logoUri");
    static final List<String> AUTHORIZATION_MEMBERS = List.of("format", "type", "constraints");
    static final List<String> CONTEXT_MEMBERS = List.of("url", "sha256");

    private static final String CERTIFICATE = "a certificate (PEM or base64 DER)";
    /**
     * The members of an anchor's constraints the service reads, by their name in lower case without '-' and '_': a
     * member whose name reads so but is not written exactly so is a near miss, and cannot be read.
     */
    private static final Map<String, String> READ_CONSTRAINTS = Map.of("doctypes", "docTypes", "crlurls", "crlUrls", "crl", "crl");

    private TrustedEntityParser() {
    }

    /** The two lists of a registry document. */
    public record Lists(List<Object> entities, List<Object> anchors) {
    }

    /**
     * The lists of a registry document. A member other than {@code entities} and {@code anchors} makes it unreadable:
     * the entries under a misspelt list would not be loaded at all.
     */
    public static Lists registry(Map<String, Object> doc) {
        Members r = new Members(doc, "a registry", REGISTRY_MEMBERS, null);
        List<Object> entities = r.list("entities", "a list");
        List<Object> anchors = r.list("anchors", "a list");
        return new Lists(entities == null ? List.of() : entities, anchors == null ? List.of() : anchors);
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

    public static TrustedEntity entity(Map<String, Object> m, String sourceFramework, Provenance provenance,
                                       ResourceLoader loader) throws IOException {
        Members e = new Members(m, "an entity", ENTITY_MEMBERS, null);
        String id = e.text("id", "text");
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("it has no id");
        }
        TrustedEntity.Builder b = TrustedEntity.builder(id).framework(framework(e, sourceFramework)).provenance(provenance);
        for (String r : roles(e)) {
            b.role(Enums.parse(EntityRole.class, r, "role"));
        }
        List<Object> ids = e.list("identifiers", "a list");
        for (int i = 0; ids != null && i < ids.size(); i++) {
            b.identifier(identifier(ids.get(i), "identifiers[" + i + "]"));
        }
        display(e, b);
        List<Object> as = e.list("authorizations", "a list");
        for (int i = 0; as != null && i < as.size(); i++) {
            Members a = new Members(as.get(i), "an authorization", AUTHORIZATION_MEMBERS, "authorizations[" + i + "]");
            b.authorization(new CredentialAuthorization(CredentialFormats.canonical(a.text("format", "text")), a.text("type", "text"),
                    a.freeForm("constraints")));
        }
        b.status(status(e));
        b.validFrom(e.date("validFrom"));
        b.validUntil(e.date("validUntil"));
        for (X509Certificate c : certificates(e, loader)) {
            b.certificate(c);
        }
        objects(e, "metadata").forEach(b::metadata);
        objects(e, "metadataPolicy").forEach(b::metadataPolicy);
        Map<String, Object> attributes = e.freeForm("attributes");
        if (attributes != null) {
            attributes.forEach(b::attribute);
        }
        contexts(e, b);
        return b.build();
    }

    public static List<TrustAnchor> anchors(Map<String, Object> m, String sourceFramework, Provenance provenance,
                                            ResourceLoader loader) throws IOException {
        Members a = new Members(m, "an anchor", ANCHOR_MEMBERS, null);
        String domain = a.text("domain", "text");
        if (domain == null) {
            throw new IllegalArgumentException("it has no domain");
        }
        String id = a.text("id", "text");
        String entity = a.text("entity", "text");
        Map<String, Object> constraints = constraints(a);
        List<X509Certificate> certs = certificates(a, loader);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("it has no certificate");
        }
        String framework = framework(a, sourceFramework);
        EntityStatus status = status(a);
        List<TrustAnchor> out = new ArrayList<>();
        for (int i = 0; i < certs.size(); i++) {
            out.add(new TrustAnchor(id == null ? null : certs.size() == 1 ? id : id + "-" + i, TrustDomain.of(domain),
                    certs.get(i), framework, entity, status, constraints, provenance));
        }
        return out;
    }

    /**
     * An entry belongs to the framework of the source that lists it. A document cannot place an entry in another
     * one: whoever writes a list for one framework would otherwise decide what the clients of any framework trust.
     */
    private static String framework(Members e, String sourceFramework) {
        String named = e.text("framework", "text");
        if (named != null && !named.equals(sourceFramework)) {
            throw new IllegalArgumentException("it names framework '" + shown(named) + "', but its source loads into "
                    + (sourceFramework == null ? "no framework" : "'" + sourceFramework + "'"));
        }
        return sourceFramework;
    }

    /** {@code roles}: a list of role names, or one name. */
    private static List<String> roles(Members e) {
        Object v = e.m.get("roles");
        if (v == null) {
            return List.of();
        }
        if (v instanceof String s) {
            return List.of(s);
        }
        if (!(v instanceof List<?> l)) {
            throw e.fail("'roles' must be a list of role names or one role name, not " + kind(v));
        }
        List<String> out = new ArrayList<>();
        for (int i = 0; i < l.size(); i++) {
            if (!(l.get(i) instanceof String s)) {
                throw e.fail("'roles[" + i + "]' must be a role name, not " + kind(l.get(i)));
            }
            out.add(s);
        }
        return out;
    }

    private static EntityStatus status(Members e) {
        String status = e.text("status", "one of the statuses");
        return status == null ? EntityStatus.ACTIVE : Enums.parse(EntityStatus.class, status, "status");
    }

    /** An item of {@code identifiers}: a bare DID, URL or client identifier, or {@code {type, value}}. */
    private static Identifier identifier(Object o, String path) {
        if (o instanceof String s) {
            return guess(s);
        }
        if (!(o instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("'" + path + "' must be text or an object with type and value, not " + kind(o));
        }
        Members i = new Members(o, "an identifier", IDENTIFIER_MEMBERS, path);
        String type = i.required("type");
        String value = i.required("value");
        IdentifierType t = i.parse(IdentifierType.class, type, "identifier type");
        // A hash or key identifier written in a form the evaluators do not compute binds nothing: a REVOKED entry
        // written so would never apply. Identifier reads a SHA-256 written any common way; the other two have one form.
        switch (t) {
            case X509_SHA256 -> {
                if (Identifier.sha256Digest(value) == null) {
                    throw i.fail("'value' is not a SHA-256 digest (32 bytes in hexadecimal, with ':' between all the bytes or none, "
                            + "or in base64 or base64url): '" + shown(value) + "'");
                }
            }
            case X509_SKI -> {
                if (!unpaddedBase64Url(value)) {
                    throw i.fail("'value' is not a subject key identifier in unpadded base64url (the form the evaluators compute): '"
                            + shown(value) + "'");
                }
            }
            case JWK_THUMBPRINT -> {
                if (value.length() != 43 || !unpaddedBase64Url(value)) {
                    throw i.fail("'value' is not a JWK thumbprint (an RFC 7638 SHA-256 thumbprint in unpadded base64url, 43 characters): '"
                            + shown(value) + "'");
                }
            }
            default -> {
                // compared as Identifier compares them
            }
        }
        return new Identifier(t, value);
    }

    /**
     * Whether a value is bytes in unpadded base64url exactly as an encoder writes them: no padding, no other alphabet,
     * no separators, and no bits set past the last byte. Hexadecimal without separators is also base64url, and cannot be
     * told from it.
     */
    static boolean unpaddedBase64Url(String value) {
        if (value.isEmpty() || !value.chars().allMatch(c -> c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')) {
            return false;
        }
        try {
            return Base64Url.encode(Base64.getUrlDecoder().decode(value)).equals(value);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** {@code name} (the English name) or {@code display}, not both: the parser would read only one of them. */
    private static void display(Members e, TrustedEntity.Builder b) {
        String name = e.text("name", "text");
        List<Object> ds = e.list("display", "a list");
        if (name != null && ds != null) {
            throw e.fail("it has both 'name' and 'display'; write the name in 'display' instead");
        }
        if (name != null) {
            b.display(LocalizedDisplay.of("en", name));
        }
        for (int i = 0; ds != null && i < ds.size(); i++) {
            Members d = new Members(ds.get(i), "a display entry", DISPLAY_MEMBERS, "display[" + i + "]");
            b.display(new LocalizedDisplay(d.text("locale", "text"), d.text("name", "text"), d.text("description", "text"),
                    d.text("logoUri", "text")));
        }
    }

    /** contexts: the JSON-LD contexts this party's credentials use, as a URL or {url, sha256} (a pinned digest). */
    private static void contexts(Members e, TrustedEntity.Builder b) {
        List<Object> contexts = e.list("contexts", "a list");
        if (contexts == null) {
            return;
        }
        List<String> urls = new ArrayList<>();
        Map<String, String> pins = new LinkedHashMap<>();
        for (int i = 0; i < contexts.size(); i++) {
            Object c = contexts.get(i);
            String path = "contexts[" + i + "]";
            if (c instanceof String url) {
                urls.add(url);
                continue;
            }
            if (!(c instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("'" + path + "' must be a URL or an object with url and sha256, not " + kind(c));
            }
            Members cm = new Members(c, "a context", CONTEXT_MEMBERS, path);
            String url = cm.required("url");
            urls.add(url);
            String sha256 = cm.text("sha256", "text");
            if (sha256 != null) {
                pins.put(url, sha256);
            }
        }
        b.attribute(Oid4vciMetadataMapper.CONTEXTS, urls);
        if (!pins.isEmpty()) {
            b.attribute(Oid4vciMetadataMapper.CONTEXT_DIGESTS, pins);
        }
    }

    /** {@code metadata} and {@code metadataPolicy}: keyed by entity type, each an object (free-form). */
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> objects(Members e, String key) {
        Map<String, Object> m = e.freeForm(key);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        if (m != null) {
            m.forEach((type, v) -> {
                if (!(v instanceof Map<?, ?> o)) {
                    throw e.fail("'" + key + "." + shown(type) + "' must be an object, not " + kind(v));
                }
                out.put(type, (Map<String, Object>) o);
            });
        }
        return out;
    }

    /**
     * An anchor's {@code constraints}: free-form, but what the service reads from it must have its type, or it would
     * be read as absent: {@code docTypes} (a list of doctypes; anything else left the anchor valid for every doctype),
     * {@code crlUrls} (a URL or a list of them) and {@code crl} (text).
     */
    private static Map<String, Object> constraints(Members a) {
        Map<String, Object> c = a.freeForm("constraints");
        if (c == null) {
            return null;
        }
        // Any other name is free, but one that is a member the service reads written another way ("doctypes",
        // "crl_urls", "CRL") would be read as absent: the IACA valid for every doctype, the CRL location not used.
        for (String name : c.keySet()) {
            String read = READ_CONSTRAINTS.get(name.toLowerCase(Locale.ROOT).replace("-", "").replace("_", ""));
            if (read != null && !read.equals(name)) {
                throw a.fail("'constraints." + shown(name) + "' is written another way than '" + read + "', the name the service reads");
            }
        }
        if (c.containsKey("docTypes")) {
            if (!(c.get("docTypes") instanceof List<?> l)) {
                throw a.fail("'constraints.docTypes' must be a list of doctypes, not " + kind(c.get("docTypes")));
            }
            texts(a, l, "constraints.docTypes", "a doctype");
        }
        Object crlUrls = c.get("crlUrls");
        if (crlUrls != null && !(crlUrls instanceof String)) {
            if (!(crlUrls instanceof List<?> l)) {
                throw a.fail("'constraints.crlUrls' must be a URL or a list of URLs, not " + kind(crlUrls));
            }
            texts(a, l, "constraints.crlUrls", "a URL");
        }
        Object crl = c.get("crl");
        if (crl != null && !(crl instanceof String)) {
            throw a.fail("'constraints.crl' must be a CRL (PEM or base64 DER), not " + kind(crl));
        }
        return c;
    }

    private static void texts(Members e, List<?> l, String path, String what) {
        for (int i = 0; i < l.size(); i++) {
            if (!(l.get(i) instanceof String)) {
                throw e.fail("'" + path + "[" + i + "]' must be " + what + ", not " + kind(l.get(i)));
            }
        }
    }

    /**
     * The certificates of an entry: {@code certificate} (one, as text), {@code certificates} (a list of them), and what
     * {@code certificateLocation} holds (a PEM bundle, DER, or with {@code certificateJsonField} a member of a JSON
     * document). Text that holds something besides certificates (a key, a damaged PEM block) is not a certificate.
     */
    private static List<X509Certificate> certificates(Members e, ResourceLoader loader) throws IOException {
        List<X509Certificate> out = new ArrayList<>();
        String one = e.text("certificate", CERTIFICATE);
        if (one != null) {
            out.addAll(certificateText(one, "certificate"));
        }
        List<Object> many = e.list("certificates", "a list of certificates");
        for (int i = 0; many != null && i < many.size(); i++) {
            String path = "certificates[" + i + "]";
            if (!(many.get(i) instanceof String s)) {
                throw e.fail("'" + path + "' must be " + CERTIFICATE + ", not " + kind(many.get(i)));
            }
            out.addAll(certificateText(s, path));
        }
        String location = e.text("certificateLocation", "text");
        String field = e.text("certificateJsonField", "text");
        if (field != null && location == null) {
            throw e.fail("'certificateJsonField' is read only with 'certificateLocation'");
        }
        if (location != null) {
            byte[] data = loader.load(location);
            if (field == null) {
                out.addAll(certificatesIn(data, "certificateLocation"));
            } else {
                Object v = Json.parseObject(data).get(field);
                if (v == null) {
                    throw new IOException("Field '" + shown(field) + "' not found in " + location);
                }
                if (!(v instanceof String s)) {
                    throw e.fail("'certificateLocation' field '" + shown(field) + "' must be " + CERTIFICATE + ", not " + kind(v));
                }
                out.addAll(certificateText(s, "certificateLocation"));
            }
        }
        return out;
    }

    private static List<X509Certificate> certificateText(String text, String path) {
        String t = text.trim();
        if (t.contains("-----BEGIN")) {
            return certificatesIn(t.getBytes(StandardCharsets.US_ASCII), path);
        }
        try {
            return List.of(Certificates.fromBase64(t.replaceAll("\\s", "")));
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("'" + path + "' is not a certificate: " + ex.getMessage());
        }
    }

    /** The certificates of a PEM bundle, DER or base64; every PEM block in it must be a certificate. */
    private static List<X509Certificate> certificatesIn(byte[] data, String path) {
        List<X509Certificate> certs;
        try {
            certs = Certificates.fromPemBundle(data);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("'" + path + "' is not a certificate: " + ex.getMessage());
        }
        String text = new String(data, StandardCharsets.US_ASCII);
        int blocks = text.split("-----BEGIN ", -1).length - 1;
        if (certs.isEmpty() || (blocks > 0 && blocks != certs.size())) {
            throw new IllegalArgumentException("'" + path + "' holds something that is not a certificate");
        }
        return certs;
    }

    /** What a value is, as an error says it: {@code text}, {@code a number}, {@code a list}, ... */
    static String kind(Object v) {
        if (v == null) {
            return "nothing";
        }
        if (v instanceof String) {
            return "text";
        }
        if (v instanceof Number) {
            return "a number";
        }
        if (v instanceof Boolean) {
            return "true or false";
        }
        if (v instanceof List<?>) {
            return "a list";
        }
        if (v instanceof Map<?, ?>) {
            return "an object";
        }
        return v.getClass().getSimpleName();
    }

    /**
     * An object of a document, read member by member: it holds only the members {@code allowed}, each with a value.
     * Errors about it start with its place ({@code identifiers[0]: }) when it is inside an entry.
     */
    private static final class Members {
        final Map<String, Object> m;
        private final String at;

        @SuppressWarnings("unchecked")
        Members(Object o, String what, List<String> allowed, String path) {
            if (!(o instanceof Map<?, ?> map)) {
                throw new IllegalArgumentException(path == null ? "it is not an object" : "'" + path + "' must be an object, not " + kind(o));
            }
            this.m = (Map<String, Object>) map;
            this.at = path == null ? "" : path + ": ";
            List<String> unknown = m.keySet().stream().filter(k -> !allowed.contains(k)).toList();
            if (!unknown.isEmpty()) {
                throw fail((unknown.size() == 1 ? "unknown member " : "unknown members ")
                        + unknown.stream().map(k -> "'" + shown(k) + "'").collect(Collectors.joining(", "))
                        + "; " + what + " has " + String.join(", ", allowed));
            }
            m.forEach((k, v) -> {
                if (v == null) {
                    throw fail("'" + k + "' has no value");
                }
            });
        }

        IllegalArgumentException fail(String message) {
            return new IllegalArgumentException(at + message);
        }

        /** A member that is text, null when absent. */
        String text(String key, String what) {
            Object v = m.get(key);
            if (v != null && !(v instanceof String)) {
                throw fail("'" + key + "' must be " + what + ", not " + kind(v));
            }
            return (String) v;
        }

        String required(String key) {
            String v = text(key, "text");
            if (v == null) {
                throw fail("'" + key + "' is missing");
            }
            return v;
        }

        @SuppressWarnings("unchecked")
        List<Object> list(String key, String what) {
            Object v = m.get(key);
            if (v != null && !(v instanceof List<?>)) {
                throw fail("'" + key + "' must be " + what + ", not " + kind(v));
            }
            return (List<Object>) v;
        }

        /** A free-form object: any member, each with a value (none would be read). */
        @SuppressWarnings("unchecked")
        Map<String, Object> freeForm(String key) {
            Object v = m.get(key);
            if (v == null) {
                return null;
            }
            if (!(v instanceof Map<?, ?> o)) {
                throw fail("'" + key + "' must be an object, not " + kind(v));
            }
            o.forEach((k, x) -> {
                if (x == null) {
                    throw fail("'" + key + "." + shown(String.valueOf(k)) + "' has no value");
                }
            });
            return (Map<String, Object>) o;
        }

        /** A date: {@code 2027-12-31} (midnight UTC) or an RFC 3339 instant, as text. */
        Instant date(String key) {
            Object v = m.get(key);
            if (v == null) {
                return null;
            }
            if (!(v instanceof String s)) {
                throw fail("'" + key + "' must be a date, not " + kind(v));
            }
            try {
                return AdapterSupport.instant(s);
            } catch (DateTimeException ex) {
                throw fail("'" + key + "' is not a date: '" + shown(s) + "' (write 2027-12-31 or 2027-12-31T00:00:00Z)");
            }
        }

        <E extends Enum<E>> E parse(Class<E> type, String value, String what) {
            try {
                return Enums.parse(type, value, what);
            } catch (IllegalArgumentException ex) {
                throw fail(ex.getMessage());
            }
        }
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
