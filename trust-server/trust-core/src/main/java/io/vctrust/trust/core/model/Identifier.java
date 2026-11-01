package io.vctrust.trust.core.model;

import java.util.Locale;
import java.util.Objects;

/**
 * A typed identifier. Values are normalized on construction so that index lookups are stable:
 * http(s) URLs as the WHATWG URL parser reads them (lower-case scheme and host, no default port, no trailing slash),
 * DNS names are lower-cased, DIDs lose any fragment.
 */
public record Identifier(IdentifierType type, String value) {

    public Identifier {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        value = normalize(type, value.trim());
    }

    public static Identifier of(IdentifierType type, String value) {
        return new Identifier(type, value);
    }

    public static Identifier did(String did) {
        return new Identifier(IdentifierType.DID, did);
    }

    public static Identifier url(String url) {
        return new Identifier(IdentifierType.URL, url);
    }

    /** Index key used by registries. */
    public String key() {
        return type.name() + "|" + value;
    }

    static String normalize(IdentifierType type, String value) {
        return switch (type) {
            case DID -> {
                int hash = value.indexOf('#');
                yield hash >= 0 ? value.substring(0, hash) : value;
            }
            case URL, FEDERATION_ENTITY -> normalizeUrl(value);
            case DNS -> value.toLowerCase(Locale.ROOT);
            default -> value;
        };
    }

    /**
     * The key a URL identifier is indexed by: the http(s) URL as the client's WHATWG URL parser reads it, so both sides
     * index the same key (see {@link UrlNormalizer}). Other schemes and invalid URLs are returned as they are.
     */
    public static String normalizeUrl(String value) {
        return UrlNormalizer.normalize(value);
    }

    /** The host of an http(s) URL as the client's WHATWG URL parser reads it ({@code hostname}); null for any other text. */
    public static String urlHost(String value) {
        return UrlNormalizer.hostOf(value);
    }

    @Override
    public String toString() {
        return type + ":" + value;
    }
}
