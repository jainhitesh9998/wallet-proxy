package io.vctrust.trust.core.model;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/**
 * A typed identifier. Values are normalized on construction so that index lookups are stable:
 * URLs lose a trailing slash and get a lower-case scheme/host, DNS names are lower-cased,
 * DIDs lose any fragment.
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
     * Normalizes an https URL identifier: lower-cases scheme and host and strips a single trailing slash.
     * Path case is preserved (paths are case sensitive). Invalid URLs are returned as-is.
     */
    public static String normalizeUrl(String value) {
        try {
            URI uri = URI.create(value);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return value;
            }
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            StringBuilder sb = new StringBuilder()
                    .append(uri.getScheme().toLowerCase(Locale.ROOT)).append("://")
                    .append(uri.getHost().toLowerCase(Locale.ROOT));
            if (uri.getPort() != -1) {
                sb.append(':').append(uri.getPort());
            }
            sb.append(path);
            if (uri.getRawQuery() != null) {
                sb.append('?').append(uri.getRawQuery());
            }
            return sb.toString();
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    @Override
    public String toString() {
        return type + ":" + value;
    }
}
