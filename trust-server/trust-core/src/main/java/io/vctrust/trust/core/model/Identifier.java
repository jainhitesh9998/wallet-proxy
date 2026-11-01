package io.vctrust.trust.core.model;

import java.net.IDN;
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
     * Normalizes a URL identifier as the client's WHATWG URL parser does, so both sides index the same key: lower-case
     * scheme and host (IDN hosts in punycode), no default port, dot segments resolved, one trailing slash stripped, no
     * fragment and no empty query. Path case is preserved (paths are case sensitive). Invalid URLs are returned as-is.
     */
    public static String normalizeUrl(String value) {
        try {
            URI uri = URI.create(value);
            if (uri.getScheme() == null) {
                return value;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost();
            int port = uri.getPort();
            if (host == null && uri.getRawAuthority() != null) {
                // A non-ASCII host leaves java.net.URI with a registry-based authority: split it here.
                String authority = uri.getRawAuthority();
                authority = authority.substring(authority.lastIndexOf('@') + 1);
                int colon = authority.lastIndexOf(':');
                if (colon > 0 && authority.indexOf(']') < colon) {
                    port = Integer.parseInt(authority.substring(colon + 1));
                    authority = authority.substring(0, colon);
                }
                host = authority;
            }
            if (host == null) {
                return value;
            }
            host = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
            if (("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80)) {
                port = -1;
            }
            String path = removeDotSegments(uri.getRawPath() == null ? "" : uri.getRawPath());
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            StringBuilder sb = new StringBuilder().append(scheme).append("://").append(host);
            if (port != -1) {
                sb.append(':').append(port);
            }
            sb.append(path);
            if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) {
                sb.append('?').append(uri.getRawQuery());
            }
            return sb.toString();
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    /** RFC 3986 §5.2.4, as the WHATWG parser applies it: empty segments ("//") are kept, unlike URI.normalize(). */
    static String removeDotSegments(String path) {
        StringBuilder in = new StringBuilder(path);
        StringBuilder out = new StringBuilder();
        while (!in.isEmpty()) {
            String s = in.toString();
            if (s.startsWith("../")) {
                in.delete(0, 3);
            } else if (s.startsWith("./")) {
                in.delete(0, 2);
            } else if (s.startsWith("/./")) {
                in.delete(0, 2);
            } else if (s.equals("/.")) {
                in.replace(0, 2, "/");
            } else if (s.startsWith("/../") || s.equals("/..")) {
                in.replace(0, s.equals("/..") ? 3 : 4, "/");
                int slash = out.lastIndexOf("/");
                out.setLength(Math.max(slash, 0));
            } else if (s.equals(".") || s.equals("..")) {
                in.setLength(0);
            } else {
                int next = s.indexOf('/', s.startsWith("/") ? 1 : 0);
                int end = next < 0 ? s.length() : next;
                out.append(s, 0, end);
                in.delete(0, end);
            }
        }
        return out.toString();
    }

    @Override
    public String toString() {
        return type + ":" + value;
    }
}
