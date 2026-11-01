package io.vctrust.trust.core.metadata;

import java.net.URI;

/** Well-known URI construction rules used by OpenID4VCI 1.0, RFC 8414 and OpenID Connect Discovery. */
public final class WellKnown {

    public static final String CREDENTIAL_ISSUER = "openid-credential-issuer";
    public static final String OAUTH_AUTHORIZATION_SERVER = "oauth-authorization-server";
    public static final String OPENID_CONFIGURATION = "openid-configuration";
    public static final String JWT_VC_ISSUER = "jwt-vc-issuer";
    public static final String OPENID_FEDERATION = "openid-federation";

    private WellKnown() {
    }

    /**
     * RFC 8615 insertion: {@code https://host/path} becomes {@code https://host/.well-known/<suffix>/path}.
     * Used for {@code openid-credential-issuer} (OID4VCI §12.2.2), {@code oauth-authorization-server}
     * (RFC 8414 §3.1) and {@code jwt-vc-issuer}.
     */
    public static URI inserted(String identifier, String suffix) {
        URI id = URI.create(identifier);
        String path = id.getRawPath() == null ? "" : id.getRawPath();
        if (path.equals("/")) {
            path = "";
        }
        return URI.create(origin(id) + "/.well-known/" + suffix + path);
    }

    /**
     * OpenID Connect Discovery / OpenID Federation append rule:
     * {@code https://host/path} becomes {@code https://host/path/.well-known/<suffix>}.
     */
    public static URI appended(String identifier, String suffix) {
        String base = identifier.endsWith("/") ? identifier.substring(0, identifier.length() - 1) : identifier;
        return URI.create(base + "/.well-known/" + suffix);
    }

    static String origin(URI uri) {
        return uri.getScheme() + "://" + uri.getRawAuthority();
    }
}
