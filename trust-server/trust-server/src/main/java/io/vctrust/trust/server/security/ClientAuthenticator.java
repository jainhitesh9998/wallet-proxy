package io.vctrust.trust.server.security;

import com.nimbusds.jwt.JWTClaimsSet;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.config.TrustProperties;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Identifies the calling client. In order:
 * <ol>
 *   <li>a bearer value shaped like a JWT, when OAuth is enabled: an access token whose client claim names a
 *       configured client; a certificate-bound token ({@code cnf.x5t#S256}) also needs that TLS client certificate;</li>
 *   <li>any other bearer value (or {@code X-API-Key}): an API key;</li>
 *   <li>no bearer value but a TLS client certificate, when mTLS is enabled: the client registered for its thumbprint;</li>
 *   <li>nothing: the anonymous profile when enabled.</li>
 * </ol>
 * The certificate comes from this server's TLS connector, or from a proxy header that is believed only when the
 * TCP peer (not any forwarded address) is a trusted proxy.
 */
public class ClientAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(ClientAuthenticator.class);
    private static final Pattern JWT_SHAPE = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    public sealed interface Result permits Authenticated, Rejected {
    }

    /** @param method {@code api_key}, {@code oauth2_jwt}, {@code mtls} or {@code anonymous} */
    public record Authenticated(ClientProfile client, String method) implements Result {
    }

    /** @param bearerError RFC 6750 error for the {@code WWW-Authenticate} header, or null */
    public record Rejected(int status, String code, String detail, String bearerError) implements Result {
    }

    private final ClientRegistry clients;
    private final TrustProperties.Auth cfg;
    private final AccessTokenVerifier tokens;
    private final List<Cidr> trustedProxies = new ArrayList<>();

    public ClientAuthenticator(ClientRegistry clients, TrustProperties.Auth cfg, AccessTokenVerifier tokens) {
        this.clients = clients;
        this.cfg = cfg;
        this.tokens = cfg.getOauth().isEnabled() ? tokens : null;
        for (String p : cfg.getMtls().getTrustedProxies()) {
            trustedProxies.add(Cidr.parse(p));
        }
    }

    public Result authenticate(HttpServletRequest request) {
        String bearer = null;
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            bearer = auth.substring(7).trim();
        } else if (request.getHeader("X-API-Key") != null) {
            bearer = request.getHeader("X-API-Key").trim();
        }
        X509Certificate cert = clientCertificate(request);
        if (bearer != null && tokens != null && JWT_SHAPE.matcher(bearer).matches()) {
            return byAccessToken(bearer, cert);
        }
        if (bearer != null) {
            if (!cfg.isApiKeys()) {
                return new Rejected(401, "unauthorized", "Unknown access token", "invalid_token");
            }
            return clients.byApiKey(bearer).<Result>map(p -> new Authenticated(p, "api_key"))
                    .orElseGet(() -> new Rejected(401, "unauthorized", "Unknown API key", null));
        }
        if (cert != null && cfg.getMtls().isEnabled()) {
            return clients.byCertificate(thumbprint(cert)).<Result>map(p -> new Authenticated(p, "mtls"))
                    .orElseGet(() -> new Rejected(401, "unauthorized", "Unknown client certificate", null));
        }
        return clients.anonymous().<Result>map(p -> new Authenticated(p, "anonymous"))
                .orElseGet(() -> new Rejected(401, "unauthorized", "Client authentication required", null));
    }

    private Result byAccessToken(String token, X509Certificate cert) {
        JWTClaimsSet claims;
        try {
            claims = tokens.verify(token);
        } catch (AccessTokenVerifier.InvalidTokenException e) {
            boolean scope = "insufficient_scope".equals(e.bearerError());
            return new Rejected(scope ? 403 : 401, scope ? "insufficient_scope" : "invalid_token", e.getMessage(), e.bearerError());
        }
        String bound = AccessTokenVerifier.certificateBinding(claims);
        if (bound != null && (cert == null || !bound.equals(thumbprint(cert)))) {
            return new Rejected(401, "invalid_token", cert == null
                    ? "Access token is bound to a client certificate, but none was presented"
                    : "Access token is bound to a different client certificate", "invalid_token");
        }
        for (String claim : cfg.getOauth().getClientIdClaims()) {
            if (claims.getClaim(claim) instanceof String id && !id.isBlank()) {
                Optional<ClientProfile> p = clients.byOauthClientId(id);
                if (p.isPresent()) {
                    return new Authenticated(p.get(), "oauth2_jwt");
                }
                log.debug("Access token for unregistered client {}", id);
                return new Rejected(401, "invalid_token", "Access token client " + id + " is not a registered client", "invalid_token");
            }
        }
        return new Rejected(401, "invalid_token", "Access token names no client (" + String.join(", ", cfg.getOauth().getClientIdClaims()) + ")",
                "invalid_token");
    }

    /** The client certificate from the TLS connector, or from the proxy header when the peer is a trusted proxy. */
    X509Certificate clientCertificate(HttpServletRequest request) {
        if (request.getAttribute(CERT_ATTRIBUTE) instanceof X509Certificate[] chain && chain.length > 0) {
            return chain[0];
        }
        String header = cfg.getMtls().getCertificateHeader();
        if (header == null || header.isBlank()) {
            return null;
        }
        String value = request.getHeader(header);
        if (value == null || value.isBlank()) {
            return null;
        }
        String peer = peerAddress(request);
        if (trustedProxies.stream().noneMatch(c -> c.contains(peer))) {
            log.debug("Ignoring {} from untrusted peer {}", header, peer);
            return null;
        }
        try {
            return parseCertificate(value);
        } catch (CertificateException | IllegalArgumentException e) {
            log.warn("Unreadable client certificate in {}: {}", header, e.getMessage());
            return null;
        }
    }

    /** The TCP peer: unwraps request wrappers such as the forwarded-header filter, which substitute a spoofable address. */
    static String peerAddress(HttpServletRequest request) {
        ServletRequest r = request;
        while (r instanceof ServletRequestWrapper w) {
            r = w.getRequest();
        }
        return r.getRemoteAddr();
    }

    /** URL-encoded PEM (a literal '+' kept), plain PEM, or base64 DER. */
    static X509Certificate parseCertificate(String value) throws CertificateException {
        String pem = URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
        String b64 = pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getMimeDecoder().decode(b64);
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    static String thumbprint(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(Hashes.sha256(cert.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An address block such as {@code 10.0.0.0/8}, {@code fd00::/8} or a single address. */
    record Cidr(byte[] network, int bits) {
        static Cidr parse(String s) {
            String[] parts = s.trim().split("/");
            try {
                if (parts.length > 2 || !parts[0].matches("[0-9A-Fa-f:.]+")) {
                    throw new NumberFormatException(); // IP literals only: no DNS lookups for configuration
                }
                byte[] addr = InetAddress.getByName(parts[0]).getAddress();
                int bits = parts.length > 1 ? Integer.parseInt(parts[1]) : addr.length * 8;
                if (bits < 0 || bits > addr.length * 8) {
                    throw new NumberFormatException();
                }
                return new Cidr(addr, bits);
            } catch (UnknownHostException | NumberFormatException e) {
                throw new IllegalArgumentException("trust.auth.mtls.trusted-proxies: invalid address or CIDR " + s);
            }
        }

        boolean contains(String address) {
            byte[] a;
            if (address == null || !address.matches("[0-9A-Fa-f:.]+")) {
                return false;
            }
            try {
                a = InetAddress.getByName(address).getAddress();
            } catch (UnknownHostException e) {
                return false;
            }
            if (a.length != network.length) {
                return false;
            }
            for (int i = 0; i < bits; i++) {
                int mask = 0x80 >> (i % 8);
                if ((a[i / 8] & mask) != (network[i / 8] & mask)) {
                    return false;
                }
            }
            return true;
        }
    }
}
