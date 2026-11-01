package io.vctrust.trust.server.security;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.policy.ClientProfile;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves the calling client (see {@link ClientAuthenticator}): API key, OAuth access token, TLS client
 * certificate, or the anonymous profile. Every path needs a client except the public ones (discovery, the service's
 * keys, health, the API description); {@code /admin/**} and the other actuator endpoints need an admin client.
 * <p>
 * Paths are judged as Spring MVC routes them: within the application, percent-decoded, without path parameters
 * ({@link #canonicalPath}). Paths whose meaning depends on who decodes them are refused with 400, so no spelling of a
 * protected path can slip past this filter and still reach its controller.
 * <p>
 * Optionally rate-limits each client, and anonymous callers per address ({@link ClientAuthenticator#clientAddress}).
 */
public class ClientAuthenticationFilter extends OncePerRequestFilter {

    public static final String ATTRIBUTE = "trust.client";
    public static final String METHOD_ATTRIBUTE = "trust.client.auth-method";
    static final String REALM = "vc-trust-service";

    private final ClientAuthenticator authenticator;
    private final ClientRegistry clients;
    private final RateLimiter rateLimiter;
    private final boolean exemptAdmin;

    /** @param rateLimiter null to disable rate limiting */
    public ClientAuthenticationFilter(ClientAuthenticator authenticator, ClientRegistry clients, RateLimiter rateLimiter, boolean exemptAdmin) {
        this.authenticator = authenticator;
        this.clients = clients;
        this.rateLimiter = rateLimiter;
        this.exemptAdmin = exemptAdmin;
    }

    /** Served without a client. */
    static final List<String> PUBLIC_PATHS = List.of("/actuator/health", "/actuator/info", "/v3/api-docs", "/swagger-ui.html");
    static final List<String> PUBLIC_PREFIXES = List.of("/.well-known/", "/actuator/health/", "/v3/api-docs/", "/swagger-ui/");

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return "OPTIONS".equals(request.getMethod()); // CORS preflights; no controller method serves OPTIONS
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path;
        try {
            path = canonicalPath(request);
        } catch (IllegalArgumentException e) {
            problem(response, 400, "invalid_request", "Invalid request path: " + e.getMessage(), null);
            return;
        }
        if (isPublic(path)) {
            chain.doFilter(request, response);
            return;
        }
        ClientAuthenticator.Result result = authenticator.authenticate(request);
        if (result instanceof ClientAuthenticator.Rejected r) {
            problem(response, r.status(), r.code(), r.detail(), r.bearerError());
            return;
        }
        ClientAuthenticator.Authenticated a = (ClientAuthenticator.Authenticated) result;
        ClientProfile profile = a.client();
        if (needsAdmin(path) && !profile.admin()) {
            problem(response, 403, "forbidden", "Admin client required", null);
            return;
        }
        if (rateLimiter != null && !(exemptAdmin && profile.admin())) {
            boolean anonymous = "anonymous".equals(a.method());
            String key = anonymous ? "anonymous:" + authenticator.clientAddress(request) : "client:" + profile.clientId();
            Optional<Duration> wait = rateLimiter.acquire(key, anonymous ? null : clients.requestsPerMinute(profile.clientId()).orElse(null));
            if (wait.isPresent()) {
                response.setHeader("Retry-After", String.valueOf(Math.max(1, (wait.get().toMillis() + 999) / 1000)));
                problem(response, 429, "rate_limited", "Too many requests", null);
                return;
            }
        }
        request.setAttribute(ATTRIBUTE, profile);
        request.setAttribute(METHOD_ATTRIBUTE, a.method());
        chain.doFilter(request, response);
    }

    /**
     * The path within the application as Spring MVC matches it: each segment percent-decoded, path parameters
     * removed. Refuses (IllegalArgumentException) what different decoders could read differently: path parameters,
     * literal or encoded backslashes, encoded slashes and dots, dot segments, empty segments, control characters and
     * malformed escapes.
     */
    static String canonicalPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String lower = uri.toLowerCase(Locale.ROOT);
        if (uri.indexOf(';') >= 0) {
            throw new IllegalArgumentException("path parameters (;) are not accepted");
        }
        if (uri.indexOf('\\') >= 0 || lower.contains("%5c") || lower.contains("%2f") || lower.contains("%2e") || uri.contains("//")) {
            throw new IllegalArgumentException("ambiguous path");
        }
        PathContainer within = RequestPath.parse(uri, request.getContextPath()).pathWithinApplication();
        StringBuilder out = new StringBuilder();
        for (PathContainer.Element e : within.elements()) {
            if (e instanceof PathContainer.PathSegment segment) {
                String v = segment.valueToMatch();
                if (v.equals(".") || v.equals("..") || v.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                    throw new IllegalArgumentException("ambiguous path");
                }
                out.append(v);
            } else {
                out.append('/');
            }
        }
        return out.isEmpty() ? "/" : out.toString();
    }

    static boolean isPublic(String path) {
        return PUBLIC_PATHS.contains(path) || PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    /** {@code /admin/**}, and the actuator endpoints other than health and info (metrics and the like). */
    static boolean needsAdmin(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        return under(p, "/admin") || (under(p, "/actuator") && !isPublic(path));
    }

    private static boolean under(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }

    static void problem(HttpServletResponse response, int status, String code, String detail, String bearerError) throws IOException {
        response.setStatus(status);
        response.setContentType("application/problem+json");
        if (status == 401 || bearerError != null) {
            StringBuilder h = new StringBuilder("Bearer realm=\"" + REALM + "\"");
            if (bearerError != null) {
                h.append(", error=\"").append(bearerError).append("\", error_description=\"")
                        .append(detail.replaceAll("[^\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]", "'")).append('"'); // RFC 6750 §3 charset
            }
            response.setHeader("WWW-Authenticate", h.toString());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "https://vctrust.io/problems/" + code);
        body.put("title", code);
        body.put("status", status);
        body.put("detail", detail);
        body.put("code", code);
        response.getWriter().write(Json.write(body));
    }
}
