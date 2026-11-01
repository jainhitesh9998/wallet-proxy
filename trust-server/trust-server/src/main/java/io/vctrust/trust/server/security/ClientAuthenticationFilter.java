package io.vctrust.trust.server.security;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.policy.ClientProfile;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves the calling client (see {@link ClientAuthenticator}): API key, OAuth access token, TLS client
 * certificate, or the anonymous profile. {@code /admin/**} requires an admin client. Optionally rate-limits
 * each client, and anonymous callers per address.
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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String p = request.getRequestURI();
        return !(p.startsWith("/api/") || p.startsWith("/admin/") || p.startsWith("/trqp/") || p.startsWith("/1.0/"))
                || "OPTIONS".equals(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        ClientAuthenticator.Result result = authenticator.authenticate(request);
        if (result instanceof ClientAuthenticator.Rejected r) {
            problem(response, r.status(), r.code(), r.detail(), r.bearerError());
            return;
        }
        ClientAuthenticator.Authenticated a = (ClientAuthenticator.Authenticated) result;
        ClientProfile profile = a.client();
        if (request.getRequestURI().startsWith("/admin/") && !profile.admin()) {
            problem(response, 403, "forbidden", "Admin client required", null);
            return;
        }
        if (rateLimiter != null && !(exemptAdmin && profile.admin())) {
            boolean anonymous = "anonymous".equals(a.method());
            String key = anonymous ? "anonymous:" + request.getRemoteAddr() : "client:" + profile.clientId();
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
