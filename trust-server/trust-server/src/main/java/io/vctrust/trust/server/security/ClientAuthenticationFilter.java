package io.vctrust.trust.server.security;

import io.vctrust.trust.core.policy.ClientProfile;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Resolves the calling client from {@code Authorization: Bearer <api key>} or {@code X-API-Key}. Requests
 * without a key get the anonymous profile when enabled. {@code /admin/**} requires an admin client.
 */
public class ClientAuthenticationFilter extends OncePerRequestFilter {

    public static final String ATTRIBUTE = "trust.client";

    private final ClientRegistry clients;

    public ClientAuthenticationFilter(ClientRegistry clients) {
        this.clients = clients;
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
        String key = null;
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            key = auth.substring(7).trim();
        } else if (request.getHeader("X-API-Key") != null) {
            key = request.getHeader("X-API-Key").trim();
        }
        Optional<ClientProfile> profile = key == null ? clients.anonymous() : clients.byApiKey(key);
        if (profile.isEmpty()) {
            problem(response, 401, "unauthorized", key == null ? "Client authentication required" : "Unknown API key");
            return;
        }
        if (request.getRequestURI().startsWith("/admin/") && !profile.get().admin()) {
            problem(response, 403, "forbidden", "Admin client required");
            return;
        }
        request.setAttribute(ATTRIBUTE, profile.get());
        chain.doFilter(request, response);
    }

    private static void problem(HttpServletResponse response, int status, String code, String detail) throws IOException {
        response.setStatus(status);
        response.setContentType("application/problem+json");
        if (status == 401) {
            response.setHeader("WWW-Authenticate", "Bearer realm=\"vc-trust-service\"");
        }
        response.getWriter().write("{\"type\":\"https://vctrust.io/problems/" + code + "\",\"title\":\"" + code
                + "\",\"status\":" + status + ",\"detail\":\"" + detail + "\",\"code\":\"" + code + "\"}");
    }
}
