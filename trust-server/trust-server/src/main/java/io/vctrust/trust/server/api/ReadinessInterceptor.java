package io.vctrust.trust.server.api;

import io.vctrust.trust.core.registry.TrustSourceManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Refuses API calls until every required trust source has loaded. A registry that lacks a source looks, to a
 * client, like that source's parties having been delisted: a snapshot built from it would take trust away from
 * wallets that had it. Clients treat 503 as "service unavailable" and keep what they have.
 */
public class ReadinessInterceptor implements HandlerInterceptor {

    private final TrustSourceManager sources;

    public ReadinessInterceptor(TrustSourceManager sources) {
        this.sources = sources;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!sources.ready()) {
            response.setHeader("Retry-After", "5");
            throw new ApiException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, "not_ready",
                    "Trust sources are still loading: " + String.join(", ", sources.waitingFor()));
        }
        return true;
    }
}
