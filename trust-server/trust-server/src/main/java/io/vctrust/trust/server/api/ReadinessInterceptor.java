package io.vctrust.trust.server.api;

import io.vctrust.trust.server.service.RegistryReadiness;
import io.vctrust.trust.server.service.ServiceException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Refuses API calls until the registry may be served (see {@link RegistryReadiness}). Clients treat 503 as
 * "service unavailable" and keep what they have.
 */
public class ReadinessInterceptor implements HandlerInterceptor {

    private final RegistryReadiness readiness;

    public ReadinessInterceptor(RegistryReadiness readiness) {
        this.readiness = readiness;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            readiness.requireReady();
        } catch (ServiceException e) {
            response.setHeader("Retry-After", "5");
            throw e;
        }
        return true;
    }
}
