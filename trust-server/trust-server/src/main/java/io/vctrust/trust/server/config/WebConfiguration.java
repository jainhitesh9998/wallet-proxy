package io.vctrust.trust.server.config;

import io.vctrust.trust.server.api.ReadinessInterceptor;
import io.vctrust.trust.server.security.AccessTokenVerifier;
import io.vctrust.trust.server.security.ClientAuthenticationFilter;
import io.vctrust.trust.server.security.ClientAuthenticator;
import io.vctrust.trust.server.security.ClientProfileArgumentResolver;
import io.vctrust.trust.server.security.ClientRegistry;
import io.vctrust.trust.server.security.RateLimiter;
import io.vctrust.trust.server.security.RequestSizeFilter;
import io.vctrust.trust.server.service.RegistryReadiness;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebConfiguration implements WebMvcConfigurer {

    private final TrustProperties props;
    private final RegistryReadiness readiness;

    public WebConfiguration(TrustProperties props, RegistryReadiness readiness) {
        this.props = props;
        this.readiness = readiness;
    }

    @Bean
    ClientAuthenticator clientAuthenticator(ClientRegistry clients) {
        TrustProperties.Auth auth = props.getAuth();
        AccessTokenVerifier tokens = auth.getOauth().isEnabled()
                ? new AccessTokenVerifier(auth.getOauth(), props.getService().getIssuer()) : null;
        return new ClientAuthenticator(clients, auth, tokens);
    }

    @Bean
    FilterRegistrationBean<ClientAuthenticationFilter> clientAuthenticationFilter(ClientAuthenticator authenticator, ClientRegistry clients) {
        TrustProperties.RateLimit limit = props.getAuth().getRateLimit();
        RateLimiter limiter = limit.isEnabled() ? new RateLimiter(limit.getRequestsPerMinute(), limit.getBurst()) : null;
        // Refused credentials: a tenth of the burst at once, then the configured rate.
        RateLimiter refused = limit.isEnabled() && limit.getRefusedPerMinute() > 0
                ? new RateLimiter(limit.getRefusedPerMinute(), Math.max(5, limit.getBurst() / 10)) : null;
        FilterRegistrationBean<ClientAuthenticationFilter> reg = new FilterRegistrationBean<>(
                new ClientAuthenticationFilter(authenticator, clients, limiter, refused,
                        limit.isEnabled() ? limit.getMaxConcurrent() : 0, limit.isExemptAdmin()));
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return reg;
    }

    /** Runs before authentication: an oversized body is refused whoever sends it. */
    @Bean
    FilterRegistrationBean<RequestSizeFilter> requestSizeFilter() {
        FilterRegistrationBean<RequestSizeFilter> reg = new FilterRegistrationBean<>(new RequestSizeFilter(props.getService().getMaxRequestBytes()));
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 5);
        return reg;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new ClientProfileArgumentResolver());
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String[] origins = props.getCorsOrigins().toArray(String[]::new);
        for (String path : List.of("/api/**", "/.well-known/**")) {
            registry.addMapping(path).allowedOriginPatterns(origins).allowedMethods("GET", "POST", "OPTIONS")
                    .allowedHeaders("*").exposedHeaders("ETag", "Cache-Control", "X-Trust-Decision", "X-Trust-Source", "Retry-After", "WWW-Authenticate").maxAge(3600);
        }
    }

    /** Nothing derived from the registry is served before the registry is complete. */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new ReadinessInterceptor(readiness)).addPathPatterns("/api/**");
    }
}
