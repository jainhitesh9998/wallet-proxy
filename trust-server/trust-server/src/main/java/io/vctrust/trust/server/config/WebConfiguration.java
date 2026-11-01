package io.vctrust.trust.server.config;

import io.vctrust.trust.server.security.ClientAuthenticationFilter;
import io.vctrust.trust.server.security.ClientProfileArgumentResolver;
import io.vctrust.trust.server.security.ClientRegistry;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebConfiguration implements WebMvcConfigurer {

    private final TrustProperties props;

    public WebConfiguration(TrustProperties props) {
        this.props = props;
    }

    @Bean
    FilterRegistrationBean<ClientAuthenticationFilter> clientAuthenticationFilter(ClientRegistry clients) {
        FilterRegistrationBean<ClientAuthenticationFilter> reg = new FilterRegistrationBean<>(new ClientAuthenticationFilter(clients));
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return reg;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new ClientProfileArgumentResolver());
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        String[] origins = props.getCorsOrigins().toArray(String[]::new);
        for (String path : List.of("/api/**", "/.well-known/**", "/1.0/**", "/trqp/**")) {
            registry.addMapping(path).allowedOriginPatterns(origins).allowedMethods("GET", "POST", "OPTIONS")
                    .allowedHeaders("*").exposedHeaders("ETag", "Cache-Control", "X-Trust-Decision", "X-Trust-Source").maxAge(3600);
        }
    }
}
