package io.vctrust.trust.server.config;

import io.vctrust.trust.core.did.DidJwkDriver;
import io.vctrust.trust.core.did.DidKeyDriver;
import io.vctrust.trust.core.did.DidMethodDriver;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.did.DidWebDriver;
import io.vctrust.trust.core.did.HttpRegistryDidDriver;
import io.vctrust.trust.core.did.UniversalResolverDriver;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.metadata.IssuerMetadataResolver;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceFactory;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.http.SafeHttpFetcher;
import io.vctrust.trust.server.http.TrustResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;
import io.vctrust.trust.server.managed.ManagedSourceFactory;
import io.vctrust.trust.server.security.ClientRegistry;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.SnapshotService;
import io.vctrust.trust.server.service.TrqpService;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

/** Wires the framework-free core into Spring. */
@Configuration(proxyBeanMethods = false)
public class TrustCoreConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TrustCoreConfiguration.class);

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    HttpFetcher httpFetcher(TrustProperties props) {
        return new SafeHttpFetcher(props.getHttp());
    }

    @Bean
    ResourceLoader trustResourceLoader(HttpFetcher http) {
        return new TrustResourceLoader(http);
    }

    @Bean
    SourceContext sourceContext(HttpFetcher http, ResourceLoader loader, Clock clock) {
        return new SourceContext() {
            @Override
            public HttpFetcher http() {
                return http;
            }

            @Override
            public ResourceLoader resources() {
                return loader;
            }

            @Override
            public Clock clock() {
                return clock;
            }
        };
    }

    @Bean
    TrustJacksonModule trustJacksonModule() {
        return new TrustJacksonModule();
    }

    @Bean
    TrustRegistry trustRegistry() {
        return new TrustRegistry();
    }

    @Bean
    ManagedEntityStore managedEntityStore(JdbcClient jdbc) {
        return new ManagedEntityStore(jdbc);
    }

    @Bean
    ManagedSourceFactory managedSourceFactory(ManagedEntityStore store) {
        return new ManagedSourceFactory(store);
    }

    @Bean(destroyMethod = "close")
    TrustSourceManager trustSourceManager(TrustProperties props, TrustRegistry registry, SourceContext ctx, Clock clock,
                                          List<TrustSourceFactory> beanFactories) {
        Map<String, TrustSourceFactory> factories = new LinkedHashMap<>();
        beanFactories.forEach(f -> factories.put(f.type(), f));
        ServiceLoader.load(TrustSourceFactory.class).forEach(f -> factories.putIfAbsent(f.type(), f));
        log.info("Trust source types available: {}", factories.keySet());
        List<TrustSource> sources = new ArrayList<>();
        for (TrustProperties.Source s : props.getSources()) {
            TrustSourceFactory f = factories.get(s.getType());
            if (f == null) {
                throw new IllegalArgumentException("Unknown trust source type '" + s.getType() + "' for source " + s.getId()
                        + "; available: " + factories.keySet());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> props2 = (Map<String, Object>) PropertyTrees.normalize(s.getProperties());
            sources.add(f.create(new SourceDefinition(s.getId(), s.getType(), s.getFramework(), s.getRefresh(),
                    s.isEnabled(), props2), ctx));
        }
        List<TrustFramework> frameworks = props.getFrameworks().stream()
                .map(f -> new TrustFramework(f.getId(), f.getName() == null ? f.getId() : f.getName(), f.getDescription(),
                        f.getGovernanceUri(), f.getAttributes()))
                .toList();
        return new TrustSourceManager(registry, frameworks, sources, clock);
    }

    @Bean
    DidResolver didResolver(TrustProperties props, HttpFetcher http) {
        List<DidMethodDriver> drivers = new ArrayList<>(List.of(new DidKeyDriver(), new DidJwkDriver(),
                new DidWebDriver(http, Set.copyOf(props.getHttp().getHttpAllowedHosts()))));
        props.getDid().getRegistries().forEach((method, template) -> drivers.add(new HttpRegistryDidDriver(http, method, template)));
        if (props.getDid().getUniversalResolverUrl() != null && !props.getDid().getUniversalResolverUrl().isBlank()) {
            drivers.add(new UniversalResolverDriver(http, URI.create(props.getDid().getUniversalResolverUrl()),
                    Set.copyOf(props.getDid().getUniversalResolverMethods())));
        }
        return new DidResolver(drivers);
    }

    @Bean
    DidService didService(DidResolver resolver, TrustProperties props, Clock clock) {
        return new DidService(resolver, props.getCache(), clock);
    }

    @Bean
    X509PathValidator x509PathValidator() {
        return new X509PathValidator();
    }

    @Bean
    TrustEvaluator trustEvaluator(TrustRegistry registry, TrustSourceManager manager, DidService didService,
                                  X509PathValidator validator, Clock clock, TrustProperties props) {
        // The evaluator resolves DIDs through the cached service.
        DidResolver cached = new DidResolver(List.of()) {
            @Override
            public io.vctrust.trust.core.did.DidResolutionResult resolve(String did) {
                return didService.resolve(did);
            }
        };
        return new TrustEvaluator(registry, manager, cached, validator, clock, props.getService().getDecisionTtl());
    }

    @Bean
    IssuerMetadataResolver issuerMetadataResolver(HttpFetcher http, Clock clock, TrustProperties props) {
        return new IssuerMetadataResolver(http, clock, props.getCache().getMetadataMinTtl(),
                props.getCache().getMetadataMaxTtl(), false);
    }

    @Bean
    MetadataService metadataService(IssuerMetadataResolver resolver, TrustRegistry registry, TrustEvaluator evaluator,
                                    TrustProperties props, Clock clock) {
        return new MetadataService(resolver, registry, evaluator, props.getCache(), clock);
    }

    @Bean
    ServiceKeyManager serviceKeyManager(TrustProperties props) throws Exception {
        return new ServiceKeyManager(props.getService().getSigningKeyFile(), props.getService().getIssuer());
    }

    @Bean
    SnapshotService snapshotService(TrustRegistry registry, ServiceKeyManager keys, JsonMapper mapper, TrustProperties props) {
        return new SnapshotService(registry, keys, mapper, props.getService().getSnapshotTtl());
    }

    @Bean
    TrqpService trqpService(TrustRegistry registry, TrustEvaluator evaluator, Clock clock) {
        return new TrqpService(registry, evaluator, clock);
    }

    @Bean
    ClientRegistry clientRegistry(TrustProperties props) {
        return new ClientRegistry(props);
    }
}
