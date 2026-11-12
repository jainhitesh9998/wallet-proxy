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
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.x509.CertificateProfiles;
import io.vctrust.trust.core.x509.ValidationIssue;
import io.vctrust.trust.core.x509.PathValidationResult;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceFactory;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.http.SafeHttpFetcher;
import io.vctrust.trust.server.http.TrustResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;
import io.vctrust.trust.server.managed.ManagedSourceFactory;
import io.vctrust.trust.server.security.ClientRegistry;
import io.vctrust.trust.server.service.CrlService;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.ContextService;
import io.vctrust.trust.server.service.StatusListRelay;
import io.vctrust.trust.server.service.SnapshotService;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
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

    /**
     * All {@code trust.*} configuration. Before it is bound, every property under {@code trust.} that a configuration
     * file or an argument sets must be one it knows, list indices aside: a misspelt name stops the service here, with
     * the name and where it was written, before anything reads the configuration.
     */
    @Bean
    @ConfigurationProperties(prefix = "trust")
    TrustProperties trustProperties(Environment environment) {
        TrustPropertyNames.check(environment);
        return new TrustProperties();
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /** For what clients ask the service to fetch: issuer metadata, DID documents, CRLs, status lists, JSON-LD contexts. */
    @Bean
    @Primary
    HttpFetcher httpFetcher(TrustProperties props) {
        return new SafeHttpFetcher(props.getHttp());
    }

    /**
     * For the trust sources, under the same rules but with connections of its own: lists must still load and refresh
     * while every connection of the lookups above is occupied, by whatever clients are asking for.
     */
    @Bean
    HttpFetcher sourceHttpFetcher(TrustProperties props) {
        return new SafeHttpFetcher(props.getHttp());
    }

    @Bean
    ResourceLoader trustResourceLoader(@Qualifier("sourceHttpFetcher") HttpFetcher http) {
        return new TrustResourceLoader(http);
    }

    @Bean
    SourceContext sourceContext(@Qualifier("sourceHttpFetcher") HttpFetcher http, ResourceLoader loader, Clock clock) {
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
            if (s.getFramework() == null || s.getFramework().isBlank()) {
                // What a source loads is visible to the clients of its framework; without one, to no client at all.
                throw new IllegalArgumentException("Trust source '" + s.getId() + "' names no framework (trust.sources[].framework): "
                        + "every source loads into exactly one");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> props2 = (Map<String, Object>) PropertyTrees.normalize(s.getProperties());
            sources.add(f.create(new SourceDefinition(s.getId(), s.getType(), s.getFramework(), s.getRefresh(),
                    s.isEnabled(), s.isRequired(), props2), ctx));
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

    /**
     * The operator's trust mechanisms, read strictly: a mechanism this service does not understand exactly stops it
     * here, with a message that names the mechanism, rather than being applied in part or not at all.
     */
    @Bean
    TrustMechanisms trustMechanisms(TrustProperties props) {
        TrustMechanisms mechanisms = TrustMechanisms.fromConfiguration(props.getMechanisms().stream().map(PropertyTrees::normalize).toList());
        if (!mechanisms.isEmpty()) {
            log.info("Trust mechanisms, tried in this order: {}", mechanisms.ids());
        }
        return mechanisms;
    }

    /** CRL distribution points are mostly http; CRLs are signed, so the CRL service may fetch them over http. */
    @Bean(destroyMethod = "close")
    CrlService crlService(TrustRegistry registry, HttpFetcher http, TrustProperties props, Clock clock) {
        return new CrlService(registry, http instanceof SafeHttpFetcher safe ? safe.allowingPlainHttp() : http, props.getRevocation(),
                props.getCache().settings(false), clock);
    }

    /**
     * CRLs from the trust list and distribution points. With revocation switched off, none: every certificate's status
     * is then unknown, and says so, which a client profile or mechanism that requires a known status refuses.
     */
    @Bean
    RevocationChecker revocationChecker(CrlService crls, TrustProperties props) {
        return new RevocationChecker(props.getRevocation().isEnabled() ? crls : RevocationChecker.CrlSource.SWITCHED_OFF, "trust-service");
    }

    @Bean
    StatusListRelay statusListRelay(HttpFetcher http, TrustProperties props, Clock clock) {
        return new StatusListRelay(http, props.getRevocation(), props.getCache().settings(false), clock);
    }

    @Bean
    ContextService contextService(HttpFetcher http, TrustProperties props, Clock clock) {
        return new ContextService(http, props.getCache(), clock);
    }

    @Bean
    TrustEvaluator trustEvaluator(TrustRegistry registry, TrustSourceManager manager, DidService didService,
                                  X509PathValidator validator, Clock clock, TrustProperties props, RevocationChecker revocation,
                                  TrustMechanisms mechanisms) {
        // The evaluator resolves DIDs through the cached service.
        DidResolver cached = new DidResolver(List.of()) {
            @Override
            public io.vctrust.trust.core.did.DidResolutionResult resolve(String did) {
                return didService.resolve(did);
            }
        };
        // The same mechanisms the snapshots carry: the service's own decisions are the clients' decisions.
        return new TrustEvaluator(registry, manager, cached, validator, clock, props.getService().getDecisionTtl(),
                revocation, mechanisms);
    }

    /**
     * The metadata proxy asks issuers for signed metadata and uses it when its signer chains to a credential-issuer
     * anchor (rejected signatures fall back to JSON, flagged); clients with require-signed-issuer-metadata get only
     * verified signed metadata.
     */
    @Bean
    IssuerMetadataResolver issuerMetadataResolver(HttpFetcher http, Clock clock, TrustProperties props, TrustRegistry registry,
                                                  X509PathValidator validator) {
        IssuerMetadataResolver.SignerTrust signerTrust = chain -> {
            PathValidationResult r = validator.validate(chain, registry.snapshot().anchors(TrustDomain.CREDENTIAL_ISSUER),
                    new X509PathValidator.Options(clock.instant(), CertificateProfiles.forDomain(TrustDomain.CREDENTIAL_ISSUER), null, null));
            return r.valid() ? null : r.issues().stream().filter(ValidationIssue::isError).map(ValidationIssue::message)
                    .reduce((x, y) -> x + "; " + y).orElse("no trusted anchor");
        };
        return new IssuerMetadataResolver(http, clock, props.getCache().getMetadataMinTtl(),
                props.getCache().getMetadataMaxTtl(), true, signerTrust);
    }

    /**
     * Per client, signed metadata counts only when its signer validates as X509Controller would validate it for that client.
     * The checker is the evaluator's, also with revocation switched off: it then gives the signer an unknown status, which
     * a client that requires a known one refuses, as its devices (which always check) refuse it.
     * It consults the CRLs of the frameworks the asking client sees, as the evaluator does and as that client's snapshot
     * carries them: what another framework says about the same CA does not enter.
     */
    @Bean
    MetadataService metadataService(IssuerMetadataResolver resolver, TrustRegistry registry, TrustEvaluator evaluator,
                                    TrustProperties props, Clock clock, X509PathValidator validator, RevocationChecker revocation) {
        MetadataService.ClientSignerTrust signerTrust = (chain, client) -> {
            List<TrustAnchor> anchors = registry.snapshot().anchors(TrustDomain.CREDENTIAL_ISSUER).stream()
                    .filter(a -> client.accepts(a.frameworkId())).toList();
            PathValidationResult r = validator.validate(chain, anchors, new X509PathValidator.Options(clock.instant(),
                    CertificateProfiles.forDomain(TrustDomain.CREDENTIAL_ISSUER), null, null)
                    .withRevocation(revocation.forFrameworks(client::accepts), client.requireRevocationStatus()));
            return r.valid() ? null : r.issues().stream().filter(ValidationIssue::isError).map(ValidationIssue::message)
                    .reduce((x, y) -> x + "; " + y).orElse("no trusted anchor");
        };
        return new MetadataService(resolver, registry, evaluator, props.getCache(), clock, signerTrust);
    }

    @Bean
    ServiceKeyManager serviceKeyManager(TrustProperties props) {
        return ServiceKeyManager.fromConfig(props.getService());
    }

    @Bean
    SnapshotService snapshotService(TrustRegistry registry, ServiceKeyManager keys, JsonMapper mapper, DidService dids,
                                    CrlService crls, ContextService contexts, TrustProperties props, Clock clock,
                                    TrustMechanisms mechanisms) {
        TrustProperties.Service s = props.getService();
        return new SnapshotService(registry, keys, mapper, dids, props.getRevocation().isEnabled() ? crls : null, contexts,
                new SnapshotService.Options(s.getSnapshotTtl(), s.isSnapshotDidDocuments(), s.getSnapshotMaxDidDocuments(),
                        s.getSnapshotDidDeadline(), props.getRevocation().getSnapshotMaxCrlBytes(), s.getSnapshotMaxContextBytes(),
                        s.getSnapshotRecheck()), clock, mechanisms);
    }

    @Bean
    ClientRegistry clientRegistry(TrustProperties props) {
        return new ClientRegistry(props);
    }
}
