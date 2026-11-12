package io.vctrust.trust.server.config;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.server.managed.ManagedEntityStore;
import io.vctrust.trust.server.security.ClientRegistry;
import io.vctrust.trust.server.service.AdministrationService;
import io.vctrust.trust.server.service.ContextRelay;
import io.vctrust.trust.server.service.ContextService;
import io.vctrust.trust.server.service.CrlRelay;
import io.vctrust.trust.server.service.CrlService;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.DocumentSigner;
import io.vctrust.trust.server.service.ManagedEntryService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.RegistryQueryService;
import io.vctrust.trust.server.service.RegistryReadiness;
import io.vctrust.trust.server.service.ServiceDescription;
import io.vctrust.trust.server.service.StatusListRelay;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;

/** Wires the use cases the controllers call. */
@Configuration(proxyBeanMethods = false)
public class UseCaseConfiguration {

    @Bean
    RegistryReadiness registryReadiness(TrustSourceManager sources) {
        return new RegistryReadiness(sources);
    }

    @Bean
    RegistryQueryService registryQueryService(TrustRegistry registry, TrustSourceManager sources) {
        return new RegistryQueryService(registry, sources);
    }

    @Bean
    ServiceDescription serviceDescription(ServiceKeyManager keys, TrustRegistry registry, TrustSourceManager sources,
                                          DidResolver didResolver, TrustProperties props) {
        return new ServiceDescription(keys, registry, sources, didResolver, props);
    }

    @Bean
    DocumentSigner documentSigner(ServiceKeyManager keys, JsonMapper mapper, TrustProperties props) {
        return new DocumentSigner(keys, mapper, props.getService().getSignedResponseTtl());
    }

    @Bean
    CrlRelay crlRelay(CrlService crls, TrustProperties props, Clock clock) {
        return new CrlRelay(crls, props.getRevocation(), clock);
    }

    @Bean
    ContextRelay contextRelay(ContextService contexts, TrustProperties props, Clock clock) {
        return new ContextRelay(contexts, props.getCache(), clock);
    }

    @Bean
    AdministrationService administrationService(TrustSourceManager sources, TrustRegistry registry, ClientRegistry clients,
                                                DidService dids, MetadataService metadata, ContextService contexts,
                                                StatusListRelay statusLists, CrlService crls, TrustProperties props) {
        TrustProperties.Revocation revocation = props.getRevocation();
        return new AdministrationService(sources, registry, clients::all, dids, metadata, contexts, statusLists,
                revocation.isEnabled() ? crls : null, revocation.getSnapshotMaxCrlBytes());
    }

    @Bean
    ManagedEntryService managedEntryService(ManagedEntityStore store, ResourceLoader loader, TrustSourceManager sources) {
        return new ManagedEntryService(store, loader, sources);
    }
}
