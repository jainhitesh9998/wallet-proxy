package io.vctrust.trust.server;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registries this repository ships load under the registry format as it is read: the demo profile's classpath
 * registry and the example of docs/trust-methods.md. (The vector registries are written through the admin API by the
 * vector tests, and the service test's registries by that test.) A registry that relied on a member being ignored would
 * not load at all. And the registry takes all of it: an anchor whose {@code entity} names no entity of its framework (an
 * id written another way) would not be loaded.
 */
class RepositoryRegistriesTest {

    static final Path ROOT = EvaluationVectors.repositoryRoot();

    /** Locations as the service started in the repository root reads them, without the network. */
    static final SourceContext CONTEXT = new SourceContext() {
        @Override
        public HttpFetcher http() {
            throw new AssertionError("a repository registry fetches nothing");
        }

        @Override
        public ResourceLoader resources() {
            return location -> {
                if (location.startsWith("classpath:")) {
                    try (InputStream in = RepositoryRegistriesTest.class.getResourceAsStream("/" + location.substring("classpath:".length()))) {
                        if (in == null) {
                            throw new IOException("No resource " + location);
                        }
                        return in.readAllBytes();
                    }
                }
                return Files.readAllBytes(ROOT.resolve(location));
            };
        }

        @Override
        public Clock clock() {
            return Clock.systemUTC();
        }
    };

    static TrustSource source(String framework, String location) {
        return new StaticTrustSourceFactory().create(new SourceDefinition("registry", "static", framework, null, true,
                Map.of("location", location)), CONTEXT);
    }

    static SourceLoadResult load(String framework, String location) throws Exception {
        return source(framework, location).load();
    }

    /**
     * The registry as the service builds it from the source alone: no warning in the source's state, every anchor loaded,
     * and each anchor that names an entity tied to that entity.
     */
    static void placedWhole(String framework, String location) throws Exception {
        SourceLoadResult loaded = load(framework, location);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = new TrustSourceManager(registry, List.of(new TrustFramework(framework, framework, null, null, null)),
                List.of(source(framework, location)), Clock.systemUTC())) {
            manager.start();
            assertThat(manager.states()).singleElement().satisfies(st -> {
                assertThat(st.lastError()).isNull();
                assertThat(st.warnings()).isEmpty();
            });
            RegistrySnapshot snapshot = registry.snapshot();
            assertThat(snapshot.allAnchors()).extracting(TrustAnchor::id)
                    .containsExactlyInAnyOrderElementsOf(loaded.anchors().stream().map(TrustAnchor::id).toList());
            for (TrustAnchor a : loaded.anchors()) {
                if (a.entityId() != null) {
                    assertThat(snapshot.anchor(a.id())).as(a.id()).get().satisfies(placed -> {
                        assertThat(placed.entityId()).isEqualTo(a.entityId());
                        assertThat(snapshot.entity(placed.entityId())).as("the entity of %s", a.id()).isPresent();
                    });
                }
            }
        }
    }

    @Test
    void theDemoProfilesRegistryLoads() throws Exception {
        var r = load("animo-playground", "classpath:trust/demo-registry.yaml");
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).hasSize(1);
        assertThat(r.anchors()).hasSize(3);
        placedWhole("animo-playground", "classpath:trust/demo-registry.yaml");
    }

    /** The demo profile's source {@code id}, as application-demo.yml configures it. */
    @SuppressWarnings("unchecked")
    static SourceDefinition demoSource(String id) throws IOException {
        try (InputStream in = RepositoryRegistriesTest.class.getResourceAsStream("/application-demo.yml")) {
            Map<String, Object> yaml = new org.yaml.snakeyaml.Yaml().load(in);
            List<Map<String, Object>> sources = (List<Map<String, Object>>) ((Map<String, Object>) yaml.get("trust")).get("sources");
            Map<String, Object> s = sources.stream().filter(x -> id.equals(x.get("id"))).findFirst().orElseThrow();
            return new SourceDefinition(id, (String) s.get("type"), (String) s.get("framework"), null, true,
                    (Map<String, Object>) s.get("properties"));
        }
    }

    /**
     * The demo profile describes the playground's issuer with what it says about itself ({@code animo-issuers}, an
     * {@code oid4vci-discovery} source). A description makes no entity of its own: it reaches the entity the demo
     * registry lists, and the two load together without a warning.
     */
    @Test
    void theDemoProfilesDescriptionOfThePlaygroundReachesItsEntity() throws Exception {
        SourceDefinition registryDef = demoSource("demo-registry");
        SourceDefinition describing = demoSource("animo-issuers");
        assertThat(describing.type()).isEqualTo("oid4vci-discovery");
        String issuer = (String) ((Map<?, ?>) describing.list("issuers").getFirst()).get("url");
        // The playground's issuer, served as it serves its metadata, without the network.
        io.vctrust.trust.core.testing.FakeHttp http = new io.vctrust.trust.core.testing.FakeHttp();
        String path = java.net.URI.create(issuer).getPath();
        http.json("https://playground.animo.id/.well-known/openid-credential-issuer" + path, "{\"credential_issuer\":\"" + issuer
                + "\",\"credential_endpoint\":\"" + issuer + "/credential\",\"display\":[{\"name\":\"Utopia\",\"locale\":\"en\"}],"
                + "\"credential_configurations_supported\":{\"mdl\":{\"format\":\"mso_mdoc\",\"doctype\":\"org.iso.18013.5.1.mDL\"}}}");
        http.json("https://playground.animo.id/.well-known/oauth-authorization-server" + path, "{\"issuer\":\"" + issuer + "\"}");
        SourceContext context = new SourceContext() {
            @Override
            public HttpFetcher http() {
                return http;
            }

            @Override
            public ResourceLoader resources() {
                return CONTEXT.resources();
            }

            @Override
            public Clock clock() {
                return Clock.systemUTC();
            }
        };
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = new TrustSourceManager(registry, List.of(new TrustFramework("animo-playground", "Animo", null, null, null)),
                List.of(new StaticTrustSourceFactory().create(registryDef, context),
                        new io.vctrust.trust.adapters.oid4vci.Oid4vciDiscoverySourceFactory().create(describing, context)), Clock.systemUTC())) {
            manager.start();
            assertThat(manager.states()).hasSize(2).allSatisfy(st -> {
                assertThat(st.lastError()).as(st.id()).isNull();
                assertThat(st.warnings()).as(st.id()).isEmpty();
            });
            assertThat(registry.snapshot().entities()).singleElement().satisfies(e -> {
                assertThat(e.id()).isEqualTo("animo-playground");
                // The registry's own display stands; the description is merged in.
                assertThat(e.displayName("en")).isEqualTo("Animo Playground");
                assertThat(e.attributes()).containsEntry("mergedFrom", List.of("demo-registry", "animo-issuers"));
            });
        }
    }

    @Test
    void theTrustMethodsExampleRegistryLoads() throws Exception {
        var r = load("example", "docs/examples/trust-methods/registry.yaml");
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).hasSize(4);
        assertThat(r.anchors()).hasSize(4);
        placedWhole("example", "docs/examples/trust-methods/registry.yaml");
    }
}
