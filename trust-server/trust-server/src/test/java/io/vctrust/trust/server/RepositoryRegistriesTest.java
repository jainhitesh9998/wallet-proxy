package io.vctrust.trust.server;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The registries this repository ships load under the registry format as it is read: the demo profile's classpath
 * registry and the example of docs/trust-methods.md. (The vector registries are written through the admin API by the
 * vector tests, and the service test's registries by that test.) A registry that relied on a member being ignored would
 * not load at all.
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

    static SourceLoadResult load(String framework, String location) throws Exception {
        return new StaticTrustSourceFactory().create(new SourceDefinition("registry", "static", framework, null, true,
                Map.of("location", location)), CONTEXT).load();
    }

    @Test
    void theDemoProfilesRegistryLoads() throws Exception {
        var r = load("animo-playground", "classpath:trust/demo-registry.yaml");
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).hasSize(1);
        assertThat(r.anchors()).hasSize(3);
    }

    @Test
    void theTrustMethodsExampleRegistryLoads() throws Exception {
        var r = load("example", "docs/examples/trust-methods/registry.yaml");
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).hasSize(4);
        assertThat(r.anchors()).hasSize(4);
    }
}
