package io.vctrust.trust.server.config;

import io.vctrust.trust.adapters.mapped.MappedSourceFactory;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Source properties reach a source through Spring's binding of nested maps (lists arrive as maps keyed "0", "1", ...,
 * which {@link PropertyTrees} turns back into lists) and map keys keep only letters, digits, {@code -} and {@code _}
 * unless written in brackets. An inline mapping must come through that unchanged, and where a key cannot, the source
 * must say so rather than read something else. MappedSourceEndToEndTest runs a whole service on such a configuration.
 */
class MappedSourceBindingTest {

    static final String REGISTRY = """
            {"issuers": [
              {"id": "a", "state": "CSCA", "level": "high"},
              {"id": "b", "state": "https://b.example/suspended"},
              {"id": "c", "state": "https://c.example/revoked"},
              {"id": "d", "state": "unknown"}
            ]}""";

    /** The properties of the first source of {@code yaml}, as the service hands them to the source's factory. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> bind(String yaml) throws IOException {
        StandardEnvironment env = new StandardEnvironment();
        new YamlPropertySourceLoader().load("test", new ByteArrayResource(yaml.getBytes(StandardCharsets.UTF_8)))
                .forEach(env.getPropertySources()::addLast);
        TrustProperties props = Binder.get(env).bind("trust", TrustProperties.class).get();
        return (Map<String, Object>) PropertyTrees.normalize(props.getSources().getFirst().getProperties());
    }

    static TrustSource source(Map<String, Object> properties) {
        ResourceLoader files = location -> {
            if (location.equals("file:/etc/trust/registry.json")) {
                return REGISTRY.getBytes(StandardCharsets.UTF_8);
            }
            throw new IOException("No " + location);
        };
        SourceContext ctx = new SourceContext() {
            @Override
            public HttpFetcher http() {
                return request -> {
                    throw new IOException("no network in this test");
                };
            }

            @Override
            public ResourceLoader resources() {
                return files;
            }

            @Override
            public Clock clock() {
                return Clock.systemUTC();
            }
        };
        return new MappedSourceFactory().create(new SourceDefinition("partner", "mapped", "partner", null, true, properties), ctx);
    }

    static String yaml(String status) {
        return """
                trust:
                  sources:
                    - id: partner
                      type: mapped
                      framework: partner
                      properties:
                        location: file:/etc/trust/registry.json
                        mapping:
                          entities:
                            - each: $.issuers[?@.id != 'x' && @.id != "y"]
                              id: { template: "partner:{$.id}" }
                              roles: [CREDENTIAL_ISSUER, VERIFIER]
                              attributes: { trust_level: $.level, sourceList: "^.issuers[0].id" }
                %s
                """.formatted(status.indent(14).stripTrailing());
    }

    @Test
    void translationsComeThroughSpringInBracketsOrAsWhenThenPairs() throws Exception {
        Map<String, Object> props = bind(yaml("""
                status:
                  path: $.state
                  values:
                    CSCA: ACTIVE
                    "[https://b.example/suspended]": SUSPENDED
                  default: REVOKED"""));
        Map<String, EntityStatus> status = source(props).load().entities().stream()
                .collect(Collectors.toMap(TrustedEntity::id, TrustedEntity::status));
        assertThat(status).containsExactlyInAnyOrderEntriesOf(Map.of("partner:a", EntityStatus.ACTIVE, "partner:b", EntityStatus.SUSPENDED,
                "partner:c", EntityStatus.REVOKED, "partner:d", EntityStatus.REVOKED));

        props = bind(yaml("""
                status:
                  path: $.state
                  values:
                    - { when: CSCA, then: ACTIVE }
                    - { when: "https://b.example/suspended", then: SUSPENDED }
                    - { when: "https://c.example/revoked", then: REVOKED }"""));
        var r = source(props).load();
        assertThat(r.entities()).extracting(e -> e.id() + " " + e.status()).containsExactlyInAnyOrder("partner:a ACTIVE",
                "partner:b SUSPENDED", "partner:c REVOKED", "partner:d SUSPENDED");
        TrustedEntity a = r.entities().stream().filter(e -> e.id().equals("partner:a")).findFirst().orElseThrow();
        assertThat(a.roles()).hasSize(2);
        assertThat(a.attributes()).containsEntry("trust_level", "high").containsEntry("sourceList", "a");
        // "unknown" is in no pair and there is no default: the status yields nothing, and a status the mapping
        // configures but cannot read is not taken for good standing. The record is listed SUSPENDED (it was skipped
        // before the second round of fixes, which left its party to whatever anchor it chains to).
        assertThat(r.warnings()).containsExactly("mapping.entities[0]: record 4 (id 'partner:d') is listed SUSPENDED: status yields "
                + "nothing (no value at its path, or one its translation does not know); give status a default to say what such a record is");
    }

    @Test
    void aKeySpringCannotCarryIsRefusedNotMisread() throws Exception {
        // Spring splits an unbracketed URI key at its dots and drops ':' and '/': "httpsb": {"examplesuspended": ...}.
        Map<String, Object> props = bind(yaml("""
                status:
                  path: $.state
                  values: { CSCA: ACTIVE, "https://b.example/suspended": SUSPENDED }"""));
        assertThatThrownBy(() -> source(props).load()).isInstanceOf(TrustSourceException.class)
                .hasMessageStartingWith("Source 'partner' (mapped): mapping.entities[0].status: values.httpsb is not a single value")
                .hasMessageContaining("write it in brackets");
        // A map whose keys are all digits arrives as a list: refused, since its pairs are not {when, then}.
        Map<String, Object> digits = bind(yaml("""
                status:
                  path: $.state
                  values: { "0": REVOKED, "1": ACTIVE }"""));
        assertThatThrownBy(() -> source(digits).load()).hasMessageContaining("values as a list holds {when, then} pairs only");
    }
}
