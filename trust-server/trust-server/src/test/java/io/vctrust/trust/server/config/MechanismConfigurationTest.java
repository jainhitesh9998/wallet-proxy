package io.vctrust.trust.server.config;

import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.server.TrustServerApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ByteArrayResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code trust.mechanisms} reaches the strict reader as the operator wrote it, whether from YAML or from flat properties,
 * and a mechanism the service does not understand stops it at startup with a message that names the mechanism.
 */
class MechanismConfigurationTest {

    static final String YAML = """
            trust:
              mechanisms:
                - id: national-id
                  for:
                    role: issuer
                    formats: [mso_mdoc]
                    types: ["org.example.id.*"]
                  keys: [x5c]
                  x509:
                    domain: national-id
                    profile:
                      leaf:
                        ca: false
                        key-usage: [digitalSignature]
                        extended-key-usage: ["1.3.6.1.4.1.99999.1.1"]
                        same-country-as-anchor: true
                        max-validity-days: 1100
                        crl-distribution-point: true
                      max-intermediates: 0
                    revocation: required
                - id: diplomas
                  for: { role: issuer, formats: [ldp_vc] }
                  did: { methods: [web] }
            """;

    static final List<Map<String, Object>> CLAIM = List.of(
            Map.of("id", "national-id",
                    "for", Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.example.id.*")),
                    "keys", List.of("x5c"),
                    "x509", Map.of("domain", "national-id", "revocation", "required", "profile", Map.of(
                            "leaf", Map.of("ca", false, "keyUsage", List.of("digitalSignature"), "extendedKeyUsage", List.of("1.3.6.1.4.1.99999.1.1"),
                                    "sameCountryAsAnchor", true, "maxValidityDays", 1100, "crlDistributionPoint", true),
                            "maxIntermediates", 0))),
            Map.of("id", "diplomas", "for", Map.of("role", "issuer", "formats", List.of("ldp_vc")), "did", Map.of("methods", List.of("web"))));

    static TrustMechanisms bound(Binder binder) {
        TrustProperties props = binder.bind("trust", TrustProperties.class).orElseGet(TrustProperties::new);
        return TrustMechanisms.fromConfiguration(props.getMechanisms().stream().map(PropertyTrees::normalize).toList());
    }

    @Test
    void fromYaml() throws IOException {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader().load("test", new ByteArrayResource(YAML.getBytes(StandardCharsets.UTF_8)));
        assertThat(bound(new Binder(ConfigurationPropertySources.from(sources))).claim()).isEqualTo(CLAIM);
    }

    @Test
    void fromFlatProperties() {
        Map<String, String> flat = new LinkedHashMap<>();
        String m = "trust.mechanisms[0].";
        flat.put(m + "id", "national-id");
        flat.put(m + "for.role", "issuer");
        flat.put(m + "for.formats[0]", "mso_mdoc");
        flat.put(m + "for.types[0]", "org.example.id.*");
        flat.put(m + "keys[0]", "x5c");
        flat.put(m + "x509.domain", "national-id");
        flat.put(m + "x509.profile.leaf.ca", "false");
        flat.put(m + "x509.profile.leaf.key-usage[0]", "digitalSignature");
        flat.put(m + "x509.profile.leaf.extended-key-usage[0]", "1.3.6.1.4.1.99999.1.1");
        flat.put(m + "x509.profile.leaf.same-country-as-anchor", "true");
        flat.put(m + "x509.profile.leaf.max-validity-days", "1100");
        flat.put(m + "x509.profile.leaf.crl-distribution-point", "true");
        flat.put(m + "x509.profile.max-intermediates", "0");
        flat.put(m + "x509.revocation", "required");
        flat.put("trust.mechanisms[1].id", "diplomas");
        flat.put("trust.mechanisms[1].for.role", "issuer");
        flat.put("trust.mechanisms[1].for.formats[0]", "ldp_vc");
        flat.put("trust.mechanisms[1].did.methods[0]", "web");
        assertThat(bound(new Binder(new MapConfigurationPropertySource(flat))).claim()).isEqualTo(CLAIM);
    }

    @Test
    void aMemberSpringWouldDropIsAnErrorInstead() throws IOException {
        String misspelt = YAML.replace("same-country-as-anchor: true", "same-country: true");
        List<PropertySource<?>> sources = new YamlPropertySourceLoader().load("test", new ByteArrayResource(misspelt.getBytes(StandardCharsets.UTF_8)));
        assertThatThrownBy(() -> bound(new Binder(ConfigurationPropertySources.from(sources))))
                .hasMessageStartingWith("Trust mechanism trust.mechanisms[0] ('national-id'): x509.profile.leaf.same-country is not a member");
    }

    @Test
    void theServiceDoesNotStartWithAMechanismItDoesNotUnderstand() throws IOException {
        Path dataDir = Files.createTempDirectory("trust-mechanisms");
        SpringApplicationBuilder app = new SpringApplicationBuilder(TrustServerApplication.class).properties(
                "server.port=0",
                "spring.datasource.url=jdbc:h2:mem:trust-mechanisms;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                "trust.service.signing-key-file=" + dataDir.resolve("key.jwk"),
                "trust.mechanisms[0].id=national-id",
                "trust.mechanisms[0].for.role=issuer",
                "trust.mechanisms[0].keys[0]=did",
                "trust.mechanisms[0].x509.revocation=required");
        assertThatThrownBy(app::run).rootCause().hasMessage(
                "Trust mechanism trust.mechanisms[0] ('national-id'): x509 is given, but keys does not accept x5c: it would never apply");
    }
}
