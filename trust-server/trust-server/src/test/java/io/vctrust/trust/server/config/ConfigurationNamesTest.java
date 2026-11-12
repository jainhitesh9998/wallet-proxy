package io.vctrust.trust.server.config;

import io.vctrust.trust.server.TrustServerApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Every property under {@code trust.} that a configuration file or an argument sets must be one the configuration
 * knows, list indices aside: what a higher-precedence source leaves behind of a list it replaces is not an error, a
 * misspelt name is. Started as the service starts, with real configuration files.
 */
class ConfigurationNamesTest {

    /** Three clients, two of them with frameworks; a source whose properties hold a list. */
    static final String BASE = """
            trust:
              frameworks:
                - { id: eu }
                - { id: national }
              sources:
                - id: bundle
                  type: x509-bundle
                  framework: national
                  properties:
                    domain: mdoc-iaca
                    certificateLocation: https://pki.example/iaca.pem
                    sha256: [aa, bb]
              clients:
                - id: wallet
                  api-key: base-wallet-key
                  frameworks: [eu, national]
                  certificate-sha256: [0a0b, 0c0d]
                - id: verifier
                  api-key: base-verifier-key
                  frameworks: [eu]
                  require-revocation-status: true
                - id: ops
                  api-key: base-ops-key
                  admin: true
            """;

    /** Of higher precedence: two clients, the second without frameworks, and another list of sources. */
    static final String PROD = """
            trust:
              sources:
                - id: managed
                  type: managed
                  framework: eu
              clients:
                - id: wallet
                  api-key: prod-wallet-key
                  frameworks: [eu]
                - id: ops
                  api-key: prod-ops-key
                  admin: true
            """;

    @Test
    void aListOverriddenFromASecondFileIsReplacedAsAWhole() throws IOException {
        try (ConfigurableApplicationContext ctx = start(List.of(BASE, PROD))) {
            TrustProperties props = ctx.getBean(TrustProperties.class);
            assertThat(props.getClients()).extracting(TrustProperties.Client::getId).containsExactly("wallet", "ops");
            TrustProperties.Client wallet = props.getClients().get(0);
            assertThat(wallet.getApiKey()).isEqualTo("prod-wallet-key");
            assertThat(wallet.getFrameworks()).containsExactly("eu");
            assertThat(wallet.getCertificateSha256()).isEmpty();
            TrustProperties.Client ops = props.getClients().get(1);
            assertThat(ops.isAdmin()).isTrue();
            assertThat(ops.getFrameworks()).isEmpty();
            assertThat(props.getSources()).extracting(TrustProperties.Source::getId).containsExactly("managed");
            assertThat(props.getSources().get(0).getProperties()).isEmpty();
            // The frameworks come from the only file that sets them.
            assertThat(props.getFrameworks()).extracting(TrustProperties.Framework::getId).containsExactly("eu", "national");
            // The override's clients are the clients: the base file's keys authenticate nobody.
            var clients = ctx.getBean(io.vctrust.trust.server.security.ClientRegistry.class);
            assertThat(clients.byApiKey("prod-wallet-key")).isPresent();
            assertThat(clients.byApiKey("prod-ops-key")).isPresent();
            assertThat(clients.byApiKey("base-wallet-key")).isEmpty();
            assertThat(clients.byApiKey("base-verifier-key")).isEmpty();
            assertThat(clients.byApiKey("base-ops-key")).isEmpty();
        }
    }

    @Test
    void aMisspeltListIsRefusedWithItsNameAndFile() throws IOException {
        Throwable t = failure(List.of("""
                trust:
                  mechanism:
                    - id: national-id
                      for: { role: issuer }
                """));
        assertThat(t).hasMessageContaining("trust.mechanism[0].id").hasMessageContaining("is not a property this service knows")
                .hasMessageContaining("config-0.yml");
    }

    @Test
    void aMisspeltMemberIsRefusedWithItsNameAndFile() throws IOException {
        Throwable t = failure(List.of("""
                trust:
                  revocaton:
                    enabled: false
                """));
        assertThat(t).hasMessageContaining("trust.revocaton.enabled").hasMessageContaining("is not a property this service knows")
                .hasMessageContaining("config-0.yml");
    }

    @Test
    void aMisspeltMemberOfAListElementIsRefused() throws IOException {
        Throwable t = failure(List.of("""
                trust:
                  clients:
                    - id: wallet
                      api-key: key
                      framworks: [eu]
                """));
        assertThat(t).hasMessageContaining("trust.clients[0].framworks[0]").hasMessageContaining("is not a property this service knows")
                .hasMessageContaining("config-0.yml");
    }

    /** A misspelt name in the lower of two files is refused too, also when the higher one replaces that list. */
    @Test
    void aMisspeltMemberLeftBehindByAnOverrideIsRefused() throws IOException {
        Throwable t = failure(List.of(BASE.replace("frameworks: [eu]\n      require", "framworks: [eu]\n      require"), PROD));
        assertThat(t).hasMessageContaining("trust.clients[1].framworks[0]").hasMessageContaining("config-0.yml");
    }

    @Test
    void anUnknownArgumentIsRefusedAndSaysItIsAnArgument() throws IOException {
        Throwable t = failure(List.of(), "--trust.revocaton.enabled=false");
        assertThat(t).hasMessageContaining("trust.revocaton.enabled (from a command-line argument) is not a property this service knows");
    }

    @Test
    void mechanismsWrittenAsAMapAreRefused() throws IOException {
        Throwable t = failure(List.of("""
                trust:
                  mechanisms:
                    national-id:
                      for: { role: issuer }
                      keys: [x5c]
                """));
        assertThat(t).hasMessageContaining("trust.mechanisms.national-id.for.role")
                .hasMessageContaining("trust.mechanisms is a list, and 'national-id' is not an index").hasMessageContaining("config-0.yml");
    }

    /**
     * An argument that sets one member of one mechanism stands for the whole list (configuration.md, "One list, from
     * one place"): a mechanism with that member alone, which the mechanisms reader refuses.
     */
    @Test
    void anArgumentForOneMemberOfAMechanismStandsForTheWholeList() throws IOException {
        Throwable t = failure(List.of("""
                trust:
                  mechanisms:
                    - id: national-id
                      for: { role: issuer }
                """), "--trust.mechanisms[0].x509.revocation=required");
        assertThat(t).hasMessage("Trust mechanism trust.mechanisms[0]: id is required");
    }

    /** Kebab case, camel case and underscores are one name, as Spring's relaxed binding reads them. */
    @Test
    void relaxedSpellingsOfKnownNamesStart() throws IOException {
        try (ConfigurableApplicationContext ctx = start(List.of("""
                trust:
                  revocation:
                    fetchAnchorCrls: false
                  auth:
                    rate_limit:
                      requests_per_minute: 77
                  clients:
                    - id: wallet
                      apiKey: key
                      Frameworks: ["*"]
                      require_revocation_status: true
                """))) {
            TrustProperties props = ctx.getBean(TrustProperties.class);
            assertThat(props.getRevocation().isFetchAnchorCrls()).isFalse();
            assertThat(props.getAuth().getRateLimit().getRequestsPerMinute()).isEqualTo(77);
            assertThat(props.getClients().get(0).isRequireRevocationStatus()).isTrue();
        }
    }

    /**
     * A container platform sets variables such as TRUST_SERVICE_PORT for a service named "trust": environment
     * variables are not checked, as Spring Boot did not check them before.
     */
    @Test
    void anUnrelatedTrustEnvironmentVariableDoesNotStopTheService() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                        Map.of("TRUST_SERVICE_PORT", "tcp://10.0.0.7:8090", "TRUST_PORT_8090_TCP_ADDR", "10.0.0.7")));
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(TrustServerApplication.class).environment(environment)
                .run(args(Files.createTempDirectory("trust-names"), List.of()))) {
            assertThat(ctx.getEnvironment().getProperty("trust.service.port")).isEqualTo("tcp://10.0.0.7:8090");
            assertThat(ctx.getBean(TrustProperties.class)).isNotNull();
        }
    }

    /** The configuration of the trust-methods guide starts as it is. */
    @Test
    void theDocumentedExampleStarts() throws IOException {
        Path dir = Files.createTempDirectory("trust-names");
        List<String> args = new ArrayList<>(List.of(args(dir, List.of())));
        args.add("--spring.config.additional-location=" + repository().resolve("docs/examples/trust-methods/application.yml").toUri());
        // What the example points at outside the configuration itself stays out of the source tree and the network.
        args.add("--trust.revocation.fetch-anchor-crls=false");
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(TrustServerApplication.class).run(args.toArray(String[]::new))) {
            TrustProperties props = ctx.getBean(TrustProperties.class);
            assertThat(props.getClients()).extracting(TrustProperties.Client::getId).containsExactly("wallet", "strict-wallet", "ops");
            assertThat(props.getMechanisms()).hasSize(1);
        }
    }

    /**
     * Every configuration in the repository, and every configuration example in the documentation, names only what
     * the service knows. (The demo profile is not started here: it loads sources from the network once started.)
     */
    @Test
    void everyConfigurationInTheRepositoryAndTheDocumentationIsKnown() throws IOException {
        Path root = repository();
        List<Resource> files = List.of(new ClassPathResource("application.yml"), new ClassPathResource("application-demo.yml"),
                new FileSystemResource(root.resolve("docs/examples/trust-methods/application.yml")));
        for (Resource r : files) {
            assertThat(problems(r)).as(r.getDescription()).isEmpty();
        }
        Pattern block = Pattern.compile("```yaml\n(trust:\n.*?)```", Pattern.DOTALL);
        int examples = 0;
        for (String doc : List.of("docs/configuration.md", "docs/trust-methods.md", "README.md")) {
            Matcher m = block.matcher(Files.readString(root.resolve(doc)));
            while (m.find()) {
                examples++;
                Resource r = new ByteArrayResource(m.group(1).getBytes(StandardCharsets.UTF_8), doc + " at offset " + m.start());
                assertThat(problems(r)).as(r.getDescription()).isEmpty();
            }
        }
        assertThat(examples).as("configuration examples in the documentation").isGreaterThanOrEqualTo(5);
    }

    private static List<String> problems(Resource yaml) throws IOException {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader().load(yaml.getDescription(), yaml);
        assertThat(sources).as(yaml.getDescription()).isNotEmpty();
        return TrustPropertyNames.problems(ConfigurationPropertySources.from(sources));
    }

    static Path repository() {
        Path p = Path.of("").toAbsolutePath();
        while (!Files.exists(p.resolve("conformance"))) {
            p = p.getParent();
        }
        return p;
    }

    /** The service started with these configuration files, each of higher precedence than the one before it. */
    static ConfigurableApplicationContext start(List<String> files, String... extra) throws IOException {
        return new SpringApplicationBuilder(TrustServerApplication.class).run(args(Files.createTempDirectory("trust-names"), files, extra));
    }

    /** The innermost cause of the failure to start with these configuration files and arguments. */
    static Throwable failure(List<String> files, String... extra) throws IOException {
        Throwable thrown = catchThrowable(() -> start(files, extra).close());
        assertThat(thrown).as("the service started with %s", files).isNotNull();
        Throwable root = thrown;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return root;
    }

    private static String[] args(Path dir, List<String> files, String... extra) throws IOException {
        List<String> args = new ArrayList<>(List.of(
                "--server.port=0",
                "--spring.datasource.url=jdbc:h2:mem:trust-names-" + dir.getFileName() + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                "--trust.service.signing-key-file=" + dir.resolve("key.jwk")));
        List<String> locations = new ArrayList<>();
        for (int i = 0; i < files.size(); i++) {
            Path f = dir.resolve("config-" + i + ".yml");
            Files.writeString(f, files.get(i));
            locations.add(f.toUri().toString());
        }
        if (!locations.isEmpty()) {
            // Of the locations given, a later one takes precedence over an earlier one.
            args.add("--spring.config.additional-location=" + String.join(",", locations));
        }
        args.addAll(List.of(extra));
        return args.toArray(String[]::new);
    }
}
