package io.vctrust.trust.server;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The layering of this module, checked on its sources. Controllers bind HTTP and call a use case; use cases live in
 * {@code service} and know nothing of the web; {@code security} and {@code http} are adapters at the edges;
 * {@code config} wires all of them and may name anything.
 *
 * <p>A name counts wherever it appears in code, imported or written out in full; comments and string literals do not
 * count.
 */
class LayeringTest {

    private static final Path SERVER = serverSources();

    /** The use cases and what they stand on. */
    private static final List<String> BELOW_THE_WEB = List.of("service", "managed", "cache", "signing");

    /** What nothing below the web may name: the REST layer, the adapters around the use cases, HTTP and servlets. */
    private static final List<String> THE_WEB = List.of(
            "io.vctrust.trust.server.api.",
            "io.vctrust.trust.server.security.",
            "io.vctrust.trust.server.http.",
            "org.springframework.http.",
            "org.springframework.web.",
            "jakarta.servlet.");

    /**
     * Everything of this project that {@code api} may name: the use cases, and the values that travel through the
     * API. Not the registry, the sources, the stores, the caches, the keys, the configuration or the list parsers:
     * a controller that needs one of those needs a use case instead.
     */
    private static final List<String> VISIBLE_TO_API = List.of(
            "io.vctrust.trust.server.api.",
            "io.vctrust.trust.server.service.",
            "io.vctrust.trust.core.policy.ClientProfile",
            "io.vctrust.trust.core.evaluation.TrustEvaluator",
            "io.vctrust.trust.core.evaluation.TrustQuery",
            "io.vctrust.trust.core.evaluation.TrustDecision",
            "io.vctrust.trust.core.model.EntityRole",
            "io.vctrust.trust.core.registry.SourceState",
            "io.vctrust.trust.core.did.DidResolutionResult",
            "io.vctrust.trust.core.spi.HttpFetcher.BlockedException");

    /** What the adapters at the edges may not name: they are used by the layers, not the other way round. */
    private static final List<String> HIDDEN_FROM_ADAPTERS = List.of(
            "io.vctrust.trust.server.api.",
            "io.vctrust.trust.server.service.",
            "io.vctrust.trust.server.managed.");

    private static final Pattern PROJECT_NAME = Pattern.compile("\\bio\\.vctrust\\.trust\\.[\\w.]+");
    private static final Pattern PACKAGE_DECLARATION = Pattern.compile("\\bpackage\\s+[\\w.]+\\s*;");

    @Test
    void useCasesKnowNothingOfTheWeb() {
        List<String> violations = new ArrayList<>();
        for (String pkg : BELOW_THE_WEB) {
            for (Path file : sources(pkg)) {
                String code = code(file);
                THE_WEB.stream().filter(code::contains).forEach(name -> violations.add(pkg + "/" + file.getFileName() + " names " + name));
            }
        }
        assertThat(violations).as("service, managed, cache and signing are below the web layer").isEmpty();
    }

    @Test
    void theWebLayerNamesOnlyUseCasesAndTheValuesOfTheApi() {
        List<String> violations = new ArrayList<>();
        for (Path file : sources("api")) {
            Matcher m = PROJECT_NAME.matcher(PACKAGE_DECLARATION.matcher(code(file)).replaceFirst(""));
            while (m.find()) {
                String name = m.group();
                if (VISIBLE_TO_API.stream().noneMatch(allowed -> names(name, allowed))) {
                    violations.add("api/" + file.getFileName() + " names " + name);
                }
            }
        }
        assertThat(violations).as("controllers call use cases (io.vctrust.trust.server.service); they hold no other collaborators").isEmpty();
    }

    @Test
    void adaptersDoNotReachIntoTheLayersThatUseThem() {
        List<String> violations = new ArrayList<>();
        for (String pkg : List.of("security", "http")) {
            for (Path file : sources(pkg)) {
                String code = code(file);
                HIDDEN_FROM_ADAPTERS.stream().filter(code::contains).forEach(name -> violations.add(pkg + "/" + file.getFileName() + " names " + name));
            }
        }
        assertThat(violations).as("security and http are used by the web layer and the wiring, and use neither").isEmpty();
    }

    /** A new package has to be given its place in the rules above. */
    @Test
    void everyPackageHasItsRules() throws IOException {
        try (Stream<Path> dirs = Files.list(SERVER)) {
            Set<String> packages = new TreeSet<>(dirs.filter(Files::isDirectory).map(p -> p.getFileName().toString()).toList());
            assertThat(packages).containsExactlyInAnyOrder("api", "service", "managed", "cache", "signing", "security", "http", "config");
        }
    }

    /** Whether {@code name} is the allowed class, one of its members, or in the allowed package (an entry ending in a dot). */
    private static boolean names(String name, String allowed) {
        return allowed.endsWith(".") ? name.startsWith(allowed) : name.equals(allowed) || name.startsWith(allowed + ".");
    }

    private static List<Path> sources(String pkg) {
        try (Stream<Path> files = Files.walk(SERVER.resolve(pkg))) {
            List<Path> out = files.filter(p -> p.toString().endsWith(".java")).sorted().toList();
            assertThat(out).as("sources of " + pkg).isNotEmpty();
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The file without comments, string literals and character literals. */
    private static String code(Path file) {
        String source;
        try {
            source = Files.readString(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (source.startsWith("//", i)) {
                i = until(source, "\n", i + 2);
            } else if (source.startsWith("/*", i)) {
                i = until(source, "*/", i + 2) + 2;
            } else if (source.startsWith("\"\"\"", i)) {
                i = until(source, "\"\"\"", i + 3) + 3;
            } else if (c == '"' || c == '\'') {
                i++;
                while (i < n && source.charAt(i) != c) {
                    i += source.charAt(i) == '\\' ? 2 : 1;
                }
                i++;
            } else {
                out.append(c);
                i++;
                continue;
            }
            out.append(' ');
        }
        return out.toString();
    }

    private static int until(String source, String end, int from) {
        int at = source.indexOf(end, from);
        return at < 0 ? source.length() : at;
    }

    private static Path serverSources() {
        try {
            Path testClasses = Path.of(LayeringTest.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return testClasses.getParent().getParent().resolve("src/main/java/io/vctrust/trust/server");
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
