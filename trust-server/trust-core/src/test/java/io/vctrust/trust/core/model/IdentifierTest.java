package io.vctrust.trust.core.model;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Both sides must index URL identifiers identically: the vectors in test-ecosystem/vectors/url-identifiers.json also run
 * in packages/trust-client/test/binding.test.ts, against Node's and Expo's WHATWG URL parsers.
 */
class IdentifierTest {

    static final Path VECTORS = Path.of("../../test-ecosystem/vectors/url-identifiers.json");

    @Test
    void urlsNormalizeAsOnTheDevice() throws Exception {
        JsonNode vectors = new ObjectMapper().readTree(Files.readString(VECTORS)).get("vectors");
        assertThat(vectors.size()).isGreaterThan(50);
        for (JsonNode v : vectors) {
            String input = v.get(0).asText();
            // Rejected URLs keep their text; the identifier itself is trimmed.
            String key = v.get(1).asText().equals(input) ? input.trim() : v.get(1).asText();
            assertThat(new Identifier(IdentifierType.URL, input).value()).as(input).isEqualTo(key);
        }
    }

    @Test
    void punycodeMatchesRfc3492() {
        assertThat(UrlNormalizer.punycode("bücher")).isEqualTo("bcher-kva");
        assertThat(UrlNormalizer.punycode("münchen")).isEqualTo("mnchen-3ya");
        // RFC 3492 §7.1 (A) Arabic (Egyptian)
        assertThat(UrlNormalizer.punycode("ليهمابتكلموشعربي؟"))
                .isEqualTo("egbpdaj6bu4bxfgehfvwxn");
    }
}
