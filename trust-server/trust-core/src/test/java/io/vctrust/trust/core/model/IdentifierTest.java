package io.vctrust.trust.core.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The same vectors are in packages/trust-client/test/binding.test.ts: both sides must index URL identifiers identically. */
class IdentifierTest {

    static final String[][] URL_VECTORS = {
            {"https://Issuer.Example:443/a/../b/", "https://issuer.example/b"},
            {"https://issuer.example/", "https://issuer.example"},
            {"https://issuer.example:8443/x?", "https://issuer.example:8443/x"},
            {"https://bücher.example/p", "https://xn--bcher-kva.example/p"},
            {"http://issuer.example:80/p?q=1#frag", "http://issuer.example/p?q=1"},
            {"https://issuer.example/Path/Case", "https://issuer.example/Path/Case"},
            {"https://issuer.example/../x", "https://issuer.example/x"},
            {"https://user@Issuer.example/y/", "https://issuer.example/y"},
    };

    @Test
    void urlsNormalizeAsOnTheDevice() {
        for (String[] v : URL_VECTORS) {
            assertThat(Identifier.normalizeUrl(v[0])).as(v[0]).isEqualTo(v[1]);
        }
    }
}
