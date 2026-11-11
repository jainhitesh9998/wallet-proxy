package io.vctrust.trust.core.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Identifiers compare as the specifications say; the client library applies the same rules (binding.test.ts). */
class IdentifierTest {

    @Test
    void urlsCompareByteForByte() {
        assertThat(Identifier.url("https://issuer.example/a")).isEqualTo(Identifier.url("https://issuer.example/a"));
        for (String other : new String[]{"https://issuer.example/a/", "https://Issuer.example/a", "https://issuer.example:443/a",
                "https://issuer.example/x/../a", "https://issuer.example/a#f"}) {
            assertThat(Identifier.url(other)).as(other).isNotEqualTo(Identifier.url("https://issuer.example/a"));
        }
    }

    @Test
    void dnsNamesIgnoreCaseAndDidsLoseTheirFragment() {
        assertThat(Identifier.of(IdentifierType.DNS, "Verifier.Example").value()).isEqualTo("verifier.example");
        assertThat(Identifier.did("did:web:issuer.example#key-1").value()).isEqualTo("did:web:issuer.example");
    }

    @Test
    void onlyPlainHttpsUrlsHaveAHost() {
        assertThat(Identifier.httpsHost("https://verifier.example/post")).isEqualTo("verifier.example");
        assertThat(Identifier.httpsHost("https://verifier.example:8443")).isEqualTo("verifier.example");
        assertThat(Identifier.httpsHost("https://verifier.example?x=1")).isEqualTo("verifier.example");
        for (String refused : new String[]{"http://verifier.example/post", "https://Verifier.example/post", "https://user@verifier.example/",
                "https://collector_1.example/cb", "https://bücher.example/", "https://verifier.example\\@evil.example/", "https:///x", ""}) {
            assertThat(Identifier.httpsHost(refused)).as(refused).isNull();
        }
    }
}
