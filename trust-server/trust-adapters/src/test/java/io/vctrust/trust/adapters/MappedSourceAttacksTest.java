package io.vctrust.trust.adapters;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.BASE;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.lookupOnly;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Attacks on a mapped source that a security review confirmed, each reproduced against the source: the document an
 * attacker controls, and what the source must make of it.
 */
class MappedSourceAttacksTest {

    /** A list in the shape of {@link MappedSourceRulesTest#mapping()}, with one issuer whose members the test chooses. */
    static String list(String issuerMembers) {
        return """
                {"publisher": "Partner", "version": 1, "issued": "%s", "next_update": "%s",
                 "issuers": [{"id": "a", "credential_issuer": "https://a.example", "state": "active", %s}]}"""
                .formatted(MappedSourceRulesTest.NOW.minusSeconds(60), MappedSourceRulesTest.NOW.plusSeconds(86_400), issuerMembers);
    }

    // F1: a number such as 1e999999999 becomes a gigabyte of text --------------------------------------------------

    @Test
    void f1_aDocumentWithANumberTooLargeToWriteOutIsNotRead() {
        // 1e999999 would be a name of a million characters; 1e999999999 one of a gigabyte. Neither reaches the
        // registry: the document is refused where it is parsed, whatever member holds the number.
        for (String number : List.of("1e999999", "-1e999999", "1e-999999", "1e41", "1e-41",
                "12345678901234567890123456789012345678901", "1.2345678901234567890123456789012345678901")) {
            for (String members : List.of("\"name\": " + number, "\"unmapped\": [" + number + "]")) {
                TestContext ctx = ctx();
                ctx.http.json(MappedSourceRulesTest.LOCATION, list(members));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
                    SourceState st = state(m, "partner");
                    assertThat(st.lastError()).as(members).contains("holds a number with more than 40 significant digits "
                            + "or a decimal exponent outside -40 to 40");
                    assertThat(registry.snapshot().entities()).as(members).isEmpty();
                }
            }
        }
        // The bound itself is read.
        for (String number : List.of("1e40", "-1e40", "1e-40", "1234567890123456789012345678901234567890",
                "0.1234567890123456789012345678901234567890", "0e999999999")) {
            TestContext ctx = ctx();
            ctx.http.json(MappedSourceRulesTest.LOCATION, list("\"name\": " + number));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
                assertThat(state(m, "partner").lastError()).as(number).isNull();
                assertThat(registry.snapshot().entities()).singleElement()
                        .satisfies(e -> assertThat(e.displayName("en")).as(number).hasSizeLessThan(100));
            }
        }
    }

    @Test
    void f1_aLookupAnswerWithANumberTooLargeToWriteOutIsAFailure() {
        TestContext ctx = ctx();
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b")).replace("}", ", \"n\": 1e999999}"));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:b"))).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("holds a number with more than 40 significant digits");
    }
}
