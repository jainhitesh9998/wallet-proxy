package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.doc;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.loadError;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.MDL;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mapped source on the registry it runs on: the registry escapes and cuts what a source reports, places an entity
 * whose id is another framework's name under its own framework's, bounds an anchor's CRL locations, and an entry that
 * is not in good standing and names no role keeps its party out whatever is asked. Where the registry does so, the
 * mapped source leans on it rather than refuse an honest list.
 */
@SuppressWarnings("unchecked")
class MappedSourceRegistryTest {

    // 1: a source's messages are escaped and cut by the registry, once --------------------------------------------------

    @Test
    void item1_whatTheSourceEscapedIsNotEscapedAgainInTheStateOrTheWarnings() {
        // A right-to-left override from the document, in a failed load and in a warning: the source writes it as an
        // escape, and the registry, which escapes what a source reports, leaves that escape as it is.
        TestContext ctx = ctx();
        Map<String, Object> d = doc("a");
        d.put("next_update", "soon‮evil");
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props()))) {
            assertThat(state(m, "partner").lastError()).contains("no date there: 'soon\\u202eevil'").doesNotContain("\\\\u202")
                    .doesNotContain("‮");
        }
        Map<String, Object> mapping = MappedSourceAttacksTest.entities("validUntil", "$.valid_until");
        d = doc();
        d.put("issuers", List.of(Map.of("id", "a", "credential_issuer", "https://a.example", "state", "active", "valid_until", "soon‮evil"),
                Map.of("id", "b", "credential_issuer", "https://b.example", "state", "active")));
        serveJson(ctx, d);
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", mapping)))) {
            assertThat(state(m, "partner").warnings()).singleElement().asString().endsWith("validUntil is not a date: 'soon\\u202eevil'")
                    .doesNotContain("\\\\u202").doesNotContain("‮");
        }
    }
}
