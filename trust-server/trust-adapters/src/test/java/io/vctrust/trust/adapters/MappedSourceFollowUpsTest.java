package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRoundFiveTest.block;
import static io.vctrust.trust.adapters.MappedSourceRoundFiveTest.derOf;
import static io.vctrust.trust.adapters.MappedSourceRoundFiveTest.revokedWith;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.props;
import static io.vctrust.trust.adapters.MappedSourceRulesTest.serveJson;
import static io.vctrust.trust.adapters.MappedSourceValidationTest.MDL;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mapped source's follow-ups after it was published, each reproduced, and decided by the evaluator where a decision
 * is at stake. The principle stays: where a valid chain to a listed CA is trusted by itself, an entry that restricts a
 * party must reach the decision, and must not lose to how its certificate text is written.
 */
class MappedSourceFollowUpsTest {

    /** A certificate as bare base64 lines of 64 characters, as tools write the body of a block. */
    static String bare(String name) {
        return Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(derOf(name)) + "\n";
    }

    /** CA rows of one list: {@code row-1} the IACA active, {@code row-7} withdrawn, its certificate written as {@code text}. */
    static Map.Entry<TrustRegistry, TrustSourceManager> rows(String text) {
        Map<String, Object> mapping = Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"], "certificates": "$.certificates[*]",
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate",
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}]}""");
        TestContext ctx = ctx();
        serveJson(ctx, Map.of("issuers", List.of(Map.of("id", "college", "state", "active")),
                "cas", List.of(Map.of("kid", "row-1", "certificate", der("iaca"), "state", "active"),
                        Map.of("kid", "row-7", "certificate", text, "state", "revoked"))));
        TrustRegistry registry = new TrustRegistry();
        return Map.entry(registry, manager(registry, source(ctx, props("mapping", mapping))));
    }

    // 3: a certificate written as bare base64 lines beside the blocks ------------------------------------------------

    static final String BARE = "mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: a PEM text has lines of "
            + "base64 outside its certificate blocks that decode to DER (a certificate written without its BEGIN and END lines)";

    @Test
    void item3_aCertificateAsBareBase64LinesBesideABlockCannotBeRead() {
        Map<String, String> hidden = new LinkedHashMap<>();
        hidden.put("a block, then the DS as one bare line", block(derOf("ds-nl")) + der("ds") + "\n");
        hidden.put("a block, then the DS in lines of 64", block(derOf("ds-nl")) + bare("ds"));
        hidden.put("the DS as a bare line, then a block", der("ds") + "\n" + block(derOf("ds-nl")));
        hidden.put("a block, then the DS between BEGIN and END lines without dashes", block(derOf("ds-nl")) + "BEGIN CERTIFICATE\n"
                + bare("ds") + "END CERTIFICATE\n");
        hidden.forEach((what, text) -> {
            // Bound to ds-nl only: the revoked issuer's DS certificate was trusted through the shared IACA.
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith(BARE);
        });
        // Text that explains the blocks stays passed over: subject= and issuer= lines, Bag Attributes, a word.
        String explained = "Bag Attributes\n    friendlyName: utopia-ds\nsubject=C = UT, O = Utopia DMV, CN = Utopia DS\n"
                + "issuer=C = UT, O = Utopia DMV, CN = Utopia IACA\nCertificate\n" + MappedTesting.pem("ds") + "Expires 2046\n";
        assertThat(revokedWith(explained)).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        // A withdrawn CA row written so is not read as the block's certificate.
        var tied = rows(block(derOf("ds-nl")) + bare("iaca"));
        try (TrustSourceManager m = tied.getValue()) {
            assertThat(tied.getKey().snapshot().allAnchors()).extracting(a -> a.id()).doesNotContain("row-7");
        }
    }
}
