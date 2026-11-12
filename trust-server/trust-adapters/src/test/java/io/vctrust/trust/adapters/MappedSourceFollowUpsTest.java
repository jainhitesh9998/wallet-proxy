package io.vctrust.trust.adapters;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.Reason;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.TrustSource;
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

    // 4: a CA row skipped for its certificate text still says which certificates it is about ---------------------------

    static String sameCertificate(String in) {
        return "Anchor 'row-1' and record 2 of mapping.anchors[0] (id 'row-7') have the same certificate in domain " + in
                + ", and the record cannot be read: which one holds cannot be told";
    }

    @Test
    void item4_aSkippedRowOfACertificateAnotherRowListsFailsTheLoad() {
        Map<String, String> written = new LinkedHashMap<>();
        written.put("one block, the IACA and another certificate", block(derOf("iaca"), derOf("ds-nl")));
        written.put("one block, another certificate and the IACA", block(derOf("ds-nl"), derOf("iaca")));
        written.put("one block, the IACA and other bytes", block(derOf("iaca"), new byte[100]));
        written.put("base64 of the IACA and another certificate", Base64.getEncoder().encodeToString(
                java.nio.ByteBuffer.allocate(derOf("iaca").length + derOf("ds-nl").length).put(derOf("iaca")).put(derOf("ds-nl")).array()));
        written.put("a block, then the IACA as bare base64 lines", block(derOf("ds-nl")) + bare("iaca"));
        written.forEach((what, text) -> {
            var r = rows(text);
            try (TrustSourceManager m = r.getValue()) {
                // Skipped and naming no certificate, row-7 did not meet row-1: the IACA was TRUSTED through it.
                assertThat(MappedSourceValidationTest.decide(r.getKey(), MDL)).as(what).isNotEqualTo(Decision.TRUSTED);
                assertThat(state(m, "partner").lastError()).as(what).isEqualTo(sameCertificate("mdoc-iaca"));
            }
        });
        // A row skipped for certificates no other row lists is skipped as before, and the IACA's row decides.
        var other = rows(block(derOf("ds-nl"), derOf("rp-ca")));
        try (TrustSourceManager m = other.getValue()) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(state(m, "partner").warnings()).singleElement().asString().startsWith("mapping.anchors[0]: record 2 (id 'row-7') "
                    + "is skipped: certificate: a PEM block holds more than one certificate");
            assertThat(MappedSourceValidationTest.decide(other.getKey(), MDL)).isEqualTo(Decision.TRUSTED);
        }
    }

    // 5: a lookup answer of an id the list withdraws for every role -------------------------------------------------------

    static final Identifier VERIFIER_DNS = Identifier.of(IdentifierType.DNS, "verifier.example");

    /** The partner's list with "Verifier Inc" REVOKED as {@code roles}, and its answer about verifier.example: active, an issuer. */
    static TrustSource withdrawnInTheList(TestContext ctx, List<String> roles) {
        serveJson(ctx, Map.of("version", 1, "parties", List.of(
                        Map.of("id", "Verifier Inc", "roles", roles, "dns", List.of("old.example"), "state", "revoked"),
                        Map.of("id", "other-verifier", "roles", List.of("VERIFIER"), "dns", List.of("other.example"), "state", "active")),
                "cas", List.of(Map.of("kid", "rp-ca", "certificate", der("rp-ca")))));
        ctx.http.json("https://registry.partner.example/v1/parties/verifier.example", Json.write(Map.of("id", "Verifier Inc",
                "roles", List.of("CREDENTIAL_ISSUER"), "dns", List.of("verifier.example"), "state", "active")));
        return source(ctx, props("mapping", OnDemandAnswerMergeTest.mapping()));
    }

    @Test
    void item5_aLookupAnswerOfAnIdTheListWithdrawsForEveryRoleNamesNoRole() throws Exception {
        TrustSource partner = withdrawnInTheList(ctx(), List.of());
        partner.load();
        TrustedEntity answer = ((OnDemandResolver) partner).resolve(VERIFIER_DNS).orElseThrow();
        // The answer kept its role: asked as a verifier, it was left out, and the chain to the partner's CA decided.
        assertThat(answer.status()).isEqualTo(EntityStatus.REVOKED);
        assertThat(answer.roles()).isEmpty();
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, partner)) {
            TrustDecision d = OnDemandAnswerMergeTest.verifier(registry, m);
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
        }
        // A withdrawal that names a role holds the answer's status and validity, and leaves its roles as they are.
        TrustSource named = withdrawnInTheList(ctx(), List.of("VERIFIER"));
        named.load();
        TrustedEntity held = ((OnDemandResolver) named).resolve(VERIFIER_DNS).orElseThrow();
        assertThat(held.status()).isEqualTo(EntityStatus.REVOKED);
        assertThat(held.roles()).containsExactly(EntityRole.CREDENTIAL_ISSUER);
    }

    // 6: a path inside a template of a member that says whom a record is about ------------------------------------------

    @Test
    void item6_aTemplateOfAnIdentifyingMemberThatReadsAListWithItemsMustYield() {
        String hash = io.vctrust.trust.core.x509.Certificates.sha256Thumbprint(io.vctrust.trust.core.x509.Certificates.fromBase64(der("ds")));
        Map<String, Object> certificates = Map.of("certificates", List.of(Map.of("template", "{$.certificates[0]}")));
        Map<String, Object> byHash = Map.of("identifiers", List.of(Map.of("type", "X509_SHA256", "value", Map.of("template", "{$.hashes[0]}"))));
        // Listed revoked without what binds it, and no warning: the DS chain decided alone, TRUSTED.
        var c = MappedSourceProbesTest.revokedDmv(certificates, MappedSourceValidationTest.members("certificates",
                java.util.Arrays.asList(null, der("ds"))));
        assertThat(c.getValue()).isNotEqualTo(Decision.TRUSTED);
        assertThat(c.getKey()).startsWith(MappedSourceRoundFiveTest.unreadable("certificates", "$.certificates[0]"));
        var h = MappedSourceProbesTest.revokedDmv(byHash, MappedSourceValidationTest.members("certificates", null, "hashes",
                java.util.Arrays.asList(null, hash)));
        assertThat(h.getValue()).isNotEqualTo(Decision.TRUSTED);
        assertThat(h.getKey()).startsWith(MappedSourceRoundFiveTest.unreadable("identifiers.value", "$.hashes[0]"));
        // In a template of the roles, beside a role that is stated: not read as a role left out.
        var r = MappedSourceProbesTest.revokedDmv(Map.of("roles", List.of(Map.of("template", "{$.roles[0]}"), "CREDENTIAL_ISSUER")),
                MappedSourceValidationTest.members("roles", java.util.Arrays.asList(null, "VERIFIER")));
        assertThat(r.getKey()).startsWith(MappedSourceRoundFiveTest.unreadable("roles", "$.roles[0]"));
        // What the templates find is read; a list there and empty, or a member that is not there, states none.
        assertThat(MappedSourceProbesTest.revokedDmv(certificates, MappedSourceValidationTest.members("certificates", List.of(der("ds")))))
                .isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        assertThat(MappedSourceProbesTest.revokedDmv(byHash, MappedSourceValidationTest.members("certificates", null, "hashes", List.of(hash))))
                .isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        assertThat(MappedSourceProbesTest.revokedDmv(certificates, MappedSourceValidationTest.members("certificates", List.of())))
                .isEqualTo(Map.entry("loaded", Decision.TRUSTED));
        assertThat(MappedSourceProbesTest.revokedDmv(byHash, MappedSourceValidationTest.members("certificates", null)))
                .isEqualTo(Map.entry("loaded", Decision.TRUSTED));
    }

    // 7: two ids that differ only by a lone surrogate ------------------------------------------------------------------

    /** JSON with every character outside ASCII written as an escape, so that a lone surrogate reaches the parser. */
    static String ascii(String json) {
        StringBuilder b = new StringBuilder();
        for (char c : json.toCharArray()) {
            b.append(c > 0x7e ? String.format("\\u%04x", (int) c) : String.valueOf(c));
        }
        return b.toString();
    }

    static String sha256(byte... bytes) throws Exception {
        return "sha256:" + java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    @Test
    void item7_twoIdsThatDifferOnlyByALoneSurrogateStayTwoEntries() throws Exception {
        Map<String, Object> mapping = Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"], "certificates": "$.certificates[*]",
                   "authorizations": [{"each": "$.credentials[*]", "format": "$.format", "type": "$.type"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate"}]}""");
        // "A\ud800" pins ds-nl and may issue the mDL; "A\udc00" pins the DS and may issue the PID only.
        Map<String, Object> doc = Map.of("issuers", List.of(
                        Map.of("id", "A\uD800", "state", "active", "certificates", List.of(der("ds-nl")),
                                "credentials", List.of(Map.of("format", "mso_mdoc", "type", MDL))),
                        Map.of("id", "A\uDC00", "state", "active", "certificates", List.of(der("ds")),
                                "credentials", List.of(Map.of("format", "mso_mdoc", "type", MappedSourceValidationTest.PID))),
                        Map.of("id", "B\né", "state", "active")),
                "cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca"))));
        TestContext ctx = ctx();
        serveJson(ctx, ascii(Json.write(doc)));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", mapping)))) {
            assertThat(state(m, "partner").lastError()).isNull();
            // UTF-8 wrote both lone surrogates as '?': one derived id, one entry authorized for both, and the DS's mDL TRUSTED.
            String high = sha256((byte) 'A', (byte) 0xED, (byte) 0xA0, (byte) 0x80);
            String low = sha256((byte) 'A', (byte) 0xED, (byte) 0xB0, (byte) 0x80);
            // An id without a lone surrogate keeps the derived id it had: the SHA-256 of its UTF-8.
            String plain = sha256("B\né".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactlyInAnyOrder(high, low, plain);
            assertThat(registry.snapshot().entity(low).orElseThrow().authorizations()).extracting(a -> a.type())
                    .containsExactly(MappedSourceValidationTest.PID);
            assertThat(MappedSourceValidationTest.decide(registry, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).isEqualTo(Decision.TRUSTED);
        }
    }
}
