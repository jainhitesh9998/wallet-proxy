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

    @Test
    void item3_aBareCertificateCannotBeReadWhateverBase64LineStandsBesideIt() {
        Map<String, String> hidden = new LinkedHashMap<>();
        hidden.put("a block, the DS in lines of 64, then a line 'A'", block(derOf("ds-nl")) + bare("ds") + "A\n");
        hidden.put("a block, the DS in lines of 64, then a line 'Hello'", block(derOf("ds-nl")) + bare("ds") + "Hello\n");
        hidden.put("a block, a subject= line without spaces, then the DS in lines of 64", block(derOf("ds-nl"))
                + "subject=/C=UT/CN=Utopia-DS\n" + bare("ds"));
        hidden.forEach((what, text) -> {
            // Read as one with the line beside it, the run was no base64, or did not start with 0x30: passed over, the
            // revoked issuer was bound to ds-nl only, and the DS chain was trusted through the shared IACA.
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith(BARE);
        });
        // A withdrawn CA row written so is about the IACA, which row-1 lists active: the load fails, naming both. It was
        // read as ds-nl, an anchor of its own beside row-1, and the IACA was trusted.
        var tied = rows(block(derOf("ds-nl")) + bare("iaca") + "OK\n");
        try (TrustSourceManager m = tied.getValue()) {
            assertThat(state(m, "partner").lastError()).isEqualTo(sameCertificate("mdoc-iaca"));
            assertThat(MappedSourceValidationTest.decide(tied.getKey(), MDL)).isNotEqualTo(Decision.TRUSTED);
        }
    }

    @Test
    void item3_aLabelOfCapitalsThatDecodesTo0x30IsTextThatExplainsTheBlock() {
        for (String label : List.of("MASTER", "MAIN", "MOBILE", "MINISTRY", "MDL", "Master")) {
            // Its first byte 0x30, the label was read as a certificate without its armor: the honest list failed to load.
            assertThat(revokedWith(label + "\n" + MappedTesting.pem("ds"))).as(label).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
            var active = MappedSourceRoundFiveTest.withIaca(label + "\n" + MappedTesting.pem("iaca"));
            try (TrustSourceManager m = active.getValue()) {
                assertThat(state(m, "partner").warnings()).as(label).isEmpty();
                assertThat(active.getKey().snapshot().allAnchors()).as(label).extracting(a -> a.id())
                        .containsExactly("utopia-iaca", "rp-access-ca");
                assertThat(MappedSourceValidationTest.decide(active.getKey(), MDL)).as(label).isEqualTo(Decision.TRUSTED);
            }
        }
    }

    @Test
    void item3_textThatExplainsTheBlocksIsReadAndABareCertificateAloneOrAcrossABlankLineIsNot() {
        String ds = MappedTesting.pem("ds");
        Map<String, String> honest = new LinkedHashMap<>();
        honest.put("subject= and issuer= lines with spaces", "subject=C = UT, O = Utopia DMV, CN = Utopia DS\n"
                + "issuer=C = UT, O = Utopia DMV, CN = Utopia IACA\n" + ds);
        honest.put("Bag Attributes", "Bag Attributes\n    localKeyID: 01 00 00 00 \n    friendlyName: utopia-ds\n" + ds);
        honest.put("a byte-order mark", "\uFEFF" + ds);
        honest.put("CRLF line ends", ds.replace("\n", "\r\n") + "valid until 2046\r\n");
        honest.put("two good blocks", MappedTesting.pem("ds-nl") + ds);
        honest.forEach((what, text) -> assertThat(revokedWith(text)).as(what).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED)));
        String lines = bare("ds");
        int half = lines.indexOf('\n', lines.length() / 2) + 1;
        Map<String, String> hidden = new LinkedHashMap<>();
        hidden.put("the DS as one long line", block(derOf("ds-nl")) + der("ds") + "\n");
        hidden.put("the DS in lines of 64", block(derOf("ds-nl")) + lines);
        hidden.put("the DS in lines of 64, CRLF", (block(derOf("ds-nl")) + lines).replace("\n", "\r\n"));
        hidden.put("the DS in lines of 64 after another certificate so", block(derOf("ds-nl")) + bare("rp-ca") + lines);
        // Two runs of lines, neither a certificate by itself: the blank line does not part them.
        hidden.put("the DS in lines of 64, a blank line halfway", block(derOf("ds-nl")) + lines.substring(0, half) + "\n"
                + lines.substring(half));
        hidden.forEach((what, text) -> {
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith(BARE);
        });
    }

    static final String UNTRIED = "mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: a PEM text has lines of "
            + "base64 outside its certificate blocks that could start a certificate at more lines than can be tried";

    /** Lines of 64 characters, each the header of a SEQUENCE of 768 bytes (16 such lines) and zeros, {@code count} times. */
    static String headers(int count) {
        byte[] line = new byte[48];
        line[0] = 0x30;
        line[1] = (byte) 0x82;
        line[2] = 0x02;
        line[3] = (byte) 0xfc;
        return (Base64.getEncoder().encodeToString(line) + "\n").repeat(count);
    }

    @Test
    void item3_linesThatStartMoreRangesThanCanBeTriedCannotBeRead() {
        // Each line starts a range of 16 lines to try as a certificate: written so, the most a certificate text may hold
        // would cost the square of its length. Up to four times the value's characters are tried; beyond, it is refused.
        var r = revokedWith(block(derOf("ds-nl")) + headers(64));
        assertThat(r.getValue()).isNotEqualTo(Decision.TRUSTED);
        assertThat(r.getKey()).startsWith(UNTRIED);
        // A few such ranges are tried, and hold no certificate: text that explains the block.
        assertThat(revokedWith(block(derOf("ds")) + headers(17))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
    }

    // 3, after review: what a certificate text may cost, and certificates that end partway through a line --------------

    /** {@code head}, then {@code line} over and over with {@code between} after every hundred, up to 1,048,576 characters. */
    static String padded(String head, String line, String between) {
        StringBuilder b = new StringBuilder(head);
        for (int n = 1; b.length() + line.length() + between.length() <= 1_048_576; n++) {
            b.append(line);
            if (n % 100 == 0) {
                b.append(between);
            }
        }
        return b.toString();
    }

    @Test
    void item3_linesThatCallTheCertificateParserInVainOverAndOverCannotBeReadAndCostLittle() {
        // MAA is a SEQUENCE of two bytes: each line one call of the certificate parser, which costs far more than the
        // three characters it reads. Tried all, they loaded after seconds (and the revoked issuer, bound to ds-nl only,
        // was trusted through its DS). The tries are counted for the whole value, not for each run of lines.
        Map<String, String> texts = new LinkedHashMap<>();
        texts.put("MAA lines", padded(block(derOf("ds-nl")), "MAA\n", ""));
        texts.put("MAA lines, CRLF", padded(block(derOf("ds-nl")).replace("\n", "\r\n"), "MAA\r\n", ""));
        texts.put("MAA lines, a line of other text after every hundred", padded(block(derOf("ds-nl")), "MAA\n", "page break\n"));
        texts.forEach((what, text) -> {
            assertThat(text.length()).as(what).isBetween(1_048_000, 1_048_576);
            long began = System.nanoTime();
            var r = revokedWith(text);
            long took = (System.nanoTime() - began) / 1_000_000;
            // Only the cap of failed parser calls refuses these lines: they hold no certificate, and the characters the
            // tries read stay far below four times the value's length.
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith(UNTRIED);
            // Not a measure of speed (that depends on the machine): a guard against seconds per value coming back.
            assertThat(took).as(what + ": milliseconds to load and decide").isLessThan(10_000);
        });
    }

    /** {@code count} certificates in blocks, ds-nl and the DS in turn, each after a line that holds {@code label}. */
    static String bundle(String label, int count) {
        StringBuilder b = new StringBuilder();
        for (int n = 0; n < count; n++) {
            b.append(label).append('\n').append(MappedTesting.pem(n % 2 == 0 ? "ds-nl" : "ds"));
        }
        return b.toString();
    }

    @Test
    void item3_aBundleWithTheSameLabelBeforeEachCertificateLoadsUpToTheCapOfTries() {
        // Blocks do not end a run: the labels are one run, and each states a SEQUENCE that ends inside it, one try each.
        // Budgeted on the labels' own characters, not the value's, a bundle labelled MDL was refused from 30 certificates.
        Map<String, Integer> bundles = new LinkedHashMap<>();
        for (int count : List.of(30, 100, 1000)) {
            bundles.put("MDL x " + count, count);
        }
        for (String label : List.of("MDOC", "MEDICAL", "MIGRATED")) {
            bundles.put(label + " x 1000", 1000);
        }
        bundles.forEach((what, count) -> assertThat(revokedWith(bundle(what.substring(0, what.indexOf(' ')), count))).as(what)
                .isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED)));
        // Past the cap of failed parser calls, the value cannot be read.
        var r = revokedWith(bundle("MDL", 1100));
        assertThat(r.getValue()).isNotEqualTo(Decision.TRUSTED);
        assertThat(r.getKey()).startsWith(UNTRIED);
    }

    /** DER certificates (or bytes) one after the other, as one stream of base64 in lines of 64 characters. */
    static String joined(byte[]... ders) {
        java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
        for (byte[] d : ders) {
            all.writeBytes(d);
        }
        return Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(all.toByteArray()) + "\n";
    }

    @Test
    void item3_aBareCertificateThatEndsPartwayThroughALineCannotBeRead() {
        Map<String, String> hidden = new LinkedHashMap<>();
        // The first certificate ends partway through a line: its range was not tried, and the stream was passed over.
        hidden.put("a block, then the RP CA and the DS as one stream", block(derOf("ds-nl")) + joined(derOf("rp-ca"), derOf("ds")));
        hidden.put("a block, then the DS and other bytes as one stream", block(derOf("ds-nl")) + joined(derOf("ds"), new byte[10]));
        String lines = bare("ds");
        hidden.put("a block, then the DS with characters after its last line", block(derOf("ds-nl"))
                + lines.substring(0, lines.length() - 1) + "AAAA\n");
        hidden.forEach((what, text) -> {
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith(BARE);
        });
        // A withdrawn CA row written so is about the IACA, first in the stream or after another certificate: the load
        // fails, naming both rows. It was read as ds-nl, and the IACA was trusted through row-1.
        for (String text : List.of(block(derOf("ds-nl")) + joined(derOf("iaca"), derOf("rp-ca")),
                block(derOf("ds-nl")) + joined(derOf("rp-ca"), derOf("iaca")))) {
            var tied = rows(text);
            try (TrustSourceManager m = tied.getValue()) {
                assertThat(state(m, "partner").lastError()).isEqualTo(sameCertificate("mdoc-iaca"));
                assertThat(MappedSourceValidationTest.decide(tied.getKey(), MDL)).isNotEqualTo(Decision.TRUSTED);
            }
        }
    }

    @Test
    void item3_textBesideTheBlocksThatHoldsNoCertificateIsPassedOver() throws Exception {
        java.security.cert.X509Certificate ds = io.vctrust.trust.core.x509.Certificates.fromDer(derOf("ds"));
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(derOf("ds"));
        String hex = java.util.HexFormat.of().formatHex(hash);
        byte[] key = ds.getPublicKey().getEncoded();
        byte[] noise = new byte[225];
        new java.util.Random(20261112).nextBytes(noise);
        Map<String, String> honest = new LinkedHashMap<>();
        honest.put("labels of capitals", "MASTER\nMAIN\nMOBILE\nMINISTRY\nMDL\n");
        honest.put("a SHA-256 in base64", Base64.getEncoder().encodeToString(hash) + "\n");
        honest.put("a SHA-256 in base64url", Base64.getUrlEncoder().withoutPadding().encodeToString(hash) + "\n");
        honest.put("a SHA-256 in hex", hex + "\n" + hex.toUpperCase(java.util.Locale.ROOT) + "\n");
        honest.put("a fingerprint with colons", "SHA256 Fingerprint=" + java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(hash) + "\n");
        honest.put("serial numbers", ds.getSerialNumber().toString(16) + "\n" + ds.getSerialNumber() + "\nserial="
                + ds.getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT) + "\n");
        honest.put("a bare public key on one line", Base64.getEncoder().encodeToString(key) + "\n");
        honest.put("a bare public key in lines of 64", Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key) + "\n");
        honest.put("a line of 300 random base64 characters", Base64.getEncoder().encodeToString(noise) + "\n");
        honest.forEach((what, text) -> {
            assertThat(revokedWith(text + MappedTesting.pem("ds"))).as(what).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
            assertThat(revokedWith(MappedTesting.pem("ds") + text)).as(what + ", after the block")
                    .isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        });
    }

    static final String UNTRIED_ROW = "Record 2 of mapping.anchors[0] (id 'row-7') cannot be read, nor can its certificate text be read "
            + "completely: which certificate it is about cannot be told";

    @Test
    void item3_aSkippedCaRowWhoseTextCouldNotBeTriedCompletelyFailsTheLoad() {
        // Lines that use up the tries before the IACA: the row was skipped, the IACA never compared with row-1, and trusted.
        for (String padding : List.of(headers(64), "MAA\n".repeat(1100))) {
            var tied = rows(block(derOf("ds-nl")) + padding + bare("iaca"));
            try (TrustSourceManager m = tied.getValue()) {
                assertThat(state(m, "partner").lastError()).isEqualTo(UNTRIED_ROW);
                assertThat(MappedSourceValidationTest.decide(tied.getKey(), MDL)).isNotEqualTo(Decision.TRUSTED);
            }
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
