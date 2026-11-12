package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedSourceRulesTest.ctx;
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
 * What a fifth validation of the mapped source found, each reproduced, and decided by the evaluator where a decision is
 * at stake. In a registry where a valid chain to a listed CA is trusted by itself, an entity entry is what restricts a
 * party: an entity record is listed as the document states it, listed as not in good standing, or the load fails; and a
 * party is listed under the name the other sources of its framework know it by.
 */
@SuppressWarnings("unchecked")
class MappedSourceRoundFiveTest {

    /** A decision about an issuer, with the source manager at hand for an on-demand lookup. */
    static TrustDecision decide(TrustRegistry registry, TrustSourceManager sources, String identifier, List<String> x5c, String type) {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(),
                Duration.ofHours(1)).evaluate(MappedSourceFixturesTest.issuer(identifier, x5c, x5c.isEmpty() ? null : "mso_mdoc", type),
                MappedSourceFixturesTest.CLIENT);
    }

    // 1: an id is kept as written whenever an entry can carry it ---------------------------------------------------------

    /** Ids as other sources write them: a URL, a name with a space. */
    static final List<String> IDS = List.of("https://dmv.utopia.example", "Utopia DMV");

    /** The operator's own static registry of the framework: the DMV withdrawn, under {@code id}. */
    static TrustSource withdrawnByTheOperator(TestContext ctx, String id) {
        ctx.put("mem:own.yaml", "entities:\n  - id: " + Json.write(id) + "\n    roles: [CREDENTIAL_ISSUER]\n    status: REVOKED\n");
        return new StaticTrustSourceFactory().create(new SourceDefinition("own", "static", "partner", null, true,
                Map.of("location", "mem:own.yaml")), ctx);
    }

    @Test
    void item1_aMappedCaIsTiedToTheEntityAnotherSourceListsUnderTheIdAsWritten() {
        for (boolean constant : List.of(false, true)) {
            for (String id : IDS) {
                Map<String, Object> mapping = Json.parseObject("""
                        {"anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate",
                           "entity": "$.issuer_id"}]}""");
                if (constant) {
                    ((Map<String, Object>) ((List<?>) mapping.get("anchors")).getFirst()).put("entity", id);
                }
                String as = id + (constant ? ", by a constant" : ", by $.issuer_id");
                TestContext ctx = ctx();
                TrustSource own = withdrawnByTheOperator(ctx, id);
                serveJson(ctx, Map.of("cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca"), "issuer_id", id))));
                TrustRegistry registry = new TrustRegistry();
                try (TrustSourceManager m = manager(registry, own, source(ctx, props("mapping", mapping)))) {
                    assertThat(state(m, "partner").lastError()).as(as).isNull();
                    assertThat(state(m, "partner").warnings()).as(as).isEmpty();
                    assertThat(registry.snapshot().allAnchors()).as(as).singleElement()
                            .satisfies(a -> assertThat(a.entityId()).isEqualTo(id));
                    // Tied to sha256:..., the CA named nobody, and the chain to it decided alone: TRUSTED.
                    TrustDecision d = decide(registry, m, null, List.of(der("ds")), MDL);
                    assertThat(d.decision()).as(as).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(d.summary()).as(as).isEqualTo("Entity '" + id + "' is REVOKED");
                }
            }
        }
    }

    @Test
    void item1_aMappedPartyAndAnotherSourcesEntryOfItsIdAreOneEntry() {
        Map<String, Object> mapping = Json.parseObject("""
                {"entities": [{"each": "$.issuers[*]", "id": "$.id", "roles": ["CREDENTIAL_ISSUER"], "certificates": "$.certificates[*]",
                   "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"}}],
                 "anchors": [{"each": "$.cas[*]", "id": "$.kid", "domain": "mdoc-iaca", "certificate": "$.certificate"}]}""");
        for (String id : IDS) {
            TestContext ctx = ctx();
            TrustSource own = withdrawnByTheOperator(ctx, id);
            serveJson(ctx, Map.of("issuers", List.of(Map.of("id", id, "state", "active", "certificates", List.of(der("ds"))),
                            Map.of("id", "college", "state", "active")),
                    "cas", List.of(Map.of("kid", "utopia-iaca", "certificate", der("iaca")))));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, own, source(ctx, props("mapping", mapping)))) {
                assertThat(state(m, "partner").warnings()).as(id).isEmpty();
                assertThat(registry.snapshot().entities()).as(id).extracting(e -> e.id() + " " + e.status())
                        .containsExactlyInAnyOrder(id + " REVOKED", "college ACTIVE");
                TrustedEntity one = registry.snapshot().entity(id).orElseThrow();
                assertThat(one.certificates()).as(id).hasSize(1);
                assertThat(one.attributes()).as(id).containsEntry("mergedFrom", List.of("own", "partner"));
                // Two entries before: the mapped one, under sha256:..., active and bound to the DS certificate: TRUSTED.
                TrustDecision d = decide(registry, m, null, List.of(der("ds")), MDL);
                assertThat(d.decision()).as(id).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.summary()).as(id).isEqualTo("Entity '" + id + "' is REVOKED");
            }
        }
    }

    /** The warning of a load that replaced one id: {@code quoted} is the first as a message quotes it. */
    static String replacedOne(String quoted, String derived) {
        return "1 id is listed under derived ids (sha256: and the SHA-256 of the id written), not being 1 to 512 characters free "
                + "of control, format and separator characters: the first, " + quoted + ", as '" + derived + "'";
    }

    @Test
    void item1_anIdAnEntryCannotCarryIsReplacedForTheEntityAndTheAnchorTieAlike() {
        Map<String, String> replaced = new LinkedHashMap<>();
        replaced.put("Utopia\nDMV", "'Utopia\\nDMV'");
        replaced.put("\u202EUtopia DMV", "'\\u202eUtopia DMV'");
        replaced.put("d".repeat(513), "'" + "d".repeat(40) + "…'");
        replaced.put(" ", "' '");   // blank: the registry format reads a blank id as none
        replaced.forEach((id, quoted) -> {
            String as = quoted;
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceProbesTest.tied(id, Map.of("state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
                String derived = MappedSourceProbesTest.derived(id);
                assertThat(state(m, "partner").lastError()).as(as).isNull();
                assertThat(registry.snapshot().entity(derived).orElseThrow().status()).as(as).isEqualTo(EntityStatus.REVOKED);
                assertThat(registry.snapshot().allAnchors()).as(as).singleElement()
                        .satisfies(a -> assertThat(a.entityId()).isEqualTo(derived));
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(as).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(state(m, "partner").warnings()).as(as).containsExactly(replacedOne(quoted, derived));
            }
        });
        // Half of a surrogate pair that stands alone (written as an escape in the JSON): replaced too.
        TestContext lone = ctx();
        serveJson(lone, Json.write(MappedSourceProbesTest.tied("dmv", Map.of("state", "revoked"))).replace("\"dmv\"", "\"\\ud800dmv\""));
        TrustRegistry r = new TrustRegistry();
        try (TrustSourceManager m = manager(r, source(lone, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
            String derived = MappedSourceProbesTest.derived("\ud800dmv");
            assertThat(r.snapshot().entity(derived)).isPresent();
            assertThat(r.snapshot().allAnchors()).singleElement().satisfies(a -> assertThat(a.entityId()).isEqualTo(derived));
            assertThat(MappedSourceValidationTest.decide(r, MDL)).isEqualTo(Decision.NOT_TRUSTED);
        }
        // Plain text of up to 512 characters is kept exactly as written: a DID with %3A, a name outside ASCII, an email
        // address, a base64 key identifier, text that only looks like a URL with a query, a name with spaces around it.
        for (String id : List.of("d".repeat(512), "did:web:x%3A8443", "名前", "issuer@example.com", "q83vEjRWeJ+/kQ==", " Utopia DMV ")) {
            TestContext ctx = ctx();
            serveJson(ctx, MappedSourceProbesTest.tied(id, Map.of("state", "revoked")));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", MappedSourceProbesTest.tiedByTheCa())))) {
                assertThat(state(m, "partner").warnings()).as(id).isEmpty();
                assertThat(registry.snapshot().entity(id).orElseThrow().status()).as(id).isEqualTo(EntityStatus.REVOKED);
                assertThat(registry.snapshot().allAnchors()).as(id).singleElement().satisfies(a -> assertThat(a.entityId()).isEqualTo(id));
                assertThat(MappedSourceValidationTest.decide(registry, MDL)).as(id).isEqualTo(Decision.NOT_TRUSTED);
            }
        }
        // A message quotes an id as it quotes any text of the document, whatever the id: escaped, and cut at 40
        // characters. (It named the record by its number alone when the id broke the admin API's rule.)
        TestContext ctx = ctx();
        String url = "https://dmv.utopia.example/";
        Map<String, String> quotedAs = Map.of("Utopia\nDMV\u202E", "'Utopia\\nDMV\\u202e'", url + "d".repeat(100),
                "'" + url + "d".repeat(40 - url.length()) + "…'");
        quotedAs.forEach((id, quoted) -> {
            // Certificates written as one text, not a list: the record cannot be read before its id is given.
            serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("id", id, "certificates", der("ds"))));
            assertThat(loadError(source(ctx, props("mapping", MappedSourceRegistryTest.idsAsWritten())))).as(quoted)
                    .startsWith("mapping.entities[0]: record 1 (id " + quoted + ") cannot be read: certificates: the path "
                            + "$.certificates[*] finds text where [*] needs a list or an object");
        });
    }

    // 2: allowAnyType with a default on the type ----------------------------------------------------------------------

    /** The DS issuer authorized by {@code credentials} as {@code item} reads them, each credential of mso_mdoc without a type. */
    static TrustSourceManager authorizedBy(TrustRegistry registry, Map<String, Object> item) {
        TestContext ctx = ctx();
        serveJson(ctx, MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("credentials",
                List.of(Map.of("format", "mso_mdoc")))));
        return manager(registry, source(ctx, props("mapping", MappedSourceValidationTest.withAuthorizations(item))));
    }

    static Map<String, Object> typeItem(Object allowAnyType, Object type) {
        Map<String, Object> item = new LinkedHashMap<>(Map.of("each", "$.credentials[*]", "format", "$.format", "type", type));
        if (allowAnyType != null) {
            item.put("allowAnyType", allowAnyType);
        }
        return item;
    }

    @Test
    void item2_allowAnyTypeAndADefaultOnTheTypeAreAConfigurationError() {
        Map<String, Object> withDefault = Map.of("path", "$.type", "values", Map.of("mdl", MDL), "default", "none.at.all");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = authorizedBy(registry, typeItem(true, withDefault))) {
            // The default was ignored: the issuer was authorized for every type of mso_mdoc, and its PID was TRUSTED.
            assertThat(state(m, "partner").lastError()).isEqualTo("Source 'partner' (mapped): mapping.entities[0].authorizations[0]: "
                    + "allowAnyType and a default on type contradict each other: an item that states no type would get the default "
                    + "under one and cover every type of its format under the other; remove one");
            assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).isNotEqualTo(Decision.TRUSTED);
        }
        // Either alone reads as it did: the default (allowAnyType false or not said) authorizes the type it names;
        // allowAnyType without a default authorizes every type of the format.
        for (Object allowAnyType : java.util.Arrays.asList(false, null)) {
            TrustRegistry r = new TrustRegistry();
            try (TrustSourceManager m = authorizedBy(r, typeItem(allowAnyType, withDefault))) {
                assertThat(state(m, "partner").lastError()).as(String.valueOf(allowAnyType)).isNull();
                assertThat(r.snapshot().entity("partner:dmv").orElseThrow().authorizations()).as(String.valueOf(allowAnyType))
                        .singleElement().satisfies(a -> assertThat(a.type()).isEqualTo("none.at.all"));
                assertThat(MappedSourceValidationTest.decide(r, MappedSourceValidationTest.PID)).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(MappedSourceValidationTest.decide(r, MDL)).isEqualTo(Decision.NOT_TRUSTED);
            }
        }
        TrustRegistry any = new TrustRegistry();
        try (TrustSourceManager m = authorizedBy(any, typeItem(true, Map.of("path", "$.type", "values", Map.of("mdl", MDL))))) {
            assertThat(state(m, "partner").lastError()).isNull();
            assertThat(MappedSourceValidationTest.decide(any, MappedSourceValidationTest.PID)).isEqualTo(Decision.TRUSTED);
        }
    }

    // 3: a PEM block is one certificate, and text that explains the blocks is passed over ----------------------------

    /** One PEM block whose body is these DER bytes, one after the other. */
    static String block(byte[]... ders) {
        java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
        for (byte[] d : ders) {
            all.writeBytes(d);
        }
        return "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(all.toByteArray())
                + "\n-----END CERTIFICATE-----\n";
    }

    static byte[] derOf(String name) {
        return java.util.Base64.getDecoder().decode(der(name));
    }

    /** The decision about the DS certificate's mDL, the issuer revoked and its certificates written as {@code text}. */
    static Map.Entry<String, Decision> revokedWith(String text) {
        return MappedSourceProbesTest.revokedDmv(Map.of(), MappedSourceValidationTest.members("certificates", List.of(text)));
    }

    /** The DMV's IACA, written as {@code text}, and a CA of verifiers beside it; the DMV active. */
    static Map.Entry<TrustRegistry, TrustSourceManager> withIaca(String text) {
        Map<String, Object> d = MappedSourceProbesTest.tied("dmv", Map.of());
        d.put("cas", List.of(Map.of("kid", "utopia-iaca", "certificate", text, "issuer_id", "dmv"),
                Map.of("kid", "rp-access-ca", "certificate", der("rp-ca"))));
        TestContext ctx = ctx();
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        return Map.entry(registry, manager(registry, source(ctx, props("mapping", MappedSourceProbesTest.tiedByTheCa()))));
    }

    @Test
    void item3_aPemBlockIsOneCertificate() {
        Map<String, String> hidden = new LinkedHashMap<>();
        hidden.put("one block, two certificates", block(derOf("ds-nl"), derOf("ds")));
        hidden.put("one block, a certificate and other bytes", block(derOf("ds-nl"), new byte[100]));
        hidden.forEach((what, text) -> {
            // Read as its first certificate: the revoked issuer was bound to ds-nl only, and the DS chain decided: TRUSTED.
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: a "
                    + "PEM block holds more than one certificate, or something after it; a PEM block is one certificate");
        });
        // A block of one certificate, and two blocks: read.
        assertThat(revokedWith(block(derOf("ds")))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        assertThat(revokedWith(block(derOf("ds-nl")) + block(derOf("ds")))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        // An anchor's certificate likewise: the record is skipped (it was placed as the IACA, its first certificate).
        var tied = withIaca(block(derOf("iaca"), derOf("rp-ca")));
        try (TrustSourceManager m = tied.getValue()) {
            assertThat(tied.getKey().snapshot().allAnchors()).extracting(a -> a.id()).containsExactly("rp-access-ca");
            assertThat(state(m, "partner").warnings()).singleElement().asString().startsWith("mapping.anchors[0]: record 1 (id 'utopia-iaca') "
                    + "is skipped: certificate: a PEM block holds more than one certificate");
            assertThat(MappedSourceValidationTest.decide(tied.getKey(), MDL)).isNotEqualTo(Decision.TRUSTED);
        }
    }

    @Test
    void item3_textThatExplainsTheBlocksIsPassedOverAndALineWithAnArmorCannotBeRead() {
        String ds = MappedTesting.pem("ds");
        Map<String, String> honest = new LinkedHashMap<>();
        honest.put("subject= and issuer= lines", "subject=C = UT, O = Utopia DMV, CN = Utopia DS\nissuer=C = UT, O = Utopia DMV, "
                + "CN = Utopia IACA\n" + ds);
        honest.put("Bag Attributes", "Bag Attributes\n    localKeyID: 01 00 00 00 \n    friendlyName: utopia-ds\n"
                + "subject=/C=UT/O=Utopia DMV/CN=Utopia DS\nissuer=/C=UT/O=Utopia DMV/CN=Utopia IACA\n" + ds
                + "Bag Attributes: <No Attributes>\nsubject=/C=UT/O=Utopia DMV/CN=Utopia DS NL\n" + MappedTesting.pem("ds-nl"));
        honest.put("a byte-order mark", "\uFEFF" + ds);
        honest.put("CRLF line ends and a line after the block", ds.replace("\n", "\r\n") + "valid until 2046\r\n");
        honest.forEach((what, text) -> {
            // The whole load failed: "a PEM text holds something besides certificate blocks and white space".
            assertThat(revokedWith(text)).as(what).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        });
        var tied = withIaca("subject=C = UT, O = Utopia DMV, CN = Utopia IACA\n" + MappedTesting.pem("iaca"));
        try (TrustSourceManager m = tied.getValue()) {
            assertThat(state(m, "partner").warnings()).isEmpty();
            assertThat(tied.getKey().snapshot().allAnchors()).extracting(a -> a.id()).containsExactly("utopia-iaca", "rp-access-ca");
            assertThat(MappedSourceValidationTest.decide(tied.getKey(), MDL)).isEqualTo(Decision.TRUSTED);
        }
        // A line that holds ----- outside the blocks is a damaged armor line, or a block of something else: unreadable.
        String nl = MappedTesting.pem("ds-nl");
        Map<String, String> damaged = new LinkedHashMap<>();
        damaged.put("a BEGIN line with four dashes", ds.replace("-----BEGIN", "----BEGIN") + nl);
        damaged.put("a BEGIN line in lower case", ds.replace("BEGIN CERTIFICATE", "begin certificate") + nl);
        damaged.put("a block that never ends", nl + ds.substring(0, ds.indexOf("-----END")));
        damaged.put("a block of a key", nl + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        damaged.put("a TRUSTED CERTIFICATE block", ds.replace("CERTIFICATE", "TRUSTED CERTIFICATE") + nl);
        damaged.put("an END line alone", "-----END CERTIFICATE-----\n" + der("ds"));
        damaged.forEach((what, text) -> {
            var r = revokedWith(text);
            assertThat(r.getValue()).as(what).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(what).startsWith("mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: certificates: a "
                    + "PEM text has a line with ----- outside its certificate blocks");
        });
    }

    // 4: a list that says whom a record is about, there with items, yields something ---------------------------------

    static final String YIELDS_NOTHING = " finds a list that holds items and yields nothing from them (a filter keeps none of them, "
            + "they hold null or \"\", or an index selects none of them); what says whom a record is about is not read as none "
            + "stated then";

    /** The revoked issuer, with {@code block} put over its block and {@code member} set to {@code value}. */
    static Map.Entry<String, Decision> revoked(Map<String, Object> block, String member, Object value) {
        return MappedSourceProbesTest.revokedDmv(block, MappedSourceValidationTest.members(member, value));
    }

    static String unreadable(String member, String path) {
        return "mapping.entities[0]: record 1 (id 'partner:dmv') cannot be read: " + member + ": " + path + YIELDS_NOTHING;
    }

    @Test
    void item4_certificatesThereWithItemsMustYieldOne() {
        String sig = "$.certificates[?@.use == 'sig'].pem";
        Map<String, Object> filtered = Map.of("certificates", sig);
        record Case(Map<String, Object> block, String path, Object certificates) {
        }
        List<Case> nothing = List.of(
                new Case(filtered, sig, List.of(Map.of("usage", "sig", "pem", der("ds")))),
                new Case(filtered, sig, List.of(Map.of("use", "SIG", "pem", der("ds")))),
                new Case(filtered, sig, List.of(Map.of("use", "enc", "pem", der("ds")))),
                new Case(Map.of(), "$.certificates[*]", java.util.Collections.singletonList(null)),
                new Case(Map.of(), "$.certificates[*]", List.of("")),
                new Case(Map.of("certificates", "$.certificates[0]"), "$.certificates[0]", java.util.Arrays.asList(null, der("ds"))),
                new Case(Map.of("certificates", "$.certificates[1]"), "$.certificates[1]", List.of(der("ds"))));
        for (Case c : nothing) {
            // Listed revoked with no certificate and no warning, and the DS chain decided alone: TRUSTED.
            var r = revoked(c.block(), "certificates", c.certificates());
            assertThat(r.getValue()).as(c.toString()).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(c.toString()).startsWith(unreadable("certificates", c.path()));
        }
        // There and empty states none; an item that passes is read, the others left as the filter says.
        assertThat(revoked(filtered, "certificates", List.of())).isEqualTo(Map.entry("loaded", Decision.TRUSTED));
        assertThat(revoked(Map.of("certificates", "$.certificates[0]"), "certificates", List.of())).isEqualTo(Map.entry("loaded",
                Decision.TRUSTED));
        assertThat(revoked(filtered, "certificates", List.of(Map.of("use", "enc", "pem", der("ds-nl")), Map.of("use", "sig", "pem",
                der("ds"))))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        assertThat(revoked(Map.of(), "certificates", java.util.Arrays.asList(null, der("ds")))).isEqualTo(Map.entry("loaded",
                Decision.NOT_TRUSTED));
    }

    /** The revoked issuer bound by nothing but the subject of its DS certificate, through {@code identifiers}. */
    static Map.Entry<String, Decision> bySubject(Map<String, Object> item, Object names) {
        Map<String, Object> block = Map.of("identifiers", List.of(item));
        return MappedSourceProbesTest.revokedDmv(block, MappedSourceValidationTest.members("certificates", null, "names", names));
    }

    static final String DS_SUBJECT = "CN=Utopia DS,O=Utopia DMV,C=UT";

    @Test
    void item4_identifiersThereWithItemsMustYieldOne() {
        String kind = "$.names[?@.kind == 'subject']";
        Map<String, Object> filtered = Map.of("each", kind, "type", "X509_SUBJECT", "value", "$.value");
        for (Object names : List.of(List.of(Map.of("kind", "SUBJECT", "value", DS_SUBJECT)), List.of(Map.of("type", "subject",
                "value", DS_SUBJECT)), java.util.Collections.singletonList(null))) {
            // No identifier, no warning, and the DS chain decided alone: TRUSTED.
            var r = bySubject(filtered, names);
            assertThat(r.getValue()).as(String.valueOf(names)).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(String.valueOf(names)).startsWith(unreadable("identifiers", kind));
        }
        assertThat(bySubject(filtered, List.of(Map.of("kind", "subject", "value", DS_SUBJECT)))).isEqualTo(Map.entry("loaded",
                Decision.NOT_TRUSTED));
        assertThat(bySubject(filtered, List.of())).isEqualTo(Map.entry("loaded", Decision.TRUSTED));
        // The path of an item's member: an index that selects null, or nothing, from a list with items.
        Map<String, Object> indexed = Map.of("type", "X509_SUBJECT", "value", "$.names[0]");
        for (Object names : List.of(java.util.Arrays.asList(null, DS_SUBJECT), List.of(""))) {
            var r = bySubject(indexed, names);
            assertThat(r.getValue()).as(String.valueOf(names)).isNotEqualTo(Decision.TRUSTED);
            assertThat(r.getKey()).as(String.valueOf(names)).startsWith(unreadable("identifiers.value", "$.names[0]"));
        }
        assertThat(bySubject(indexed, List.of(DS_SUBJECT))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
        assertThat(bySubject(indexed, List.of())).isEqualTo(Map.entry("loaded", Decision.TRUSTED));
    }

    @Test
    void item4_rolesThereWithItemsMustYieldOneUnderAllowEmptyToo() {
        // The DMV active and authorized for the mDL only, asked about the PID; the college's roles read by the same path.
        String active = "$.roles[?@.active == true].name";
        for (Object roles : List.of(java.util.Collections.singletonList(null), List.of(Map.of("name", "CREDENTIAL_ISSUER", "aktiv", true)))) {
            Map<String, Object> m = MappedSourceValidationTest.boundMapping();
            ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).put("roles", Map.of("path", active, "allowEmpty", true));
            Map<String, Object> d = MappedSourceValidationTest.boundList(1, MappedSourceValidationTest.members("roles", roles));
            List<Object> issuers = new java.util.ArrayList<>((List<Object>) d.get("issuers"));
            Map<String, Object> college = new LinkedHashMap<>((Map<String, Object>) issuers.get(1));
            college.put("roles", List.of(Map.of("name", "CREDENTIAL_ISSUER", "active", true)));
            issuers.set(1, college);
            d.put("issuers", issuers);
            TestContext ctx = ctx();
            serveJson(ctx, d);
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
                // Listed ACTIVE without a role ("none stated"): not considered, and the chain decided the PID: TRUSTED.
                assertThat(MappedSourceValidationTest.decide(registry, MappedSourceValidationTest.PID)).as(String.valueOf(roles))
                        .isNotEqualTo(Decision.TRUSTED);
                assertThat(state(manager, "partner").lastError()).as(String.valueOf(roles)).startsWith(roles.equals(
                        java.util.Collections.singletonList(null)) ? unreadable("roles", active) : "mapping.entities[0]: record 1 (id "
                        + "'partner:dmv') cannot be read: roles: " + active + " finds a list but nothing it holds");
            }
        }
        // An index past the end of a list with items, beside a form that yields a role: not "none" either.
        Map<String, Object> both = Map.of("roles", List.of("CREDENTIAL_ISSUER", "$.roles[1]"));
        var r = revoked(both, "roles", List.of("VERIFIER"));
        assertThat(r.getValue()).isNotEqualTo(Decision.TRUSTED);
        assertThat(r.getKey()).startsWith(unreadable("roles", "$.roles[1]"));
        assertThat(revoked(both, "roles", List.of("VERIFIER", "VERIFIER"))).isEqualTo(Map.entry("loaded", Decision.NOT_TRUSTED));
    }

    // 5: how many times the bytes read a load may yield is the operator's to set ----------------------------------------

    /** A list of {@code n} terse issuers (an id and a URL each), and {@code more} members at its root. */
    static String terse(int n, String more) {
        StringBuilder b = new StringBuilder("{\"issuers\":[");
        for (int i = 0; i < n; i++) {
            b.append(i == 0 ? "" : ",").append("{\"id\":\"p").append(i).append("\",\"u\":\"https://p").append(i).append(".example\"}");
        }
        return b.append("]").append(more).append("}").toString();
    }

    static Map<String, Object> terseMapping(Object authorizations) {
        Map<String, Object> block = new LinkedHashMap<>(Map.of("each", "$.issuers[*]", "id", "$.id", "roles", List.of("CREDENTIAL_ISSUER"),
                "identifiers", List.of(Map.of("type", "URL", "value", "$.u"))));
        block.put("authorizations", authorizations);
        return new LinkedHashMap<>(Map.of("entities", List.of(block)));
    }

    /** {@code n} credential types, stated once at the root of a list. */
    static String sharedTypes(int n) {
        StringBuilder b = new StringBuilder(",\"credential_types\":[");
        for (int i = 0; i < n; i++) {
            b.append(i == 0 ? "" : ",").append("\"org.example.credential.type.number.").append(i).append('"');
        }
        return b.append(']').toString();
    }

    static final Object EACH_SHARED_TYPE = List.of(Map.of("each", "^.credential_types[*]", "format", "mso_mdoc", "type", "$"));

    static String refused(String document, int factor) {
        return "The list's records yield more than " + factor + " times the " + document.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                + " bytes read (limits.yield, which may be raised up to 1024; at least 1048576 is always allowed)";
    }

    @Test
    void item5_anHonestListThatStatesOnceWhatEachRecordRepeatsLoadsWithLimitsYield() throws Exception {
        // 3,000 issuers, each of which may issue the 30 types the list states once at its root.
        String shared = terse(3_000, sharedTypes(30));
        TestContext ctx = ctx();
        serveJson(ctx, shared);
        assertThat(loadError(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE))))).isEqualTo(refused(shared, 32));
        var loaded = source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", 64))).load();
        assertThat(loaded.entities()).hasSize(3_000).allSatisfy(e -> assertThat(e.authorizations()).hasSize(30));
        // 3,000 issuers and 40 authorizations the mapping gives each of them; the factor as Spring hands it over, as text.
        List<Object> constants = new java.util.ArrayList<>();
        for (int i = 0; i < 40; i++) {
            constants.add(Map.of("format", "mso_mdoc", "type", "org.example.credential.type.number." + i));
        }
        String bare = terse(3_000, "");
        serveJson(ctx, bare);
        assertThat(loadError(source(ctx, props("mapping", terseMapping(constants))))).isEqualTo(refused(bare, 32));
        assertThat(source(ctx, props("mapping", terseMapping(constants), "limits", Map.of("yield", "64"))).load().entities())
                .hasSize(3_000).allSatisfy(e -> assertThat(e.authorizations()).hasSize(40));
    }

    @Test
    void item5_limitsYieldIsAWholeNumberFrom1To1024AndTheFloorAndLimitsTextStay() throws Exception {
        TestContext ctx = ctx();
        String ten = terse(3_000, sharedTypes(10));
        serveJson(ctx, ten);
        for (Object factor : java.util.Arrays.asList(0, -1, 1_025, "x", 1.5, "", List.of(32))) {
            assertThat(loadError(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", factor)))))
                    .as(String.valueOf(factor)).isEqualTo("Source 'partner' (mapped): limits.yield must be a whole number from 1 to 1024: "
                            + "how many times the bytes it read a load may yield");
        }
        // Ten shared types load at the default and at 1,024; at 1 the factor holds them to the bytes read.
        assertThat(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE))).load().entities()).hasSize(3_000);
        assertThat(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", 1_024))).load().entities())
                .hasSize(3_000);
        assertThat(loadError(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", 1)))))
                .isEqualTo(refused(ten, 1));
        // The floor stays: a small list may yield a mebibyte whatever the factor; and limits.text stays a bound on top.
        serveJson(ctx, terse(10, sharedTypes(10)));
        assertThat(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", 1))).load().entities()).hasSize(10);
        serveJson(ctx, ten);
        assertThat(loadError(source(ctx, props("mapping", terseMapping(EACH_SHARED_TYPE), "limits", Map.of("yield", 1_024, "text",
                1_000_000))))).contains("yield more than 1000000 characters and nodes of mapped text (limits.text)");
    }

    // 6: a lookup answer for an id the loaded list holds ------------------------------------------------------------------

    /** The issuers tied to their CA, and a lookup by URL whose answer is mapped as a list's record is. */
    static Map<String, Object> withLookup() {
        Map<String, Object> m = MappedSourceProbesTest.tiedByTheCa();
        m.put("list", Map.of("sequence", "$.version"));
        m.put("lookup", Json.parseObject("""
                {"url": "https://registry.partner.example/v1/issuers/{identifier}", "identifierTypes": ["URL"], "startsWith": ["https://"],
                 "entity": {"id": "$.id", "roles": ["CREDENTIAL_ISSUER"], "identifiers": [{"type": "URL", "value": "$.url"}],
                            "status": {"path": "$.state", "values": {"active": "ACTIVE"}, "default": "REVOKED"},
                            "validUntil": "$.valid_until"}}"""));
        return m;
    }

    /** The URL the lookup is asked about: one the loaded list does not give the DMV. */
    static final String ASKED = "https://issuer.utopia.example";
    static final String ANSWER_AT = "https://registry.partner.example/v1/issuers/https%3A%2F%2Fissuer.utopia.example";

    /** Version {@code version} of the list: the DMV ("Utopia DMV") under its old URL, with {@code party} put over it. */
    static Map<String, Object> listed(int version, Map<String, Object> party) {
        Map<String, Object> dmv = new LinkedHashMap<>(Map.of("url", "https://old.utopia.example"));
        dmv.putAll(party);
        Map<String, Object> d = MappedSourceProbesTest.tied("Utopia DMV", dmv);
        d.put("version", version);
        return d;
    }

    static Map<String, Object> answer(String id, Map<String, Object> party) {
        Map<String, Object> a = new LinkedHashMap<>(Map.of("id", id, "url", ASKED, "state", "active"));
        a.putAll(party);
        return a;
    }

    @Test
    void item6_aLookupAnswerOfAnIdTheLoadedListHoldsHasTheStricterStatusAndValidityOfTheTwo() {
        String past = MappedSourceRulesTest.NOW.minus(Duration.ofDays(1)).toString();
        record Case(String what, Map<String, Object> party, Map<String, Object> answer, Decision decision) {
        }
        List<Case> cases = List.of(
                // The answer stood alone: the party the list revokes was TRUSTED by its other identifier.
                new Case("listed revoked, answered active", Map.of("state", "revoked"), answer("Utopia DMV", Map.of()), Decision.NOT_TRUSTED),
                new Case("listed until yesterday, answered active", Map.of("valid_until", past), answer("Utopia DMV", Map.of()),
                        Decision.NOT_TRUSTED),
                new Case("listed active, answered revoked", Map.of(), answer("Utopia DMV", Map.of("state", "revoked")), Decision.NOT_TRUSTED),
                new Case("listed active, answered active", Map.of(), answer("Utopia DMV", Map.of()), Decision.TRUSTED),
                new Case("listed revoked, answered active under another id", Map.of("state", "revoked"), answer("Utopia DMV (new)", Map.of()),
                        Decision.TRUSTED));
        for (Case c : cases) {
            TestContext ctx = ctx();
            serveJson(ctx, listed(1, c.party()));
            ctx.http.json(ANSWER_AT, Json.write(c.answer()));
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", withLookup())))) {
                assertThat(state(m, "partner").lastError()).as(c.what()).isNull();
                TrustDecision d = decide(registry, m, ASKED, List.of(), null);
                assertThat(d.decision()).as(c.what()).isEqualTo(c.decision());
                if (c.what().equals("listed revoked, answered active")) {
                    assertThat(d.summary()).isEqualTo("Entity 'Utopia DMV' is REVOKED");
                }
            }
        }
    }

    @Test
    void item6_aRememberedAnswerIsHeldToTheListLoadedSinceButNotToAnOlderOne() throws Exception {
        TestContext ctx = ctx();
        serveJson(ctx, listed(2, Map.of()));
        ctx.http.json(ANSWER_AT, Json.write(answer("Utopia DMV", Map.of())));
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, props("mapping", withLookup())))) {
            assertThat(decide(registry, m, ASKED, List.of(), null).decision()).isEqualTo(Decision.TRUSTED);
            // Version 3 revokes the DMV: the answer remembered for ten minutes is held to it at once.
            serveJson(ctx, listed(3, Map.of("state", "revoked")));
            assertThat(m.refresh("partner").lastError()).isNull();
            assertThat(decide(registry, m, ASKED, List.of(), null).decision()).isEqualTo(Decision.NOT_TRUSTED);
            // Version 1, from before the withdrawal, served again: the registry refuses it, and so does the lookup.
            serveJson(ctx, listed(1, Map.of()));
            assertThat(m.refresh("partner").lastError()).contains("is older than the one already loaded");
            assertThat(decide(registry, m, ASKED, List.of(), null).decision()).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(registry.snapshot().entity("Utopia DMV").orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
        }
    }
}
