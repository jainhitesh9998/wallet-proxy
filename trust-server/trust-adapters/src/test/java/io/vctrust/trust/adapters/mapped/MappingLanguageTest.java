package io.vctrust.trust.adapters.mapped;

import io.vctrust.trust.core.json.Json;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The path subset and the value forms of a mapping, and the checks made when a mapping is read. */
class MappingLanguageTest {

    static final Object DOC = Json.parseObject("""
            {"publisher": "Partner", "country": "UT",
             "issuers": [
               {"id": "a", "type": "DSC", "country": "UT", "n": 1, "flag": true, "gone": null,
                "display": {"name": "Alpha"}, "tags": ["x", "y"], "odd name": "spaced"},
               {"id": "b", "type": "CSCA", "country": "XX", "n": 1.0, "flag": false},
               {"id": "c", "type": "DSC", "n": 2}
             ],
             "byKey": {"k1": {"v": 1}, "k2": {"v": 2}}}""");

    static List<Object> select(String path) {
        return JsonPath.parse(path).select(DOC, DOC);
    }

    static List<Object> ids(List<Object> nodes) {
        List<Object> out = new ArrayList<>();
        nodes.forEach(n -> out.add(((Map<?, ?>) n).get("id")));
        return out;
    }

    @Test
    void pathsSelectMembersIndicesAndEveryChild() {
        assertThat(select("$.publisher")).containsExactly("Partner");
        assertThat(select("$['publisher']")).containsExactly("Partner");
        assertThat(select("$[\"publisher\"]")).containsExactly("Partner");
        assertThat(select("$.issuers[0]['odd name']")).containsExactly("spaced");
        assertThat(select("$.issuers[-1].id")).containsExactly("c");
        assertThat(select("$.issuers[5].id")).isEmpty();
        assertThat(select("$.issuers[*].id")).containsExactly("a", "b", "c");
        assertThat(select("$.byKey[*].v")).containsExactly(1, 2);              // the wildcard takes an object's members too
        assertThat(select("$.issuers[0].tags[*]")).containsExactly("x", "y");
        assertThat(select("$.missing[*].id")).isEmpty();
        assertThat(select("$.issuers[0].gone")).containsExactly((Object) null); // a null member is there; Value leaves it out
        assertThat(select("$")).containsExactly(DOC);
    }

    @Test
    void rootPathsStartAtTheDocumentWhateverTheRecord() {
        Object record = ((List<?>) ((Map<?, ?>) DOC).get("issuers")).get(1);
        assertThat(JsonPath.parse("$.id").select(record, DOC)).containsExactly("b");
        assertThat(JsonPath.parse("^.country").select(record, DOC)).containsExactly("UT");
        assertThat(JsonPath.parse("^.issuers[0].id").select(record, DOC)).containsExactly("a");
    }

    @Test
    void filtersCompareMembersOfTheCurrentItemWithLiterals() {
        assertThat(ids(select("$.issuers[?@.type == 'DSC']"))).containsExactly("a", "c");
        assertThat(ids(select("$.issuers[?@.type == 'DSC' && @.country != 'XX']"))).containsExactly("a", "c");
        assertThat(ids(select("$.issuers[?(@.type == 'DSC' && @.country == 'UT')]"))).containsExactly("a");
        assertThat(ids(select("$.issuers[?(@.type=='CSCA')&&(@.country=='XX')]"))).containsExactly("b");
        assertThat(ids(select("$.issuers[? 'DSC' == @.type ]"))).containsExactly("a", "c");
        // Numbers by value; booleans; a missing member is neither equal to null nor to anything else (RFC 9535 2.3.5.2.2).
        assertThat(ids(select("$.issuers[?@.n == 1]"))).containsExactly("a", "b");
        assertThat(ids(select("$.issuers[?@.n == 1e0]"))).containsExactly("a", "b");
        assertThat(ids(select("$.issuers[?@.flag == true]"))).containsExactly("a");
        assertThat(ids(select("$.issuers[?@.gone == null]"))).containsExactly("a");
        assertThat(ids(select("$.issuers[?@.country != 'XX']"))).containsExactly("a", "c");   // c has no country
        assertThat(ids(select("$.issuers[?@.country == 'XX']"))).containsExactly("b");
        assertThat(ids(select("$.issuers[?@.display.name == 'Alpha']"))).containsExactly("a");
        assertThat(select("$.issuers[0].tags[?@ != 'x']")).containsExactly("y");
        assertThat(select("$.byKey[?@.v == 2].v")).containsExactly(2);
    }

    @Test
    void anythingOutsideTheSubsetIsRefusedWhenReadNamingWhere() {
        for (String bad : List.of("", "issuers", "$..id", "$.issuers[0:2]", "$.issuers[?length(@.id) == 1]",
                "$.issuers[?@.id =~ 'a']", "$.issuers[?@.id == 'a' || @.id == 'b']", "$.issuers.*", "$.issuers[?@.id]",
                "$['unterminated", "$.issuers[01]", "$.issuers[-0]", "$.issuers[?'a' == 'a']", "$.issuers[?@.id == $.x]",
                "$.issuers[?!(@.id == 'a')]", "$.a b", "$.issuers[?@.n == 01]", "$[?@[*] == 1]")) {
            assertThatThrownBy(() -> JsonPath.parse(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> JsonPath.parse("$.issuers[0:2]")).hasMessageContaining("'$.issuers[0:2]'").hasMessageContaining("position");
        assertThatThrownBy(() -> JsonPath.parse("$" + ".a".repeat(300))).hasMessageContaining("longer than");
        assertThatThrownBy(() -> JsonPath.parse("$[?" + "(".repeat(40) + "@.a == 1" + ")".repeat(40) + "]"))
                .hasMessageContaining("nested too deeply");
    }

    @Test
    void wildcardsVisitEachNodeOncePerSegment() {
        // 300 x 300 nested arrays: three wildcards select every leaf once, not a product of guesses.
        List<Object> rows = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            List<Object> row = new ArrayList<>();
            for (int j = 0; j < 300; j++) {
                row.add(Map.of("v", j));
            }
            rows.add(row);
        }
        Object doc = Map.of("rows", rows);
        assertThat(JsonPath.parse("$.rows[*][*].v").select(doc, doc)).hasSize(90_000);
        assertThat(JsonPath.parse("$.rows[*][?@.v == 7].v").select(doc, doc)).hasSize(300);
    }

    @Test
    void aPathFromTheRootIsEvaluatedOncePerDocumentNotOncePerRecord() {
        // A document whose root counts how often its member "contexts" is looked into.
        java.util.concurrent.atomic.AtomicInteger lookups = new java.util.concurrent.atomic.AtomicInteger();
        Map<String, Object> root = new java.util.LinkedHashMap<>() {
            @Override
            public boolean containsKey(Object key) {
                if ("contexts".equals(key)) {
                    lookups.incrementAndGet();
                }
                return super.containsKey(key);
            }
        };
        List<Object> issuers = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            issuers.add(Map.of("id", "p" + i));
        }
        root.put("issuers", issuers);
        root.put("contexts", List.of("https://contexts.example/a", "https://contexts.example/b"));
        Mapping m = Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.issuers[*]", "id", "$.id", "roles", "VERIFIER",
                "contexts", "^.contexts[*]", "attributes", Map.of("first", "^.contexts[0]")))));
        Mapping.Block block = m.entities.getFirst();
        for (Object record : block.records(root)) {
            assertThat(block.map(record, root).entry()).containsEntry("contexts", List.of("https://contexts.example/a", "https://contexts.example/b"));
        }
        assertThat(lookups).hasValue(2);   // once for each of the two paths, for the whole document
        // Another document is another evaluation.
        Map<String, Object> other = new java.util.LinkedHashMap<>(root);
        other.put("contexts", List.of("https://contexts.example/c"));
        assertThat(block.map(issuers.getFirst(), other).entry()).containsEntry("contexts", List.of("https://contexts.example/c"));
    }

    static Object first(Object form, Object record) {
        return Value.parse(form, "test").first(record, DOC);
    }

    static List<Object> all(Object form, Object record) {
        return Value.parse(form, "test").all(record, DOC);
    }

    @Test
    void valueForms() {
        Object a = ((List<?>) ((Map<?, ?>) DOC).get("issuers")).get(0);
        assertThat(first("$.id", a)).isEqualTo("a");
        assertThat(first("^.publisher", a)).isEqualTo("Partner");
        assertThat(first("CREDENTIAL_ISSUER", a)).isEqualTo("CREDENTIAL_ISSUER");
        assertThat(first(5, a)).isEqualTo(5);
        assertThat(first(Map.of("value", "$5"), a)).isEqualTo("$5");
        assertThat(first("$.gone", a)).isNull();                      // null yields nothing
        assertThat(all("$.tags[*]", a)).containsExactly("x", "y");   // a wildcard contributes every match
        assertThat(first(Map.of("template", "partner:{$.id}:{^.country}"), a)).isEqualTo("partner:a:UT");
        assertThat(first(Map.of("template", "n{$.n}-{$.flag}"), a)).isEqualTo("n1-true");
        assertThat(first(Map.of("template", "partner:{$.missing}"), a)).isNull();   // any part missing: nothing
        // An object is not text: present but unusable, which skips the record (not a template that yields nothing).
        assertThatThrownBy(() -> first(Map.of("template", "x{$.display}"), a)).hasMessage("the path $.display finds an object where text belongs");
        assertThat(first(Map.of("template", "{$['odd name']}{$.tags[?@ == '}']}"), a)).isNull();
        assertThat(first(Map.of("template", "{$['odd name']}!"), a)).isEqualTo("spaced!");
    }

    @Test
    void aNumberIsWrittenAsTextInBoundedSpace() {
        // In plain notation 1e9999999 is ten million characters; a document cannot hold it (StrictJson), and a number
        // from anywhere else is not written out either.
        assertThat(Value.text(new java.math.BigDecimal("1E+9999999"))).hasSizeLessThan(40);
        assertThat(Value.text(new java.math.BigDecimal("1E-9999999"))).hasSizeLessThan(40);
        assertThat(Value.text(new java.math.BigDecimal("1E+40"))).isEqualTo("1" + "0".repeat(40));
        assertThat(Value.text(new java.math.BigDecimal("0.5"))).isEqualTo("0.5");
    }

    @Test
    void aQuotedValueCannotBreakALogLine() {
        assertThat(Mapping.quote("partner\r\n2026-11-12 WARN forged\tline\u0007\u007f")).isEqualTo("'partner\\r\\n2026-11-12 WARN forged\\tline\\u0007\\u007f'");
        assertThat(Mapping.quote("plain")).isEqualTo("'plain'");
        assertThat(Mapping.quote("x".repeat(39) + "\n" + "y".repeat(10))).isEqualTo("'" + "x".repeat(39) + "\\n…'");
    }

    @Test
    void everyControlFormatAndSeparatorCharacterIsEscaped() {
        // Third round (item 9): not only those below 0x20. A line or paragraph separator, NEL, a bidi override or a zero
        // width character in a log line breaks it, or makes it read otherwise than it is written.
        String text = "a\u0085b c d​e‮f﻿g­h" + new String(Character.toChars(0xE0001)) + "i";
        assertThat(Mapping.escape(text)).isEqualTo("a\\u0085b\\u2028c\\u2029d\\u200be\\u202ef\\ufeffg\\u00adh\\udb40\\udc01i");
        assertThat(MappedSourceFactory.told("x WARN forged", 2_000)).isEqualTo("x\\u2028WARN forged");
        assertThat(Mapping.escape("plain text, é, 日本")).isEqualTo("plain text, é, 日本");
    }

    @Test
    void translationKeysIgnoreEverySurroundingSpaceAndNumbersMatchByValue() {
        // Third round (item 9): the no-break space and the zero-width space surround a key too; a number in the
        // document matches a key by its value (1.0 is 1).
        Map<String, Object> status = Map.of("path", "$.s", "values", Map.of(" revoked​", "REVOKED", "1", "ACTIVE", "2.50", "SUSPENDED"));
        assertThat(first(status, Map.of("s", "Revoked"))).isEqualTo("REVOKED");
        assertThat(first(status, Map.of("s", "​revoked "))).isEqualTo("REVOKED");
        assertThat(first(status, Map.of("s", new java.math.BigDecimal("1.0")))).isEqualTo("ACTIVE");
        assertThat(first(status, Map.of("s", 1))).isEqualTo("ACTIVE");
        assertThat(first(status, Map.of("s", new java.math.BigDecimal("2.5")))).isEqualTo("SUSPENDED");
        assertThat(first(status, Map.of("s", new java.math.BigDecimal("1E+0")))).isEqualTo("ACTIVE");
        // Text is text: "1.0" written as a string is not the number.
        assertThat(first(status, Map.of("s", "1.0"))).isNull();
        // Two keys of one value are one key, and a configuration error.
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.s", "values", Map.of("1", "A", "1.0", "B")), "w"))
                .hasMessageContaining("values names 1 twice");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.s", "values", Map.of("x", "A", " X", "B")), "w"))
                .hasMessageContaining("values names 'x' twice");
    }

    @Test
    void theQueryOfEveryWebUrlInATextIsCutUpToTheNextWhitespace() {
        // Second round: the scrubber stopped at an apostrophe, a quote or an angle bracket, and left the rest.
        assertThat(MappedSourceFactory.withoutQueries("from https://h.example/x?key=part1'part2\"part3<part4>part5 failed"))
                .isEqualTo("from https://h.example/x failed");
        assertThat(MappedSourceFactory.withoutQueries("at 'https://h.example/x?k=s', then HTTPS://H.example#frag; done"))
                .isEqualTo("at 'https://h.example/x', then HTTPS://H.example; done");
        assertThat(MappedSourceFactory.withoutQueries("x_https://h.example/?k=s and https://h.example/path'?k=s"))
                .isEqualTo("x_https://h.example/ and https://h.example/path'");
        assertThat(MappedSourceFactory.withoutQueries("https://h.example/list?key=x: refused")).isEqualTo("https://h.example/list: refused");
    }

    @Test
    void translatedValues() {
        Object a = ((List<?>) ((Map<?, ?>) DOC).get("issuers")).get(0);
        Object b = ((List<?>) ((Map<?, ?>) DOC).get("issuers")).get(1);
        Map<String, Object> status = Map.of("path", "$.type", "values", Map.of("DSC", "ACTIVE"), "default", "REVOKED");
        assertThat(first(status, a)).isEqualTo("ACTIVE");
        assertThat(first(status, b)).isEqualTo("REVOKED");
        assertThat(first(Map.of("path", "$.missing", "values", Map.of("x", "y"), "default", "REVOKED"), a)).isEqualTo("REVOKED");
        // Without a default, an untranslated value yields nothing.
        assertThat(first(Map.of("path", "$.type", "values", Map.of("DSC", "ACTIVE")), b)).isNull();
        // Booleans and numbers are matched by their text.
        assertThat(first(Map.of("path", "$.flag", "values", Map.of("true", "ACTIVE", "false", "SUSPENDED")), b)).isEqualTo("SUSPENDED");
        assertThat(first(Map.of("path", "$.n", "values", Map.of("1.0", "one point oh")), b)).isEqualTo("one point oh");
        // Keys a YAML or Spring property key cannot carry: a list of {when, then}.
        Map<String, Object> pairs = Map.of("path", "$.url", "values", List.of(
                Map.of("when", "https://a.example/x", "then", "credential-issuer"),
                Map.of("when", "https://b.example/y", "then", "verifier-access")));
        assertThat(first(pairs, Map.of("url", "https://b.example/y"))).isEqualTo("verifier-access");
        assertThat(all(Map.of("path", "$.tags[*]", "values", Map.of("x", "X"), "default", "?"), a)).containsExactly("X", "?");
    }

    @Test
    void unknownValueFormsAreRefusedNamingWhere() {
        assertThatThrownBy(() -> Value.parse(Map.of("pth", "$.a"), "mapping.entities[0].name"))
                .hasMessageStartingWith("mapping.entities[0].name: unknown value form with members [pth]");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a"), "w")).hasMessageContaining("unknown value form");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a", "default", "x"), "w")).hasMessageContaining("unknown value form");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a", "values", Map.of("a", "b"), "else", "c"), "w"))
                .hasMessageContaining("unknown value form");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "a", "values", Map.of("a", "b")), "w")).hasMessageContaining("must be a path");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a", "values", Map.of()), "w")).hasMessageContaining("values is empty");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a", "values", List.of(Map.of("when", "a"))), "w"))
                .hasMessageContaining("{when, then}");
        assertThatThrownBy(() -> Value.parse(Map.of("path", "$.a", "values", List.of(Map.of("when", "a", "then", "b"),
                Map.of("when", "a", "then", "c"))), "w")).hasMessageContaining("twice");
        assertThatThrownBy(() -> Value.parse(Map.of("value", Map.of()), "w")).hasMessageContaining("value must be");
        assertThatThrownBy(() -> Value.parse(Map.of("template", "no path"), "w")).hasMessageContaining("no path");
        assertThatThrownBy(() -> Value.parse(Map.of("template", "a{$.x"), "w")).hasMessageContaining("{ without }");
        assertThatThrownBy(() -> Value.parse(Map.of("template", "a}"), "w")).hasMessageContaining("} without {");
        assertThatThrownBy(() -> Value.parse(Map.of("template", "{x}"), "w")).hasMessageContaining("braces hold a path");
        assertThatThrownBy(() -> Value.parse(List.of("$.a"), "w")).hasMessageContaining("list is not accepted");
        assertThatThrownBy(() -> Value.parse(null, "w")).hasMessageContaining("missing");
        assertThatThrownBy(() -> Value.parse("$.a[", "mapping.entities[0].id"))
                .hasMessageStartingWith("mapping.entities[0].id: Invalid path '$.a['");
    }

    @Test
    void aMappingIsCheckedWhenRead() {
        Map<String, Object> ok = Map.of("entities", List.of(Map.of("each", "$.issuers[*]", "id", "$.id", "roles", "VERIFIER")));
        assertThat(Mapping.parse(ok).entities).hasSize(1);

        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.x[*]", "id", "$.id", "nmae", "$.n")))))
                .hasMessageStartingWith("mapping.entities[0]: unknown member [nmae]");
        assertThatThrownBy(() -> Mapping.parse(Map.of("entites", List.of())))
                .hasMessageStartingWith("mapping: unknown member [entites]");
        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.x[*]", "id", "$.id", "roles", "VERIFIER",
                "identifiers", List.of(Map.of("type", "URL", "value", "$.u", "kind", "x")))))))
                .hasMessageStartingWith("mapping.entities[0].identifiers[0]: unknown member [kind]");
        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("id", "$.id")))))
                .hasMessageContaining("each is required");
        assertThatThrownBy(() -> Mapping.parse(Map.of("anchors", List.of(Map.of("each", "$.x[*]", "domain", "mdoc-iaca")))))
                .hasMessageContaining("mapping.anchors[0]: certificate is required");
        // Constants that name enumeration values are checked now, also inside a translation.
        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.x[*]", "id", "$.id", "roles", List.of("ISSUER"))))))
                .hasMessageStartingWith("mapping.entities[0].roles: Unknown role 'ISSUER'");
        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.x[*]", "id", "$.id", "roles", "VERIFIER",
                "status", Map.of("path", "$.s", "values", Map.of("on", "ENABLED"), "default", "REVOKED"))))))
                .hasMessageStartingWith("mapping.entities[0].status: Unknown status 'ENABLED'");
        assertThatThrownBy(() -> Mapping.parse(Map.of("entities", List.of(Map.of("each", "$.x[*]", "id", "$.id", "roles", "VERIFIER",
                "identifiers", List.of(Map.of("type", "EMAIL", "value", "$.e")))))))
                .hasMessageContaining("Unknown identifier type 'EMAIL'");
        assertThatThrownBy(() -> Mapping.parse(Map.of("anchors", List.of(Map.of("each", "$.x[*]", "domain", "d", "certificate", "$.c",
                "status", "GONE"))))).hasMessageContaining("mapping.anchors[0].status: Unknown status 'GONE'");
        assertThatThrownBy(() -> Mapping.parse(Map.of("pages", Map.of("next", "$.n", "max", 0), "entities", ok.get("entities"))))
                .hasMessageContaining("mapping.pages.max must be a positive whole number");
    }

    @Test
    void aLookupIsAskedOnlyAboutWhatItNames() {
        Map<String, Object> entity = Map.of("id", "$.id", "roles", "VERIFIER");
        assertThat(Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:example:"), "entity", entity))).lookup.missStatus()).containsExactly(404);
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of(""), "entity", entity)))).hasMessageContaining("not empty");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}", "identifierTypes", List.of("DID"),
                "entity", entity)))).hasMessageContaining("mapping.lookup.startsWith");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{id}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:"), "entity", entity)))).hasMessageContaining("{identifier}");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}/{other}",
                "identifierTypes", List.of("DID"), "startsWith", List.of("did:"), "entity", entity)))).hasMessageContaining("other than {identifier}");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "file:/etc/{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:"), "entity", entity)))).hasMessageContaining("http(s) URL");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}", "identifierTypes", List.of("PHONE"),
                "startsWith", List.of("did:"), "entity", entity)))).hasMessageContaining("Unknown identifier type 'PHONE'");
        assertThatThrownBy(() -> Mapping.parse(Map.of("lookup", Map.of("url", "https://r.example/{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:"), "entity", entity, "missStatus", List.of(500))))).hasMessageContaining("4xx");
    }

    @Test
    void theTextOfASourcesConfigurationHoldsNoHeaderValue() throws Exception {
        var def = new io.vctrust.trust.core.spi.SourceDefinition("partner", "mapped", "partner", null, true, Map.of(
                "location", "https://registry.partner.example/v1/issuers?key=s3cret-query",
                "headers", Map.of("Authorization", "Bearer s3cret-token"),
                "mapping", Map.of("entities", List.of(Map.of("each", "$.issuers[*]", "id", "$.id", "roles", "VERIFIER")))));
        String text = MappedSourceFactory.read(def, location -> new byte[0]).toString();
        assertThat(text).contains("headers=[Authorization]").contains("location=https://registry.partner.example/v1/issuers,")
                .doesNotContain("s3cret");
    }

    @Test
    void aRecordIsMappedIntoTheRegistryFormat() {
        Mapping m = Mapping.parse(Json.parseObject("""
                {"entities": [{"each": "$.issuers[?@.type == 'DSC']",
                   "id": {"template": "p:{$.id}"}, "roles": ["CREDENTIAL_ISSUER"], "name": "$.display.name",
                   "identifiers": [{"type": "URL", "value": {"template": "https://{$.id}.example"}}, {"type": "DID", "value": "$.did"},
                                   {"each": "$.tags[*]", "type": "CLIENT_ID", "value": "$"}],
                   "authorizations": [{"format": "mso_mdoc", "type": "org.iso.18013.5.1.mDL"}],
                   "status": {"path": "$.flag", "values": {"true": "ACTIVE"}, "default": "SUSPENDED"},
                   "validUntil": "$.n", "attributes": {"country": "$.country", "publisher": "^.publisher"}}]}"""));
        Object a = ((List<?>) ((Map<?, ?>) DOC).get("issuers")).get(0);
        assertThat(m.entities.getFirst().records(DOC)).hasSize(2);
        Mapping.Mapped mapped = m.entities.getFirst().map(a, DOC);
        assertThat(mapped.entry()).isEqualTo(Json.parseObject("""
                {"id": "p:a", "roles": ["CREDENTIAL_ISSUER"], "name": "Alpha",
                 "identifiers": [{"type": "URL", "value": "https://a.example"}, {"type": "CLIENT_ID", "value": "x"},
                                 {"type": "CLIENT_ID", "value": "y"}],
                 "authorizations": [{"format": "mso_mdoc", "type": "org.iso.18013.5.1.mDL"}],
                 "status": "ACTIVE", "validUntil": "1970-01-01T00:00:01Z", "attributes": {"country": "UT", "publisher": "Partner"}}"""));
        assertThat(mapped.unusable()).isEmpty();
        // Something of the wrong kind cannot be read: the member is named with why, not left out as if absent.
        Mapping.Mapped soon = m.entities.getFirst().map(Map.of("id", "z", "n", "soon"), DOC);
        assertThat(soon.unusable()).containsExactly(Map.entry("validUntil", "validUntil is not a date: 'soon'"));
        assertThat(soon.entry()).containsEntry("id", "p:z").doesNotContainKey("validUntil");
        Mapping plain = Mapping.parse(Map.of("entities", List.of(Map.of("each", "$[*]", "id", "$.id", "roles", "$.roles[*]"))));
        assertThat(plain.entities.getFirst().map(Map.of("id", Map.of("x", 1)), DOC).unusable().get("id")).contains("id is an object");
        assertThat(plain.entities.getFirst().map(Map.of("id", "z", "roles", List.of(List.of("VERIFIER"))), DOC).unusable().get("roles"))
                .contains("roles is a list");
    }
}
