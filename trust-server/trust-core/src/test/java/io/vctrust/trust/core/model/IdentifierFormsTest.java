package io.vctrust.trust.core.model;

import io.vctrust.trust.core.json.Json;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The service compares identifiers exactly as conformance/evaluation/identifiers.json says, and the client library is
 * held to the same file (identifiers.test.ts): a certificate hash written in hexadecimal, or in padded or standard
 * base64, reads as the unpadded base64url both evaluators compute, so that a REVOKED entry written that way binds the
 * certificate on both sides.
 */
class IdentifierFormsTest {

    @SuppressWarnings("unchecked")
    static Map<String, Object> forms() throws IOException {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        assertThat(p).as("conformance/ above the working directory").isNotNull();
        return Json.parseObject(Files.readAllBytes(p.resolve("conformance/evaluation/identifiers.json")));
    }

    @Test
    @SuppressWarnings("unchecked")
    void identifiersAreComparedAsTheSharedListSays() throws IOException {
        Map<String, Object> forms = forms();
        for (Map<String, Object> same : (List<Map<String, Object>>) forms.get("same")) {
            IdentifierType type = IdentifierType.valueOf((String) same.get("type"));
            for (String value : (List<String>) same.get("values")) {
                assertThat(Identifier.of(type, value).value()).as("%s %s", type, value).isEqualTo(same.get("key"));
                assertThat(Identifier.of(type, value)).as("%s %s", type, value).isEqualTo(Identifier.of(type, (String) same.get("key")));
            }
        }
        for (Map<String, Object> unchanged : (List<Map<String, Object>>) forms.get("unchanged")) {
            IdentifierType type = IdentifierType.valueOf((String) unchanged.get("type"));
            for (String value : (List<String>) unchanged.get("values")) {
                assertThat(Identifier.of(type, value).value()).as("%s '%s'", type, value).isEqualTo(value);
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void aSha256DigestIsToldApartFromAnythingElse() throws IOException {
        Map<String, Object> forms = forms();
        for (Map<String, Object> same : (List<Map<String, Object>>) forms.get("same")) {
            if ("X509_SHA256".equals(same.get("type"))) {
                for (String value : (List<String>) same.get("values")) {
                    assertThat(Identifier.sha256Digest(value)).as(value).isEqualTo(same.get("key"));
                }
            }
        }
        for (Map<String, Object> unchanged : (List<Map<String, Object>>) forms.get("unchanged")) {
            if ("X509_SHA256".equals(unchanged.get("type"))) {
                for (String value : (List<String>) unchanged.get("values")) {
                    assertThat(Identifier.sha256Digest(value)).as("'%s'", value).isNull();
                }
            }
        }
    }
}
