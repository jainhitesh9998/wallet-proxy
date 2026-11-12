package io.vctrust.trust.server.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vctrust.trust.core.model.EntityRole;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The service reads the role of a query exactly as conformance/evaluation/roles.json says, and the client library is
 * held to the same file (roles.test.ts): a spelling one side reads and the other does not would put a question under a
 * mechanism on one side and under none on the other.
 */
class RoleSpellingsTest {

    record Roles(String description, Map<String, String> spellings, Map<String, String> variants, List<String> absent, List<String> refused) {
    }

    static Roles roles() throws IOException {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        assertThat(p).as("conformance/ above the working directory").isNotNull();
        return new ObjectMapper().readValue(p.resolve("conformance/evaluation/roles.json").toFile(), new TypeReference<Roles>() { });
    }

    @Test
    void theServiceReadsExactlyTheSpellingsOfTheSharedList() throws IOException {
        Roles roles = roles();
        Map<String, String> mine = new LinkedHashMap<>();
        Dtos.ROLES.forEach((spelling, role) -> mine.put(spelling, role.name()));
        assertThat(mine).isEqualTo(roles.spellings());
        for (Map<String, String> m : List.of(roles.spellings(), roles.variants())) {
            m.forEach((spelling, role) -> assertThat(Dtos.parseRole(spelling)).as("'%s'", spelling).isEqualTo(EntityRole.valueOf(role)));
        }
        assertThat(Dtos.parseRole(null)).isNull();
        for (String spelling : roles.absent()) {
            assertThat(Dtos.parseRole(spelling)).as("'%s'", spelling).isNull();
        }
        for (String spelling : roles.refused()) {
            assertThatThrownBy(() -> Dtos.parseRole(spelling)).as("'%s'", spelling).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Unknown role");
        }
    }
}
