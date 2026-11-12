package io.vctrust.trust.server;

import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * The second pair of evaluation vectors: {@code conformance/evaluation/mechanisms.cases.json} turned into
 * {@code conformance/evaluation/mechanisms.vectors.json} by a service configured with the operator's trust mechanisms
 * the file lists. Its snapshots are format 5 and carry them; every outcome names the mechanism that governed the query
 * (null: none), and the client library must name the same. See {@link EvaluationVectors}.
 */
class MechanismVectorsTest extends EvaluationVectors {

    static final Path CASES = ROOT.resolve("conformance/evaluation/mechanisms.cases.json");
    static final Path VECTORS = ROOT.resolve("conformance/evaluation/mechanisms.vectors.json");

    /**
     * {@code trust.mechanisms} as the file states it, given to the service as flat properties, as arguments or the
     * environment would give them: every value a string, which the service reads as strictly as YAML.
     */
    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        service(r, "trust-mechanism-vectors");
        Map<String, Object> input = JSON.readValue(CASES.toFile(), new TypeReference<>() { });
        flatten("trust.mechanisms", input.get("mechanisms"), r);
    }

    static void flatten(String name, Object value, DynamicPropertyRegistry r) {
        if (value instanceof Map<?, ?> m) {
            m.forEach((k, v) -> flatten(name + "." + k, v, r));
        } else if (value instanceof List<?> l) {
            for (int i = 0; i < l.size(); i++) {
                flatten(name + "[" + i + "]", l.get(i), r);
            }
        } else {
            String text = String.valueOf(value);
            r.add(name, () -> text);
        }
    }

    @Override
    Path cases() {
        return CASES;
    }

    @Override
    Path vectors() {
        return VECTORS;
    }

    @Override
    String generatedBy() {
        return "MechanismVectorsTest";
    }

    @Override
    boolean withMechanisms() {
        return true;
    }
}
