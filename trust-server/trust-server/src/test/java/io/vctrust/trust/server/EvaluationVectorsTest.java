package io.vctrust.trust.server;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.nio.file.Path;

/**
 * The first pair of evaluation vectors: {@code conformance/evaluation/cases.json} turned into
 * {@code conformance/evaluation/vectors.json} by a service without trust mechanisms. It proves that such a service
 * decides exactly as before mechanisms existed: its snapshot is format 4 without a {@code mechanisms} claim, and no
 * decision names a mechanism. See {@link EvaluationVectors}.
 */
class EvaluationVectorsTest extends EvaluationVectors {

    static final Path CASES = ROOT.resolve("conformance/evaluation/cases.json");
    static final Path VECTORS = FIRST_PAIR_VECTORS;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws IOException {
        service(r, "trust-vectors");
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
        return "EvaluationVectorsTest";
    }

    @Override
    boolean withMechanisms() {
        return false;
    }
}
