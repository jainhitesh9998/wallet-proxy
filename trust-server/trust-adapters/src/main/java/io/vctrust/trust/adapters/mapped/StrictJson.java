package io.vctrust.trust.adapters.mapped;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

/**
 * Reads a document written by someone else: strict JSON (RFC 8259) and nothing more. A member named twice, content
 * after the value, nesting deeper than {@link #MAX_DEPTH} and very long numbers, strings or names are refused, so
 * that what one reader takes from a document cannot differ from what another takes, and a document cannot make the
 * reader do more than linear work. Numbers with a fraction are kept exactly ({@code BigDecimal}).
 */
final class StrictJson {

    static final int MAX_DEPTH = 32;

    private static final JsonMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNestingDepth(MAX_DEPTH)
                            .maxNumberLength(100)
                            .maxNameLength(1_000)
                            .maxStringLength(2_000_000) // a pushed CRL of 1 MiB, in base64
                            .build())
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .build();

    private StrictJson() {
    }

    /**
     * @return a {@code Map} or a {@code List}: a document is an object or an array
     * @throws IllegalArgumentException with a short reason, for anything else
     */
    static Object parse(byte[] json) {
        Object v;
        try {
            v = MAPPER.readValue(json, Object.class);
        } catch (JacksonException e) {
            String reason = e.getOriginalMessage() == null ? e.getClass().getSimpleName() : e.getOriginalMessage();
            throw new IllegalArgumentException("not valid JSON: " + (reason.length() <= 160 ? reason : reason.substring(0, 160) + "…"));
        }
        if (!(v instanceof Map<?, ?>) && !(v instanceof List<?>)) {
            throw new IllegalArgumentException("not a JSON object or array");
        }
        return v;
    }
}
