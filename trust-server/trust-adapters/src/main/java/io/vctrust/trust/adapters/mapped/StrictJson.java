package io.vctrust.trust.adapters.mapped;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Reads a document written by someone else: strict JSON (RFC 8259) and nothing more. A member named twice, content
 * after the value, nesting deeper than {@link #MAX_DEPTH} and very long numbers, strings or names are refused, so
 * that what one reader takes from a document cannot differ from what another takes, and a document cannot make the
 * reader do more than linear work. Numbers with a fraction are kept exactly ({@code BigDecimal}).
 *
 * <p>So is a number that is short to write but large to write out: {@code 1e999999999} is eleven characters, and a
 * gigabyte of digits as text or as an integer. A document is read only if every number in it has at most
 * {@link #MAX_DIGITS} significant digits and a decimal exponent from -{@link #MAX_EXPONENT} to {@link #MAX_EXPONENT};
 * otherwise the whole document is refused, so that no code after the parser meets such a number.
 */
final class StrictJson {

    static final int MAX_DEPTH = 32;
    static final int MAX_DIGITS = 40;
    static final int MAX_EXPONENT = 40;

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
        checkNumbers(v);
        return v;
    }

    /** Every number in a parsed document, at any depth (at most {@link #MAX_DEPTH}), must be {@link #small}. */
    private static void checkNumbers(Object v) {
        if (v instanceof Map<?, ?> m) {
            m.values().forEach(StrictJson::checkNumbers);
        } else if (v instanceof List<?> l) {
            l.forEach(StrictJson::checkNumbers);
        } else if (v instanceof Number n && !small(n)) {
            throw new IllegalArgumentException("not read: it holds a number with more than " + MAX_DIGITS
                    + " significant digits or a decimal exponent outside -" + MAX_EXPONENT + " to " + MAX_EXPONENT);
        }
    }

    /**
     * Whether a number has at most {@link #MAX_DIGITS} significant digits and, written as {@code d.ddd x 10^e}, an
     * exponent {@code e} from -{@link #MAX_EXPONENT} to {@link #MAX_EXPONENT}. Cheap whatever the number: the parser
     * keeps {@code 1e999999999} as the digit 1 and a scale, and so does every step here.
     */
    static boolean small(Number n) {
        BigDecimal d;
        if (n instanceof BigDecimal b) {
            d = b;
        } else if (n instanceof BigInteger i) {
            d = new BigDecimal(i);
        } else if (n instanceof Integer || n instanceof Long || n instanceof Short || n instanceof Byte) {
            d = BigDecimal.valueOf(n.longValue());
        } else {
            return false;   // the parser makes no other kind of number; one it did make is not read
        }
        if (d.signum() == 0) {
            return true;
        }
        BigDecimal s = d.stripTrailingZeros();
        long exponent = (long) s.precision() - s.scale() - 1;
        return s.precision() <= MAX_DIGITS && exponent >= -MAX_EXPONENT && exponent <= MAX_EXPONENT;
    }
}
