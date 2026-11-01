package io.vctrust.trust.core.json;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/** Shared JSON helpers over a single, immutable Jackson 3 mapper. */
public final class Json {

    public static final JsonMapper MAPPER = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private Json() {
    }

    public static Map<String, Object> parseObject(byte[] json) {
        return MAPPER.readValue(json, MAP);
    }

    public static Map<String, Object> parseObject(String json) {
        return MAPPER.readValue(json, MAP);
    }

    public static String write(Object value) {
        return MAPPER.writeValueAsString(value);
    }

    public static byte[] writeBytes(Object value) {
        return write(value).getBytes(StandardCharsets.UTF_8);
    }

    public static <T> T convert(Object value, Class<T> type) {
        return MAPPER.convertValue(value, type);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object v) {
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> array(Object v) {
        return v instanceof List<?> l ? (List<Object>) l : null;
    }

    public static String string(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v instanceof String s ? s : null;
    }

    public static List<String> strings(Object v) {
        if (v instanceof List<?> l) {
            return l.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        if (v instanceof String s) {
            return List.of(s);
        }
        return List.of();
    }
}
