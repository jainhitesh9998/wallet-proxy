package io.vctrust.trust.core.spi;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Configuration of one trust source instance. {@code properties} is free-form and interpreted by the
 * {@link TrustSourceFactory} for {@code type}.
 */
public record SourceDefinition(String id, String type, String frameworkId, Duration refreshInterval, boolean enabled,
                               Map<String, Object> properties) {

    public SourceDefinition {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(type, "type");
        refreshInterval = refreshInterval == null ? Duration.ofHours(1) : refreshInterval;
        properties = properties == null ? Map.of() : Map.copyOf(properties);
    }

    public String string(String key) {
        Object v = properties.get(key);
        return v == null ? null : String.valueOf(v);
    }

    public String requireString(String key) {
        String v = string(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Source '" + id + "' (" + type + ") requires property '" + key + "'");
        }
        return v;
    }

    public boolean bool(String key, boolean dflt) {
        Object v = properties.get(key);
        return v == null ? dflt : Boolean.parseBoolean(String.valueOf(v));
    }

    public int integer(String key, int dflt) {
        Object v = properties.get(key);
        return v == null ? dflt : Integer.parseInt(String.valueOf(v));
    }

    /** A list property; also accepts Spring's map-indexed form ({@code {"0": a, "1": b}}). */
    @SuppressWarnings("unchecked")
    public List<Object> list(String key) {
        Object v = properties.get(key);
        if (v instanceof List<?> l) {
            return (List<Object>) l;
        }
        if (v instanceof Map<?, ?> m && m.keySet().stream().allMatch(k -> String.valueOf(k).matches("\\d+"))) {
            return m.entrySet().stream()
                    .sorted(java.util.Comparator.comparingInt(e -> Integer.parseInt(String.valueOf(e.getKey()))))
                    .map(e -> (Object) e.getValue())
                    .toList();
        }
        if (v instanceof String s && !s.isBlank()) {
            return List.of((Object[]) s.split("\\s*,\\s*"));
        }
        return List.of();
    }

    public List<String> strings(String key) {
        return list(key).stream().map(String::valueOf).toList();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> map(String key) {
        Object v = properties.get(key);
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }
}
