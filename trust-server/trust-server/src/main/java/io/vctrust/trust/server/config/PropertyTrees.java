package io.vctrust.trust.server.config;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Converts Spring's index-keyed maps ({@code {"0": a, "1": b}}) back into lists, recursively. */
final class PropertyTrees {

    private PropertyTrees() {
    }

    static Object normalize(Object value) {
        if (value instanceof Map<?, ?> m) {
            if (!m.isEmpty() && m.keySet().stream().allMatch(k -> String.valueOf(k).matches("\\d+"))) {
                List<Object> list = new ArrayList<>();
                m.entrySet().stream()
                        .sorted(Comparator.comparingInt(e -> Integer.parseInt(String.valueOf(e.getKey()))))
                        .forEach(e -> list.add(normalize(e.getValue())));
                return list;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), normalize(v)));
            return out;
        }
        if (value instanceof List<?> l) {
            return l.stream().map(PropertyTrees::normalize).toList();
        }
        return value;
    }
}
