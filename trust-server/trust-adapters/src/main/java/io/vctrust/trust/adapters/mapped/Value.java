package io.vctrust.trust.adapters.mapped;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * What one field of a mapping is written as. The forms, and nothing else:
 *
 * <ul>
 *   <li>a string that starts with {@code $}: a {@link JsonPath} into the current record; with {@code ^}: from the root
 *       of the document;</li>
 *   <li>any other scalar: a constant; {@code {value: X}} for a constant that starts with {@code $} or {@code ^};</li>
 *   <li>{@code {path: P, values: {a: X}, default: Z}}: the value at P, translated; {@code values} may also be a list of
 *       {@code {when, then}} pairs, for keys a YAML or Spring property key cannot carry. Without {@code default}, a value
 *       not in the table yields nothing;</li>
 *   <li>{@code {template: "did:web:{$.host}"}}: a string with paths in braces; nothing if any of them yields nothing.</li>
 * </ul>
 */
sealed interface Value permits Value.Constant, Value.At, Value.Translated, Value.Template {

    /** Every value this form yields for a record, nulls left out: one for a constant, every match of a path. */
    List<Object> all(Object current, Object root);

    /** The first value, or null when the form yields nothing. */
    default Object first(Object current, Object root) {
        List<Object> all = all(current, root);
        return all.isEmpty() ? null : all.getFirst();
    }

    /** The constants this form can yield whatever the document says, so they can be checked when the configuration is read. */
    List<Object> constants();

    /**
     * Reads a value form from configuration.
     *
     * @param where where the form is, for the error ("mapping.entities[0].status")
     * @throws IllegalArgumentException for anything that is not one of the forms
     */
    static Value parse(Object raw, String where) {
        try {
            return read(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + ": " + e.getMessage(), e);
        }
    }

    private static Value read(Object raw) {
        if (raw instanceof String s) {
            return s.startsWith("$") || s.startsWith("^") ? new At(JsonPath.parse(s)) : new Constant(s);
        }
        if (raw instanceof Number || raw instanceof Boolean) {
            return new Constant(raw);
        }
        if (raw instanceof Map<?, ?> m) {
            TreeSet<String> keys = new TreeSet<>();
            m.keySet().forEach(k -> keys.add(String.valueOf(k)));
            if (keys.equals(new TreeSet<>(List.of("value")))) {
                return new Constant(scalar(m.get("value"), "value"));
            }
            if (keys.equals(new TreeSet<>(List.of("template")))) {
                return Template.of(scalar(m.get("template"), "template").toString());
            }
            if (keys.contains("path") && keys.contains("values") && keys.size() <= 3
                    && (keys.size() == 2 || keys.contains("default"))) {
                Object path = m.get("path");
                if (!(path instanceof String p) || !(p.startsWith("$") || p.startsWith("^"))) {
                    throw new IllegalArgumentException("path must be a path ($... or ^...)");
                }
                Object fallback = m.containsKey("default") ? scalar(m.get("default"), "default") : null;
                return new Translated(JsonPath.parse(p), table(m.get("values")), fallback);
            }
            throw new IllegalArgumentException("unknown value form with members " + keys + "; a value is a path ($... or ^...), "
                    + "a constant, {value}, {path, values, default} or {template}");
        }
        if (raw instanceof List<?>) {
            throw new IllegalArgumentException("a list is not accepted here");
        }
        throw new IllegalArgumentException("a value is missing");
    }

    private static Object scalar(Object v, String what) {
        if (v instanceof String || v instanceof Number || v instanceof Boolean) {
            return v;
        }
        throw new IllegalArgumentException(what + " must be a string, a number or a boolean");
    }

    /** The translation table: a map, or a list of {when, then} pairs. Keys are compared with {@link #text(Object)}. */
    private static Map<String, Object> table(Object raw) {
        Map<String, Object> table = new LinkedHashMap<>();
        if (raw instanceof Map<?, ?> m) {
            m.forEach((k, v) -> {
                if (v instanceof Map<?, ?>) {
                    // What Spring makes of a key with dots in it, such as a URI: it is split into nested keys.
                    throw new IllegalArgumentException("values." + k + " is not a single value: a key with characters other than "
                            + "letters, digits, - and _ does not survive Spring's property binding; write it in brackets "
                            + "(\"[https://...]\"), or give values as a list of {when, then} pairs");
                }
                table.put(String.valueOf(k), scalar(v, "values." + k));
            });
        } else if (raw instanceof List<?> l) {
            for (Object o : l) {
                if (!(o instanceof Map<?, ?> pair) || pair.size() != 2 || !pair.containsKey("when") || !pair.containsKey("then")) {
                    throw new IllegalArgumentException("values as a list holds {when, then} pairs only");
                }
                String when = text(scalar(pair.get("when"), "when"));
                if (table.put(when, scalar(pair.get("then"), "then")) != null) {
                    throw new IllegalArgumentException("values names '" + when + "' twice");
                }
            }
        } else {
            throw new IllegalArgumentException("values must be a map or a list of {when, then} pairs");
        }
        if (table.isEmpty()) {
            throw new IllegalArgumentException("values is empty");
        }
        return Map.copyOf(table);
    }

    /** A scalar as text: a string as it is, a number as written in the document, a boolean as true or false; else null. */
    static String text(Object v) {
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof BigDecimal d) {
            return d.toPlainString();
        }
        if (v instanceof Number || v instanceof Boolean) {
            return v.toString();
        }
        return null;
    }

    private static List<Object> present(List<Object> values) {
        List<Object> out = new ArrayList<>(values.size());
        for (Object v : values) {
            if (v != null) {
                out.add(v);
            }
        }
        return out;
    }

    record Constant(Object value) implements Value {
        @Override
        public List<Object> all(Object current, Object root) {
            return List.of(value);
        }

        @Override
        public List<Object> constants() {
            return List.of(value);
        }
    }

    record At(JsonPath path) implements Value {
        @Override
        public List<Object> all(Object current, Object root) {
            return present(path.select(current, root));
        }

        @Override
        public List<Object> constants() {
            return List.of();
        }
    }

    record Translated(JsonPath path, Map<String, Object> table, Object fallback) implements Value {
        @Override
        public List<Object> all(Object current, Object root) {
            List<Object> found = present(path.select(current, root));
            if (found.isEmpty()) {
                return fallback == null ? List.of() : List.of(fallback);
            }
            List<Object> out = new ArrayList<>(found.size());
            for (Object v : found) {
                String key = text(v);
                Object translated = key == null ? null : table.get(key);
                if (translated != null) {
                    out.add(translated);
                } else if (fallback != null) {
                    out.add(fallback);
                }
            }
            return out;
        }

        @Override
        public List<Object> constants() {
            List<Object> out = new ArrayList<>(table.values());
            if (fallback != null) {
                out.add(fallback);
            }
            return out;
        }
    }

    /** Literal text and paths; a path's first value is put in as text. */
    record Template(String text, List<Object> parts) implements Value {

        static Template of(String text) {
            List<Object> parts = new ArrayList<>();
            StringBuilder literal = new StringBuilder();
            int i = 0;
            while (i < text.length()) {
                char c = text.charAt(i);
                if (c == '}') {
                    throw new IllegalArgumentException("template '" + text + "' has a } without {");
                }
                if (c != '{') {
                    literal.append(c);
                    i++;
                    continue;
                }
                int end = closing(text, i + 1);
                if (literal.length() > 0) {
                    parts.add(literal.toString());
                    literal.setLength(0);
                }
                String path = text.substring(i + 1, end);
                if (!path.startsWith("$") && !path.startsWith("^")) {
                    throw new IllegalArgumentException("template '" + text + "': braces hold a path ($... or ^...)");
                }
                parts.add(JsonPath.parse(path));
                i = end + 1;
            }
            if (literal.length() > 0) {
                parts.add(literal.toString());
            }
            if (parts.stream().noneMatch(JsonPath.class::isInstance)) {
                throw new IllegalArgumentException("template '" + text + "' has no path in braces; write a constant instead");
            }
            return new Template(text, List.copyOf(parts));
        }

        /** The } that closes a path, skipping quoted strings in it (a filter literal may hold a brace). */
        private static int closing(String text, int from) {
            char quote = 0;
            for (int i = from; i < text.length(); i++) {
                char c = text.charAt(i);
                if (quote != 0) {
                    if (c == '\\') {
                        i++;
                    } else if (c == quote) {
                        quote = 0;
                    }
                } else if (c == '\'' || c == '"') {
                    quote = c;
                } else if (c == '{') {
                    break;
                } else if (c == '}') {
                    return i;
                }
            }
            throw new IllegalArgumentException("template '" + text + "' has a { without }");
        }

        @Override
        public List<Object> all(Object current, Object root) {
            StringBuilder out = new StringBuilder();
            for (Object part : parts) {
                if (part instanceof JsonPath p) {
                    List<Object> found = present(p.select(current, root));
                    String t = found.isEmpty() ? null : Value.text(found.getFirst());
                    if (t == null) {
                        return List.of();
                    }
                    out.append(t);
                } else {
                    out.append(part);
                }
            }
            return List.of(out.toString());
        }

        @Override
        public List<Object> constants() {
            return List.of();
        }
    }
}
