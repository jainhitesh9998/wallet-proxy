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
 *       {@code {when, then}} pairs, for keys a YAML or Spring property key cannot carry. Keys are compared without
 *       regard to case and surrounding whitespace. {@code default} stands for both a value not in the table and no
 *       value at P; without it, either yields nothing. An object or a list at P is the wrong kind, not the default;</li>
 *   <li>{@code {template: "did:web:{$.host}"}}: a string with paths in braces; nothing if any of them yields nothing;</li>
 *   <li>for a member that takes a list, {@code {path: P, allowEmpty: true}} (also with {@code values} and
 *       {@code default}): a list at P that is there and yields nothing leaves the member absent, where it would
 *       otherwise restrict to nothing.</li>
 * </ul>
 *
 * <p>A path that finds something of the wrong kind (see {@link JsonPath#select}) is an error, which skips the record.
 */
sealed interface Value permits Value.Constant, Value.At, Value.Translated, Value.Template {

    /**
     * The most values a member yields for one record: a path from the root could otherwise give each record all of them.
     * Every node a path selects counts, whether or not it becomes a value (a null, a value no translation knows): a
     * path over 400,000 nulls would otherwise cost each record the time to look at all of them.
     */
    int MAX_VALUES = 1_000;

    /** The longest text one mapped value may be: a path from the root would otherwise repeat a long text into every record. */
    int MAX_TEXT = 8_192;

    /**
     * Every value this form yields for a record, nulls left out: one for a constant, every match of a path.
     *
     * @throws IllegalArgumentException when that is more than {@link #MAX_VALUES}, or a path finds the wrong kind of node
     */
    List<Object> all(Object current, Object root);

    /** The first value, or null when the form yields nothing. Never more work than finding that one. */
    default Object first(Object current, Object root) {
        List<Object> all = all(current, root);
        return all.isEmpty() ? null : all.getFirst();
    }

    /** What a member that yields more than {@link #MAX_VALUES} for one record says (and the record is skipped). */
    static IllegalArgumentException tooMany() {
        return new IllegalArgumentException("yields more than " + MAX_VALUES + " values for one record");
    }

    /** The constants this form can yield whatever the document says, so they can be checked when the configuration is read. */
    List<Object> constants();

    /**
     * What this form yields for a member that restricts (an anchor's doctypes), read as {@link JsonPath#restricted}
     * reads its path: past a list, an item that lacks what the path goes on to cannot be read; and a value that its
     * translation does not know (without a default) cannot be read either. Dropped, it would narrow the list or empty
     * it, and an emptied list may read as "none stated".
     *
     * @throws IllegalArgumentException as {@link #all}, and for those two
     */
    default Restricting restricting(Object current, Object root) {
        return new Restricting(all(current, root), false, false);
    }

    /**
     * What a form of a restricting member yields, and what tells a list that is there and empty from one that is not
     * there ({@link JsonPath.Restricted}).
     */
    record Restricting(List<Object> values, boolean there, boolean lost) {
    }

    /**
     * Whether the operator said that a list this form reads, when it is there and has no item at all, is absent rather
     * than a restriction to nothing ({@code {path: P, allowEmpty: true}}): for an upstream that writes an empty list
     * where it means "none registered".
     */
    default boolean allowEmpty() {
        return false;
    }

    /**
     * Reads a value form of a member that takes a single value.
     *
     * @param where where the form is, for the error ("mapping.entities[0].status")
     * @throws IllegalArgumentException for anything that is not one of the forms
     */
    static Value parse(Object raw, String where) {
        return parse(raw, where, Kind.SINGLE);
    }

    /**
     * Reads a value form of a member that takes a list but restricts nothing (roles, certificates, CRL locations):
     * as {@link #parse}; {@code allowEmpty} would change nothing there, and is refused so that nobody believes it does.
     */
    static Value parseList(Object raw, String where) {
        return parse(raw, where, Kind.LIST);
    }

    /** Reads a value form of a list that restricts (an anchor's doctypes): as {@link #parse}, and {@code allowEmpty} may be said. */
    static Value parseRestricting(Object raw, String where) {
        return parse(raw, where, Kind.RESTRICTING);
    }

    /** What a member takes: a single value, a list, or a list that restricts what its record may do. */
    enum Kind {
        SINGLE, LIST, RESTRICTING
    }

    private static Value parse(Object raw, String where, Kind kind) {
        try {
            return read(raw, kind);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + ": " + e.getMessage(), e);
        }
    }

    /** What is said of {@code allowEmpty} where it changes nothing. */
    static String changesNothing() {
        return "allowEmpty applies to a list that restricts (authorizations, docTypes), where a list that is there and empty "
                + "would otherwise restrict to nothing; here it would change nothing";
    }

    private static Value read(Object raw, Kind kind) {
        boolean list = kind != Kind.SINGLE;
        if (raw instanceof String s) {
            return s.startsWith("$") || s.startsWith("^") ? new At(JsonPath.parse(s), false) : new Constant(s);
        }
        if (raw instanceof Number || raw instanceof Boolean) {
            return new Constant(raw);
        }
        if (raw instanceof Map<?, ?> m) {
            TreeSet<String> keys = new TreeSet<>();
            m.keySet().forEach(k -> keys.add(String.valueOf(k)));
            boolean allowEmpty = false;
            boolean says = keys.contains("allowEmpty");
            if (says) {
                if (!list) {
                    throw new IllegalArgumentException("allowEmpty applies to a member that takes a list, not to one that takes a single value");
                }
                Object flag = m.get("allowEmpty");
                if (!(Boolean.TRUE.equals(flag) || Boolean.FALSE.equals(flag) || "true".equals(flag) || "false".equals(flag))) {
                    throw new IllegalArgumentException("allowEmpty must be true or false");
                }
                allowEmpty = Boolean.TRUE.equals(flag) || "true".equals(flag);
            }
            TreeSet<String> form = new TreeSet<>(keys);
            form.remove("allowEmpty");
            if (!says && form.equals(new TreeSet<>(List.of("value")))) {
                return new Constant(scalar(m.get("value"), "value"));
            }
            if (!says && form.equals(new TreeSet<>(List.of("template")))) {
                return Template.of(scalar(m.get("template"), "template").toString());
            }
            boolean translated = form.contains("path") && form.contains("values") && form.size() <= 3
                    && (form.size() == 2 || form.contains("default"));
            if (translated || says && form.equals(new TreeSet<>(List.of("path")))) {
                if (says && kind != Kind.RESTRICTING) {
                    throw new IllegalArgumentException(changesNothing());
                }
                Object path = m.get("path");
                if (!(path instanceof String p) || !(p.startsWith("$") || p.startsWith("^"))) {
                    throw new IllegalArgumentException("path must be a path ($... or ^...)");
                }
                JsonPath at = JsonPath.parse(p);
                if (says && !at.readsList()) {
                    throw new IllegalArgumentException("allowEmpty applies to a list: " + p + " has no [*] or filter");
                }
                if (!translated) {
                    return new At(at, allowEmpty);
                }
                Object fallback = m.containsKey("default") ? scalar(m.get("default"), "default") : null;
                return new Translated(at, table(m.get("values")), fallback, allowEmpty);
            }
            throw new IllegalArgumentException("unknown value form with members " + keys + "; a value is a path ($... or ^...), "
                    + "a constant, {value}, {path, values, default} or {template}" + (list ? ", and {path, allowEmpty} for a list" : ""));
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

    /**
     * The translation table: a map, or a list of {when, then} pairs. Keys are compared by {@link #key}: without regard
     * to case and to surrounding whitespace, so that {@code Revoked}, {@code " revoked"} and {@code revoked} are one
     * state, and two keys that are one under that rule are a configuration error.
     */
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
                once(table, key(String.valueOf(k)), scalar(v, "values." + k));
            });
        } else if (raw instanceof List<?> l) {
            for (Object o : l) {
                if (!(o instanceof Map<?, ?> pair) || pair.size() != 2 || !pair.containsKey("when") || !pair.containsKey("then")) {
                    throw new IllegalArgumentException("values as a list holds {when, then} pairs only");
                }
                once(table, key(text(scalar(pair.get("when"), "when"))), scalar(pair.get("then"), "then"));
            }
        } else {
            throw new IllegalArgumentException("values must be a map or a list of {when, then} pairs");
        }
        if (table.isEmpty()) {
            throw new IllegalArgumentException("values is empty");
        }
        return Map.copyOf(table);
    }

    private static void once(Map<String, Object> table, String key, Object then) {
        if (table.put(key, then) != null) {
            throw new IllegalArgumentException("values names '" + key + "' twice (keys are compared without regard to case and "
                    + "surrounding whitespace)");
        }
    }

    /** A translation key as it is compared: without surrounding whitespace, in lower case. */
    static String key(String text) {
        return text.strip().toLowerCase(java.util.Locale.ROOT);
    }

    /** Beyond this scale either way, a number is written with an exponent: in plain notation it could be any length. */
    int MAX_PLAIN_SCALE = 100;

    /**
     * A scalar as text: a string as it is, a number as written in the document, a boolean as true or false; else null.
     * The text of a number is never much longer than the number's own digits: {@code 1e999999999} in plain notation
     * would be a gigabyte. A document cannot hold such a number ({@link StrictJson}); one from anywhere else is written
     * with its exponent.
     */
    static String text(Object v) {
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof BigDecimal d) {
            return Math.abs((long) d.scale()) <= MAX_PLAIN_SCALE ? d.toPlainString() : d.toString();
        }
        if (v instanceof Number || v instanceof Boolean) {
            return v.toString();
        }
        return null;
    }

    /** The nodes that are not null, of at most {@link #MAX_VALUES} selected. */
    private static List<Object> present(List<Object> values) {
        bounded(values);
        List<Object> out = new ArrayList<>(Math.min(values.size(), 16));
        for (Object v : values) {
            if (v != null) {
                out.add(v);
            }
        }
        return out;
    }

    /** What a path selected, when it is at most {@link #MAX_VALUES} nodes, nulls included. */
    private static List<Object> bounded(List<Object> selected) {
        if (selected.size() > MAX_VALUES) {
            throw tooMany();
        }
        return selected;
    }

    /** The first node that is not null, or null, of at most {@link #MAX_VALUES} selected. */
    private static Object firstPresent(List<Object> values) {
        bounded(values);
        for (Object v : values) {
            if (v != null) {
                return v;
            }
        }
        return null;
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

    record At(JsonPath path, boolean allowEmpty) implements Value {
        @Override
        public List<Object> all(Object current, Object root) {
            return present(path.select(current, root));
        }

        @Override
        public Object first(Object current, Object root) {
            return firstPresent(path.select(current, root));
        }

        @Override
        public List<Object> constants() {
            return List.of();
        }

        @Override
        public Restricting restricting(Object current, Object root) {
            JsonPath.Restricted r = path.restricted(current, root);
            return new Restricting(present(r.nodes()), r.there(), r.lost());
        }
    }

    record Translated(JsonPath path, Map<String, Object> table, Object fallback, boolean allowEmpty) implements Value {
        @Override
        public List<Object> all(Object current, Object root) {
            List<Object> found = present(path.select(current, root));
            if (found.isEmpty()) {
                return fallback == null ? List.of() : List.of(fallback);
            }
            List<Object> out = new ArrayList<>(found.size());
            for (Object v : found) {
                Object translated = translate(v);
                if (translated != null) {
                    out.add(translated);
                }
            }
            return out;
        }

        /** As {@code all(...).getFirst()}: the first value that translates (or the default), without the rest. */
        @Override
        public Object first(Object current, Object root) {
            boolean found = false;
            for (Object v : bounded(path.select(current, root))) {
                if (v != null) {
                    found = true;
                    Object translated = translate(v);
                    if (translated != null) {
                        return translated;
                    }
                }
            }
            return found ? null : fallback;
        }

        /**
         * The first value at the path that the table does not translate, when there is no default; else null. A member
         * that says whom a record is about (its roles) cannot leave out what the document states there.
         */
        Object untranslated(Object current, Object root) {
            if (fallback != null) {
                return null;
            }
            for (Object v : bounded(path.select(current, root))) {
                if (v != null && translate(v) == null) {
                    return v;
                }
            }
            return null;
        }

        /**
         * The value's translation, else the default (null without one). An object or a list is not a value the table
         * or its default can stand for: the document says something there, in a shape the mapping does not know.
         */
        private Object translate(Object v) {
            String text = text(v);
            if (text == null) {
                throw new IllegalArgumentException("the path " + path.text() + " finds " + JsonPath.kind(v) + " where a value to translate belongs");
            }
            Object translated = table.get(key(text));
            return translated != null ? translated : fallback;
        }

        @Override
        public List<Object> constants() {
            List<Object> out = new ArrayList<>(table.values());
            if (fallback != null) {
                out.add(fallback);
            }
            return out;
        }

        /**
         * Every value at the path, translated; a value the table does not know, without a default, cannot be read:
         * left out, it would narrow the list, or empty it ({@code ["photo-id"]} under a table that knows only the
         * mDL), and an emptied list may read as "none stated". With no value at the path, the default, as anywhere.
         */
        @Override
        public Restricting restricting(Object current, Object root) {
            JsonPath.Restricted r = path.restricted(current, root);
            List<Object> found = present(r.nodes());
            if (found.isEmpty()) {
                return new Restricting(fallback == null ? List.of() : List.of(fallback), r.there(), r.lost());
            }
            List<Object> out = new ArrayList<>(found.size());
            for (Object v : found) {
                Object translated = translate(v);
                if (translated == null) {
                    throw new IllegalArgumentException("the path " + path.text() + " finds " + Mapping.quote(v) + ", which its translation "
                            + "does not know, and it has no default: a list that restricts is not narrowed by what cannot be read");
                }
                out.add(translated);
            }
            return new Restricting(out, r.there(), r.lost());
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

        /** A part that finds nothing makes the template yield nothing; one that finds an object or a list is an error. */
        @Override
        public List<Object> all(Object current, Object root) {
            StringBuilder out = new StringBuilder();
            for (Object part : parts) {
                if (part instanceof JsonPath p) {
                    Object found = firstPresent(p.select(current, root));
                    if (found == null) {
                        return List.of();
                    }
                    String t = Value.text(found);
                    if (t == null) {
                        throw new IllegalArgumentException("the path " + p.text() + " finds " + JsonPath.kind(found) + " where text belongs");
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
