package io.vctrust.trust.adapters.mapped;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The subset of JSONPath (RFC 9535) a mapping is written in. A path starts at {@code $}, the current record, or at
 * {@code ^}, the root of the document (an extension of this service); then come member names ({@code .name},
 * {@code ['name']}), array indices ({@code [n]}, negative from the end), the wildcard ({@code [*]}) and filters
 * ({@code [?@.type == 'DSC' && @.country != 'XX']}, also written {@code [?(...)]}): comparisons with {@code ==} and
 * {@code !=} of members of the current item against string, number, boolean and null literals, joined with
 * {@code &&}. Comparisons follow RFC 9535 section 2.3.5.2.2: a missing member equals nothing but another missing one,
 * numbers compare by value.
 *
 * <p>There is no recursive descent, no slice, no function and no regular expression: each segment looks once at the
 * children of the nodes the previous segment selected, so evaluation is linear in the size of the document whatever
 * the document holds. Paths come from the configuration only, and are parsed when it is read.
 *
 * <p>Unlike RFC 9535, a segment applied to a node it cannot look into is an error rather than nothing (see
 * {@link #select}); inside a filter, RFC 9535 holds.
 */
final class JsonPath {

    static final int MAX_LENGTH = 512;
    private static final int MAX_NESTING = 16;

    /** A filter's query on a member that is not there: RFC 9535 "Nothing", which is not the same as a null value. */
    private static final Object NOTHING = new Object();

    private final String text;
    private final boolean fromRoot;
    private final List<Segment> segments;

    private JsonPath(String text, boolean fromRoot, List<Segment> segments) {
        this.text = text;
        this.fromRoot = fromRoot;
        this.segments = segments;
    }

    /** @throws IllegalArgumentException naming the path, the position and what was expected there */
    static JsonPath parse(String text) {
        return new Parser(text).path();
    }

    String text() {
        return text;
    }

    /** Whether the path can select more than one node (it has a wildcard or a filter). */
    boolean multiple() {
        return segments.stream().anyMatch(s -> s instanceof Wildcard || s instanceof Filter);
    }

    /**
     * The nodes the path selects, in document order; a member whose value is null is selected as null.
     *
     * <p>Only a member that is not there, or is null, selects nothing. A segment that meets what it cannot look into
     * (a member name on text or on a list, {@code [*]} on a number, an index on an object) is an error: the document
     * holds something there, not what the mapping expects, and reading it as absent would leave out what it says (a
     * list of doctypes written as one string would constrain nothing).
     *
     * @throws IllegalArgumentException naming the path, what it found and what the segment needs
     */
    List<Object> select(Object current, Object root) {
        List<Object> nodes = new ArrayList<>(1);
        nodes.add(fromRoot ? root : current);
        for (Segment s : segments) {
            List<Object> next = new ArrayList<>();
            for (Object n : nodes) {
                if (n == null) {
                    continue;
                }
                if (!s.accepts(n)) {
                    throw new IllegalArgumentException("the path " + text + " finds " + kind(n) + " where " + s.needs());
                }
                s.apply(n, next);
            }
            nodes = next;
            if (nodes.isEmpty()) {
                break;
            }
        }
        return nodes;
    }

    /** What a node of a document is, in words, for a message. */
    static String kind(Object node) {
        return node instanceof Map<?, ?> ? "an object" : node instanceof List<?> ? "a list" : node instanceof String ? "text"
                : node instanceof Boolean ? "true or false" : node instanceof Number ? "a number" : "nothing";
    }

    @Override
    public String toString() {
        return text;
    }

    private sealed interface Segment permits Member, Index, Wildcard, Filter {
        void apply(Object node, List<Object> out);

        /** Whether the segment can look into this node at all (a missing member or index is not a question of kind). */
        boolean accepts(Object node);

        /** What the segment needs, for a message. */
        String needs();
    }

    private record Member(String name) implements Segment {
        @Override
        public void apply(Object node, List<Object> out) {
            if (node instanceof Map<?, ?> m && m.containsKey(name)) {
                out.add(m.get(name));
            }
        }

        @Override
        public boolean accepts(Object node) {
            return node instanceof Map<?, ?>;
        }

        @Override
        public String needs() {
            return "." + name + " needs an object";
        }
    }

    private record Index(int index) implements Segment {
        @Override
        public void apply(Object node, List<Object> out) {
            if (node instanceof List<?> l) {
                int i = index < 0 ? l.size() + index : index;
                if (i >= 0 && i < l.size()) {
                    out.add(l.get(i));
                }
            }
        }

        @Override
        public boolean accepts(Object node) {
            return node instanceof List<?>;
        }

        @Override
        public String needs() {
            return "[" + index + "] needs a list";
        }
    }

    private record Wildcard() implements Segment {
        @Override
        public void apply(Object node, List<Object> out) {
            children(node, out);
        }

        @Override
        public boolean accepts(Object node) {
            return node instanceof Map<?, ?> || node instanceof List<?>;
        }

        @Override
        public String needs() {
            return "[*] needs a list or an object";
        }
    }

    private record Filter(Condition condition) implements Segment {
        @Override
        public boolean accepts(Object node) {
            return node instanceof Map<?, ?> || node instanceof List<?>;
        }

        @Override
        public String needs() {
            return "a filter needs a list or an object";
        }

        @Override
        public void apply(Object node, List<Object> out) {
            List<Object> children = new ArrayList<>();
            children(node, children);
            for (Object c : children) {
                if (condition.test(c)) {
                    out.add(c);
                }
            }
        }
    }

    /** The children of an object (its member values) or of an array (its elements); a scalar has none. */
    private static void children(Object node, List<Object> out) {
        if (node instanceof Map<?, ?> m) {
            out.addAll(m.values());
        } else if (node instanceof List<?> l) {
            out.addAll(l);
        }
    }

    private sealed interface Condition permits All, Comparison {
        boolean test(Object item);
    }

    private record All(List<Condition> parts) implements Condition {
        @Override
        public boolean test(Object item) {
            for (Condition c : parts) {
                if (!c.test(item)) {
                    return false;
                }
            }
            return true;
        }
    }

    private record Comparison(Operand left, boolean equal, Operand right) implements Condition {
        @Override
        public boolean test(Object item) {
            return same(left.value(item), right.value(item)) == equal;
        }
    }

    private sealed interface Operand permits Literal, Relative {
        Object value(Object item);
    }

    private record Literal(Object value) implements Operand {
        @Override
        public Object value(Object item) {
            return value;
        }
    }

    /** {@code @} followed by names and indices only: it selects at most one node. */
    private record Relative(List<Segment> segments) implements Operand {
        @Override
        public Object value(Object item) {
            Object n = item;
            List<Object> one = new ArrayList<>(1);
            for (Segment s : segments) {
                one.clear();
                s.apply(n, one);
                if (one.isEmpty()) {
                    return NOTHING;
                }
                n = one.getFirst();
            }
            return n;
        }
    }

    private static boolean same(Object a, Object b) {
        if (a == NOTHING || b == NOTHING || a == null || b == null) {
            return a == b;
        }
        if (a instanceof Number x && b instanceof Number y) {
            BigDecimal dx = decimal(x);
            BigDecimal dy = decimal(y);
            return dx != null && dy != null ? dx.compareTo(dy) == 0 : x.equals(y);
        }
        return Objects.equals(a, b);
    }

    private static BigDecimal decimal(Number n) {
        if (n instanceof BigDecimal d) {
            return d;
        }
        if (n instanceof BigInteger i) {
            return new BigDecimal(i);
        }
        if (n instanceof Double || n instanceof Float) {
            double d = n.doubleValue();
            return Double.isFinite(d) ? new BigDecimal(Double.toString(d)) : null;
        }
        return BigDecimal.valueOf(n.longValue());
    }

    private static final class Parser {
        private final String s;
        private int i;
        private int nesting;

        Parser(String s) {
            this.s = s;
        }

        JsonPath path() {
            if (s == null || s.isEmpty()) {
                throw new IllegalArgumentException("A path cannot be empty");
            }
            if (s.length() > MAX_LENGTH) {
                throw new IllegalArgumentException("Path longer than " + MAX_LENGTH + " characters");
            }
            char c = s.charAt(0);
            if (c != '$' && c != '^') {
                fail("a path starts with $ (the current record) or ^ (the document)");
            }
            i = 1;
            List<Segment> segments = new ArrayList<>();
            while (i < s.length()) {
                segments.add(segment(false));
            }
            return new JsonPath(s, c == '^', List.copyOf(segments));
        }

        /** @param singular inside a filter: names and indices only */
        Segment segment(boolean singular) {
            char c = s.charAt(i);
            if (c == '.') {
                i++;
                if (i < s.length() && s.charAt(i) == '*') {
                    fail("write [*] for every member or element");
                }
                return new Member(name());
            }
            if (c != '[') {
                fail("expected . or [");
            }
            i++;
            blank();
            char d = peek();
            Segment segment;
            if (d == '\'' || d == '"') {
                segment = new Member(string());
            } else if (d == '-' || digit(d)) {
                segment = new Index(index());
            } else if (d == '*' && !singular) {
                i++;
                segment = new Wildcard();
            } else if (d == '?' && !singular) {
                i++;
                blank();
                segment = new Filter(conjunction());
            } else {
                fail(singular ? "expected a quoted name or an index" : "expected a quoted name, an index, * or a filter (?...)");
                return null;
            }
            blank();
            expect(']');
            return segment;
        }

        String name() {
            int start = i;
            while (i < s.length() && nameChar(s.charAt(i), i == start)) {
                i++;
            }
            if (i == start) {
                fail("expected a member name (letters, digits, _; other names in brackets: ['name'])");
            }
            return s.substring(start, i);
        }

        private static boolean nameChar(char c, boolean first) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80 || (!first && digit(c));
        }

        int index() {
            int start = i;
            if (peek() == '-') {
                i++;
            }
            int digits = i;
            while (i < s.length() && digit(s.charAt(i))) {
                i++;
            }
            String n = s.substring(start, i);
            if (i == digits || i - digits > 9 || (s.charAt(digits) == '0' && i - digits > 1) || n.equals("-0")) {
                fail("expected an index: an integer without leading zeros");
            }
            return Integer.parseInt(n);
        }

        Condition conjunction() {
            if (++nesting > MAX_NESTING) {
                fail("filter nested too deeply");
            }
            List<Condition> parts = new ArrayList<>();
            parts.add(atom());
            blank();
            while (s.startsWith("&&", i)) {
                i += 2;
                blank();
                parts.add(atom());
                blank();
            }
            nesting--;
            return parts.size() == 1 ? parts.getFirst() : new All(List.copyOf(parts));
        }

        Condition atom() {
            if (peek() == '(') {
                i++;
                blank();
                Condition c = conjunction();
                blank();
                expect(')');
                return c;
            }
            Operand left = operand();
            blank();
            boolean equal;
            if (s.startsWith("==", i)) {
                equal = true;
            } else if (s.startsWith("!=", i)) {
                equal = false;
            } else {
                fail("expected == or != (a filter compares; || and ! are not supported)");
                return null;
            }
            i += 2;
            blank();
            Operand right = operand();
            if (left instanceof Literal && right instanceof Literal) {
                fail("a comparison needs a member of the current item (@)");
            }
            return new Comparison(left, equal, right);
        }

        Operand operand() {
            char c = peek();
            if (c == '@') {
                i++;
                List<Segment> segments = new ArrayList<>();
                while (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == '[')) {
                    segments.add(segment(true));
                }
                return new Relative(List.copyOf(segments));
            }
            if (c == '\'' || c == '"') {
                return new Literal(string());
            }
            if (c == '-' || digit(c)) {
                return new Literal(number());
            }
            for (String word : List.of("true", "false", "null")) {
                if (s.startsWith(word, i) && (i + word.length() == s.length() || !nameChar(s.charAt(i + word.length()), false))) {
                    i += word.length();
                    return new Literal(word.equals("null") ? null : Boolean.valueOf(word));
                }
            }
            if (c == '$' || c == '^') {
                fail("a filter compares members of the current item (@) with literals, not other paths");
            }
            fail("expected @, a quoted string, a number, true, false or null");
            return null;
        }

        BigDecimal number() {
            int start = i;
            if (peek() == '-') {
                i++;
            }
            while (i < s.length() && (digit(s.charAt(i)) || ".eE+-".indexOf(s.charAt(i)) >= 0)) {
                i++;
            }
            String n = s.substring(start, i);
            if (!n.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?") || n.length() > 40) {
                fail("not a number: " + n);
            }
            return new BigDecimal(n);
        }

        /** A quoted string with the escapes of RFC 9535 section 2.3.1.1. */
        String string() {
            char quote = s.charAt(i++);
            StringBuilder out = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    fail("unterminated string");
                }
                char c = s.charAt(i++);
                if (c == quote) {
                    return out.toString();
                }
                if (c < 0x20) {
                    fail("control character in a string");
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (i >= s.length()) {
                    fail("unterminated string");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '\\', '/', '\'', '"' -> out.append(e);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length() || !s.substring(i, i + 4).matches("[0-9A-Fa-f]{4}")) {
                            fail("expected four hex digits after \\u");
                        }
                        out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> fail("unknown escape \\" + e);
                }
            }
        }

        void blank() {
            while (i < s.length() && " \t\n\r".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
        }

        char peek() {
            if (i >= s.length()) {
                fail("unexpected end");
            }
            return s.charAt(i);
        }

        void expect(char c) {
            if (peek() != c) {
                fail("expected " + c);
            }
            i++;
        }

        private static boolean digit(char c) {
            return c >= '0' && c <= '9';
        }

        private void fail(String what) {
            throw new IllegalArgumentException("Invalid path '" + s + "' at position " + i + ": " + what);
        }
    }
}
