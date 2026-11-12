package io.vctrust.trust.adapters.mapped;

import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.util.Enums;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * How a JSON document is read into the registry: facts about the list as a whole, how its pages link, and blocks
 * that each turn every match of their {@code each} path into one entity or one anchor in the registry format
 * ({@code docs/configuration.md}, "Registry format"). Read and checked when the configuration is read: an unknown
 * member, a malformed path or an unknown constant is an error that names where it is.
 */
final class Mapping {

    /** Facts about the list as a whole, read from the root of the first page; each may be absent. */
    record ListFacts(Value issuer, Value sequence, Value issuedAt, Value nextUpdate) {
    }

    record Pages(Value next, int max) {
    }

    /**
     * Asking about one party: only identifiers of these types and prefixes, answered by an entity block.
     *
     * @param maxAge how long after its {@code iat} a signed answer without {@code exp} counts; null when not configured
     */
    record Lookup(String url, Set<IdentifierType> types, List<String> prefixes, Block entity, Set<Integer> missStatus,
                  Duration maxAge) {
    }

    static final int DEFAULT_MAX_PAGES = 50;

    final ListFacts list;
    final Pages pages;
    final List<Block> entities;
    final List<Block> anchors;
    final Lookup lookup;

    private Mapping(ListFacts list, Pages pages, List<Block> entities, List<Block> anchors, Lookup lookup) {
        this.list = list;
        this.pages = pages;
        this.entities = entities;
        this.anchors = anchors;
        this.lookup = lookup;
    }

    static Mapping parse(Object raw) {
        Map<String, Object> m = members(raw, "mapping", Set.of("list", "pages", "entities", "anchors", "lookup"));
        ListFacts list = null;
        if (m.containsKey("list")) {
            Map<String, Object> l = members(m.get("list"), "mapping.list", Set.of("issuer", "sequence", "issuedAt", "nextUpdate"));
            list = new ListFacts(optional(l, "issuer", "mapping.list"), optional(l, "sequence", "mapping.list"),
                    optional(l, "issuedAt", "mapping.list"), optional(l, "nextUpdate", "mapping.list"));
        }
        Pages pages = null;
        if (m.containsKey("pages")) {
            Map<String, Object> p = members(m.get("pages"), "mapping.pages", Set.of("next", "max"));
            if (!p.containsKey("next")) {
                throw new IllegalArgumentException("mapping.pages: next is required");
            }
            pages = new Pages(Value.parse(p.get("next"), "mapping.pages.next"),
                    p.containsKey("max") ? positive(p.get("max"), "mapping.pages.max") : DEFAULT_MAX_PAGES);
        }
        List<Block> entities = blocks(m.get("entities"), "mapping.entities", true);
        List<Block> anchors = blocks(m.get("anchors"), "mapping.anchors", false);
        Lookup lookup = m.containsKey("lookup") ? lookup(m.get("lookup")) : null;
        return new Mapping(list, pages, entities, anchors, lookup);
    }

    private static List<Block> blocks(Object raw, String where, boolean entity) {
        if (raw == null) {
            return List.of();
        }
        if (!(raw instanceof List<?> l) || l.isEmpty()) {
            throw new IllegalArgumentException(where + " must be a list of blocks");
        }
        List<Block> out = new ArrayList<>();
        for (int i = 0; i < l.size(); i++) {
            out.add(entity ? Block.entity(l.get(i), where + "[" + i + "]", true) : Block.anchor(l.get(i), where + "[" + i + "]"));
        }
        return List.copyOf(out);
    }

    private static Lookup lookup(Object raw) {
        Map<String, Object> m = members(raw, "mapping.lookup", Set.of("url", "identifierTypes", "startsWith", "entity", "missStatus",
                "maxAge"));
        String url = m.get("url") instanceof String s ? s : null;
        if (url == null || !url.contains("{identifier}")) {
            throw new IllegalArgumentException("mapping.lookup.url must be a URL with {identifier} in it");
        }
        if (url.replace("{identifier}", "").contains("{") || url.replace("{identifier}", "").contains("}")) {
            throw new IllegalArgumentException("mapping.lookup.url has a placeholder other than {identifier}");
        }
        java.net.URI probe;
        try {
            probe = java.net.URI.create(url.replace("{identifier}", "x"));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("mapping.lookup.url is not a URL");
        }
        if (probe.getHost() == null || !("https".equals(probe.getScheme()) || "http".equals(probe.getScheme()))) {
            throw new IllegalArgumentException("mapping.lookup.url must be an http(s) URL");
        }
        Set<IdentifierType> types = EnumSet.noneOf(IdentifierType.class);
        for (Object t : list(m.get("identifierTypes"), "mapping.lookup.identifierTypes")) {
            try {
                types.add(Enums.parse(IdentifierType.class, String.valueOf(t), "identifier type"));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("mapping.lookup.identifierTypes: " + e.getMessage(), e);
            }
        }
        List<String> prefixes = new ArrayList<>();
        for (Object p : list(m.get("startsWith"), "mapping.lookup.startsWith")) {
            // An empty prefix would send every identifier of the type to the external service.
            if (!(p instanceof String s) || s.isEmpty()) {
                throw new IllegalArgumentException("mapping.lookup.startsWith holds prefixes that are not empty");
            }
            prefixes.add(s);
        }
        if (!m.containsKey("entity")) {
            throw new IllegalArgumentException("mapping.lookup.entity is required");
        }
        Set<Integer> miss = new LinkedHashSet<>();
        if (m.containsKey("missStatus")) {
            for (Object s : list(m.get("missStatus"), "mapping.lookup.missStatus")) {
                int status = positive(s, "mapping.lookup.missStatus");
                if (status < 400 || status > 499) {
                    throw new IllegalArgumentException("mapping.lookup.missStatus holds 4xx statuses only");
                }
                miss.add(status);
            }
        } else {
            miss.add(404);
        }
        Duration maxAge = null;
        if (m.containsKey("maxAge")) {
            try {
                maxAge = Duration.parse(String.valueOf(m.get("maxAge")).trim());
            } catch (DateTimeParseException e) {
                maxAge = Duration.ZERO;
            }
            if (maxAge.isNegative() || maxAge.isZero()) {
                throw new IllegalArgumentException("mapping.lookup.maxAge must be a duration such as PT24H, longer than none");
            }
        }
        return new Lookup(url, Set.copyOf(types), List.copyOf(prefixes), Block.entity(m.get("entity"), "mapping.lookup.entity", false),
                Set.copyOf(miss), maxAge);
    }

    /** One block: what every match of {@code each} becomes. */
    static final class Block {
        final String where;
        final JsonPath each;
        final boolean entity;
        /** Whether a document in which this block finds no record at all is still a list (else the load fails). */
        final boolean allowEmpty;
        private final Map<String, Object> fields;

        private Block(String where, JsonPath each, boolean entity, boolean allowEmpty, Map<String, Object> fields) {
            this.where = where;
            this.each = each;
            this.entity = entity;
            this.allowEmpty = allowEmpty;
            this.fields = fields;
        }

        static final Set<String> ENTITY_MEMBERS = Set.of("each", "allowEmpty", "id", "roles", "name", "display", "identifiers",
                "certificates", "authorizations", "status", "validFrom", "validUntil", "contexts", "attributes", "metadataPolicy",
                "framework");
        static final Set<String> ANCHOR_MEMBERS = Set.of("each", "allowEmpty", "id", "domain", "certificate", "entity", "status",
                "docTypes", "crlUrls", "crl", "framework");

        /** @param eachRequired false for a lookup's answer, where {@code each} defaults to the whole document */
        static Block entity(Object raw, String where, boolean eachRequired) {
            Map<String, Object> m = members(raw, where, ENTITY_MEMBERS);
            JsonPath each = each(m, where, eachRequired);
            if (!eachRequired && m.containsKey("allowEmpty")) {
                throw new IllegalArgumentException(where + ": allowEmpty applies to the blocks of entities and anchors");
            }
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", required(m, "id", where));
            f.put("roles", many(m.get("roles"), where + ".roles"));
            f.put("name", optional(m, "name", where));
            f.put("display", items(m.get("display"), where + ".display", Set.of("locale", "name", "description", "logoUri"), Set.of("name")));
            f.put("identifiers", items(m.get("identifiers"), where + ".identifiers", Set.of("type", "value"), Set.of("type", "value")));
            f.put("certificates", many(m.get("certificates"), where + ".certificates"));
            f.put("authorizations", items(m.get("authorizations"), where + ".authorizations", Set.of("format", "type"), Set.of()));
            f.put("status", optional(m, "status", where));
            f.put("validFrom", optional(m, "validFrom", where));
            f.put("validUntil", optional(m, "validUntil", where));
            f.put("contexts", contextEntries(m.get("contexts"), where + ".contexts"));
            f.put("attributes", named(m.get("attributes"), where + ".attributes"));
            f.put("metadataPolicy", optional(m, "metadataPolicy", where));
            f.put("framework", optional(m, "framework", where));
            for (Value v : values(f.get("roles"))) {
                check(v, EntityRole.class, "role", where + ".roles");
            }
            check((Value) f.get("status"), EntityStatus.class, "status", where + ".status");
            for (Item item : items(f.get("identifiers"))) {
                check(item.members.get("type"), IdentifierType.class, "identifier type", where + ".identifiers.type");
            }
            return new Block(where, each, true, flag(m, "allowEmpty", where), f);
        }

        static Block anchor(Object raw, String where) {
            Map<String, Object> m = members(raw, where, ANCHOR_MEMBERS);
            JsonPath each = each(m, where, true);
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", optional(m, "id", where));
            f.put("domain", required(m, "domain", where));
            f.put("certificate", required(m, "certificate", where));
            f.put("entity", optional(m, "entity", where));
            f.put("status", optional(m, "status", where));
            f.put("docTypes", many(m.get("docTypes"), where + ".docTypes"));
            f.put("crlUrls", many(m.get("crlUrls"), where + ".crlUrls"));
            f.put("crl", optional(m, "crl", where));
            f.put("framework", optional(m, "framework", where));
            check((Value) f.get("status"), EntityStatus.class, "status", where + ".status");
            return new Block(where, each, false, flag(m, "allowEmpty", where), f);
        }

        private static JsonPath each(Map<String, Object> m, String where, boolean required) {
            Object each = m.get("each");
            if (each == null) {
                if (required) {
                    throw new IllegalArgumentException(where + ": each is required (the path whose every match is one record)");
                }
                return JsonPath.parse("$");
            }
            if (!(each instanceof String s) || !(s.startsWith("$") || s.startsWith("^"))) {
                throw new IllegalArgumentException(where + ".each must be a path");
            }
            return pathAt(s, where + ".each");
        }

        /** The records this block finds in a document. */
        List<Object> records(Object root) {
            List<Object> out = new ArrayList<>();
            for (Object o : each.select(root, root)) {
                if (o != null) {
                    out.add(o);
                }
            }
            return out;
        }

        /**
         * One record as an entry in the registry format. A member that yields nothing is left out; one that yields
         * something of the wrong kind (an object where text belongs, a date that is not one) is an error, and the
         * caller skips the record: a malformed {@code validUntil} must not make a party valid forever. No member can
         * name a file ({@code certificateLocation} is not one of them): a document from elsewhere never makes the
         * service read one.
         */
        Map<String, Object> map(Object record, Object root) {
            Map<String, Object> out = new LinkedHashMap<>();
            if (entity) {
                put(out, "id", text("id", record, root));
                putList(out, "roles", texts("roles", record, root));
                put(out, "name", text("name", record, root));
                putList(out, "display", objects("display", record, root, Set.of("name")));
                putList(out, "identifiers", objects("identifiers", record, root, Set.of("type", "value")));
                putList(out, "certificates", texts("certificates", record, root));
                putList(out, "authorizations", objects("authorizations", record, root, Set.of()));
                put(out, "status", text("status", record, root));
                put(out, "validFrom", instant("validFrom", record, root));
                put(out, "validUntil", instant("validUntil", record, root));
                putList(out, "contexts", contexts(record, root));
                Map<String, Object> attributes = new LinkedHashMap<>();
                @SuppressWarnings("unchecked")
                Map<String, Value> named = (Map<String, Value>) fields.get("attributes");
                named.forEach((k, v) -> put(attributes, k, v.first(record, root)));
                if (!attributes.isEmpty()) {
                    out.put("attributes", attributes);
                }
                Value policy = (Value) fields.get("metadataPolicy");
                Object p = policy == null ? null : policy.first(record, root);
                if (p != null && !(p instanceof Map<?, ?>)) {
                    throw new IllegalArgumentException("metadataPolicy is not an object");
                }
                put(out, "metadataPolicy", p);
            } else {
                put(out, "id", text("id", record, root));
                put(out, "domain", text("domain", record, root));
                put(out, "certificate", text("certificate", record, root));
                put(out, "entity", text("entity", record, root));
                put(out, "status", text("status", record, root));
                Map<String, Object> constraints = new LinkedHashMap<>();
                putList(constraints, "docTypes", texts("docTypes", record, root));
                putList(constraints, "crlUrls", texts("crlUrls", record, root));
                put(constraints, "crl", text("crl", record, root));
                if (!constraints.isEmpty()) {
                    out.put("constraints", constraints);
                }
            }
            put(out, "framework", text("framework", record, root));
            return out;
        }

        private static void put(Map<String, Object> out, String key, Object value) {
            if (value != null) {
                out.put(key, value);
            }
        }

        private static void putList(Map<String, Object> out, String key, List<?> value) {
            if (!value.isEmpty()) {
                out.put(key, value);
            }
        }

        private String text(String member, Object record, Object root) {
            Value v = (Value) fields.get(member);
            return v == null ? null : scalar(v.first(record, root), member);
        }

        private List<String> texts(String member, Object record, Object root) {
            List<String> out = new ArrayList<>();
            for (Value v : values(fields.get(member))) {
                for (Object o : v.all(record, root)) {
                    out.add(scalar(o, member));
                }
            }
            return out;
        }

        /** A date as an ISO instant: an ISO date-time or date, or seconds since the epoch (a number or digits). */
        private String instant(String member, Object record, Object root) {
            Value v = (Value) fields.get(member);
            Object found = v == null ? null : v.first(record, root);
            if (found == null) {
                return null;
            }
            Instant i = Mapping.instant(found);
            if (i == null) {
                throw new IllegalArgumentException(member + " is not a date: " + quote(found));
            }
            return i.toString();
        }

        /** Nested items: one per match of the item's {@code each}, or one; left out without a required member. */
        private List<Map<String, Object>> objects(String member, Object record, Object root, Set<String> required) {
            return objects(items(fields.get(member)), member, record, root, required);
        }

        private static List<Map<String, Object>> objects(List<Item> items, String member, Object record, Object root,
                                                         Set<String> required) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Item item : items) {
                List<Object> matches = item.each == null ? List.of(record) : item.each.select(record, root);
                for (Object match : matches) {
                    if (match == null) {
                        continue;
                    }
                    Map<String, Object> o = new LinkedHashMap<>();
                    item.members.forEach((k, v) -> put(o, k, scalar(v.first(match, root), member + "." + k)));
                    if (o.keySet().containsAll(required) && !o.isEmpty()) {
                        out.add(o);
                    }
                }
            }
            return out;
        }

        private List<Object> contexts(Object record, Object root) {
            List<Object> out = new ArrayList<>();
            @SuppressWarnings("unchecked")
            List<Object> entries = (List<Object>) fields.get("contexts");
            for (Object e : entries) {
                if (e instanceof Value v) {
                    for (Object o : v.all(record, root)) {
                        out.add(scalar(o, "contexts"));
                    }
                } else {
                    out.addAll(objects(List.of((Item) e), "contexts", record, root, Set.of("url")));
                }
            }
            return out;
        }

        private static String scalar(Object v, String member) {
            if (v == null) {
                return null;
            }
            String t = Value.text(v);
            if (t == null) {
                throw new IllegalArgumentException(member + " is " + (v instanceof Map<?, ?> ? "an object" : "a list") + ", not a value");
            }
            return t;
        }
    }

    /** A value from a document, quoted and cut short, for a message. */
    static String quote(Object v) {
        String s = String.valueOf(Value.text(v) != null ? Value.text(v) : v instanceof Map<?, ?> ? "{...}" : "[...]");
        return "'" + (s.length() <= 40 ? s : s.substring(0, 40) + "…") + "'";
    }

    /** A nested item (an identifier, an authorization, a display, a context): its own {@code each}, and members. */
    record Item(JsonPath each, Map<String, Value> members) {
    }

    private static List<Value> many(Object raw, String where) {
        if (raw == null) {
            return List.of();
        }
        List<Value> out = new ArrayList<>();
        if (raw instanceof List<?> l) {
            for (int i = 0; i < l.size(); i++) {
                out.add(Value.parse(l.get(i), where + "[" + i + "]"));
            }
        } else {
            out.add(Value.parse(raw, where));
        }
        return List.copyOf(out);
    }

    private static List<Item> items(Object raw, String where, Set<String> allowed, Set<String> required) {
        if (raw == null) {
            return List.of();
        }
        if (!(raw instanceof List<?> l)) {
            throw new IllegalArgumentException(where + " must be a list of {" + String.join(", ", new TreeSet<>(allowed)) + "}");
        }
        List<Item> out = new ArrayList<>();
        for (int i = 0; i < l.size(); i++) {
            out.add(item(l.get(i), where + "[" + i + "]", allowed, required));
        }
        return List.copyOf(out);
    }

    private static Item item(Object raw, String where, Set<String> allowed, Set<String> required) {
        Set<String> all = new LinkedHashSet<>(allowed);
        all.add("each");
        Map<String, Object> m = members(raw, where, all);
        JsonPath each = null;
        if (m.containsKey("each")) {
            if (!(m.get("each") instanceof String s) || !(s.startsWith("$") || s.startsWith("^"))) {
                throw new IllegalArgumentException(where + ".each must be a path");
            }
            each = pathAt(s, where + ".each");
        }
        Map<String, Value> members = new LinkedHashMap<>();
        for (String k : allowed) {
            if (m.containsKey(k)) {
                members.put(k, Value.parse(m.get(k), where + "." + k));
            } else if (required.contains(k)) {
                throw new IllegalArgumentException(where + ": " + k + " is required");
            }
        }
        if (members.isEmpty()) {
            throw new IllegalArgumentException(where + " maps nothing");
        }
        return new Item(each, java.util.Collections.unmodifiableMap(members));
    }

    /** Contexts: a URL as a value form, or {url, sha256} items (a pinned digest). */
    private static List<Object> contextEntries(Object raw, String where) {
        if (raw == null) {
            return List.of();
        }
        List<?> entries = raw instanceof List<?> l ? l : List.of(raw);
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            Object e = entries.get(i);
            if (e instanceof Map<?, ?> m && (m.containsKey("url") || m.containsKey("each") || m.containsKey("sha256"))) {
                out.add(item(e, where + "[" + i + "]", Set.of("url", "sha256"), Set.of("url")));
            } else {
                out.add(Value.parse(e, where + "[" + i + "]"));
            }
        }
        return List.copyOf(out);
    }

    private static Map<String, Value> named(Object raw, String where) {
        if (raw == null) {
            return Map.of();
        }
        if (!(raw instanceof Map<?, ?> m) || m.isEmpty()) {
            throw new IllegalArgumentException(where + " must be a map of names to values");
        }
        Map<String, Value> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(String.valueOf(k), Value.parse(v, where + "." + k)));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Value> values(Object field) {
        return field == null ? List.of() : (List<Value>) field;
    }

    @SuppressWarnings("unchecked")
    private static List<Item> items(Object field) {
        return field == null ? List.of() : (List<Item>) field;
    }

    private static Value required(Map<String, Object> m, String key, String where) {
        if (!m.containsKey(key)) {
            throw new IllegalArgumentException(where + ": " + key + " is required");
        }
        return Value.parse(m.get(key), where + "." + key);
    }

    private static Value optional(Map<String, Object> m, String key, String where) {
        return m.containsKey(key) ? Value.parse(m.get(key), where + "." + key) : null;
    }

    private static JsonPath pathAt(String path, String where) {
        try {
            return JsonPath.parse(path);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + ": " + e.getMessage(), e);
        }
    }

    /** A constant that must name an enumeration value is checked now, not when the first document arrives. */
    private static <E extends Enum<E>> void check(Value v, Class<E> type, String what, String where) {
        if (v == null) {
            return;
        }
        for (Object c : v.constants()) {
            try {
                Enums.parse(type, Value.text(c), what);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(where + ": " + e.getMessage(), e);
            }
        }
    }

    /** A map with only the given members; anything else is an error, so that nothing is silently ignored. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> members(Object raw, String where, Set<String> allowed) {
        if (!(raw instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException(where + " must be a map");
        }
        TreeSet<String> unknown = new TreeSet<>();
        for (Object k : m.keySet()) {
            if (!allowed.contains(String.valueOf(k))) {
                unknown.add(String.valueOf(k));
            }
        }
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(where + ": unknown member" + (unknown.size() > 1 ? "s " : " ") + unknown
                    + "; known: " + new TreeSet<>(allowed));
        }
        return (Map<String, Object>) m;
    }

    static List<?> list(Object raw, String where) {
        if (raw instanceof List<?> l && !l.isEmpty()) {
            return l;
        }
        if (raw instanceof String s && !s.isBlank()) {
            return List.of(s);
        }
        throw new IllegalArgumentException(where + " must be a list that is not empty");
    }

    /** A member that is true or false (Spring hands a configured boolean over as text); absent is false. */
    static boolean flag(Map<String, Object> m, String key, String where) {
        Object v = m.get(key);
        if (v == null || Boolean.FALSE.equals(v) || "false".equals(v)) {
            return false;
        }
        if (Boolean.TRUE.equals(v) || "true".equals(v)) {
            return true;
        }
        throw new IllegalArgumentException(where + "." + key + " must be true or false");
    }

    static int positive(Object raw, String where) {
        try {
            int n = raw instanceof Number num ? Math.toIntExact(num.longValue()) : Integer.parseInt(String.valueOf(raw).trim());
            if (n > 0 && (!(raw instanceof Number num) || num.doubleValue() == n)) {
                return n;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // fall through
        }
        throw new IllegalArgumentException(where + " must be a positive whole number");
    }

    /** The most seconds since the epoch a date is written with: the twelve digits its text form may have. */
    private static final BigDecimal MAX_EPOCH_SECONDS = BigDecimal.valueOf(999_999_999_999L);

    /**
     * A number of seconds since the epoch as an instant: from 0 to 999,999,999,999 (the twelve digits a date's text
     * form may have), else null. A fraction is cut off, unless {@code whole}, when a number with one is null too.
     * Bounded whatever the number: its size is compared before anything is computed from it.
     */
    static Instant epochSeconds(Number n, boolean whole) {
        BigDecimal d = StrictJson.decimal(n);
        if (d == null || d.signum() < 0 || d.compareTo(MAX_EPOCH_SECONDS) > 0) {
            return null;
        }
        if (whole && d.stripTrailingZeros().scale() > 0) {
            return null;
        }
        return Instant.ofEpochSecond(d.longValue());
    }

    /** An ISO date-time or date, or seconds since the epoch (a number or a string of digits); null for anything else. */
    static Instant instant(Object v) {
        try {
            if (v instanceof Number n) {
                return Instant.ofEpochSecond(n.longValue());
            }
            if (!(v instanceof String s)) {
                return null;
            }
            String t = s.trim();
            if (t.matches("[0-9]{1,12}")) {
                return Instant.ofEpochSecond(Long.parseLong(t));
            }
            if (t.length() == 10) {
                return LocalDate.parse(t).atStartOfDay().toInstant(ZoneOffset.UTC);
            }
            return java.time.OffsetDateTime.parse(t).toInstant();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
