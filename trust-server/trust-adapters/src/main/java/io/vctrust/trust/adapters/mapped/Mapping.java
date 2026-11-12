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

    /**
     * How the pages of a list link, and what they say about themselves.
     *
     * @param number where a page says its own number (null when not mapped)
     * @param count  where a page says how many pages the list has (null when not mapped)
     */
    record Pages(Value next, int max, Value number, Value count) {
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

    /**
     * The members of an entity that say whom a record is about: through them a key is tied to the entry, and the entry
     * to a question. A record in which one of them cannot be read cannot keep anybody out by being listed.
     */
    static final List<String> IDENTIFYING = List.of("id", "roles", "identifiers", "certificates");

    /**
     * What one record yields: its entry in the registry format, with every member that could be read, the members that
     * could not, each with why (in the order the record was read), and how many characters of mapped text the entry
     * holds.
     */
    record Mapped(Map<String, Object> entry, Map<String, String> unusable, int text) {
    }

    /**
     * The most characters of mapped text one record yields, all its members together: a path from the root repeats
     * what it finds into every record, so that a small document could otherwise make a registry of gigabytes.
     */
    static final int MAX_RECORD_TEXT = 65_536;

    /**
     * The characters of mapped text in a value: text, numbers and booleans as written, and the names of an object's
     * members; counted up to {@code limit + 1} at most, so that the cost is bounded too.
     *
     * @throws IllegalArgumentException naming {@code member}, for a text in it longer than {@link Value#MAX_TEXT}
     */
    static int weight(Object v, String member, int limit) {
        if (v instanceof Map<?, ?> m) {
            int total = 0;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                total += weight(e.getKey(), member, limit - total);
                if (total <= limit) {
                    total += weight(e.getValue(), member, limit - total);
                }
                if (total > limit) {
                    return total;
                }
            }
            return total;
        }
        if (v instanceof List<?> l) {
            int total = 0;
            for (Object o : l) {
                total += weight(o, member, limit - total);
                if (total > limit) {
                    return total;
                }
            }
            return total;
        }
        String t = Value.text(v);
        if (t == null) {
            return 0;
        }
        if (t.length() > Value.MAX_TEXT) {
            throw new IllegalArgumentException(member + ": a value of " + t.length() + " characters, more than " + Value.MAX_TEXT);
        }
        return t.length();
    }

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
            Map<String, Object> p = members(m.get("pages"), "mapping.pages", Set.of("next", "max", "number", "count"));
            if (!p.containsKey("next")) {
                throw new IllegalArgumentException("mapping.pages: next is required");
            }
            pages = new Pages(Value.parse(p.get("next"), "mapping.pages.next"),
                    p.containsKey("max") ? positive(p.get("max"), "mapping.pages.max") : DEFAULT_MAX_PAGES,
                    optional(p, "number", "mapping.pages"), optional(p, "count", "mapping.pages"));
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
        if (probe.getRawUserInfo() != null) {
            // As for location: a credential in the URL would be named wherever the URL is.
            throw new IllegalArgumentException("mapping.lookup.url must not hold credentials; send them in headers");
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
        /** The members a record must yield; one that yields none of them is skipped. */
        final List<String> required;
        private final Map<String, Object> fields;

        private Block(String where, JsonPath each, boolean entity, boolean allowEmpty, List<String> required, Map<String, Object> fields) {
            this.where = where;
            this.each = each;
            this.entity = entity;
            this.allowEmpty = allowEmpty;
            this.required = required;
            this.fields = fields;
        }

        /** Members that say how the block is read, not what a record yields. */
        private static final Set<String> CONTROL = Set.of("each", "allowEmpty", "required");
        static final Set<String> ENTITY_MEMBERS = Set.of("each", "allowEmpty", "required", "id", "roles", "name", "display",
                "identifiers", "certificates", "authorizations", "status", "validFrom", "validUntil", "contexts", "attributes",
                "metadataPolicy", "framework");
        static final Set<String> ANCHOR_MEMBERS = Set.of("each", "allowEmpty", "required", "id", "domain", "certificate", "entity",
                "status", "docTypes", "crlUrls", "crl", "framework");

        /** @param eachRequired false for a lookup's answer, where {@code each} defaults to the whole document */
        static Block entity(Object raw, String where, boolean eachRequired) {
            Map<String, Object> m = members(raw, where, ENTITY_MEMBERS);
            JsonPath each = each(m, where, eachRequired);
            if (!eachRequired && m.containsKey("allowEmpty")) {
                throw new IllegalArgumentException(where + ": allowEmpty applies to the blocks of entities and anchors");
            }
            List<String> required = requiredMembers(m, where, ENTITY_MEMBERS);
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
            return new Block(where, each, true, flag(m, "allowEmpty", where), required, f);
        }

        static Block anchor(Object raw, String where) {
            Map<String, Object> m = members(raw, where, ANCHOR_MEMBERS);
            JsonPath each = each(m, where, true);
            List<String> required = requiredMembers(m, where, ANCHOR_MEMBERS);
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
            return new Block(where, each, false, flag(m, "allowEmpty", where), required, f);
        }

        /**
         * {@code required}: members of the block that the block maps. A name that is not a member, or one the block
         * does not map (it could never yield anything, and every record would be skipped), is an error.
         */
        private static List<String> requiredMembers(Map<String, Object> m, String where, Set<String> members) {
            if (!m.containsKey("required")) {
                return List.of();
            }
            TreeSet<String> known = new TreeSet<>(members);
            known.removeAll(CONTROL);
            List<String> out = new ArrayList<>();
            for (Object o : list(m.get("required"), where + ".required")) {
                String name = String.valueOf(o);
                if (!known.contains(name)) {
                    throw new IllegalArgumentException(where + ".required: '" + name + "' is not a member of the block; members: " + known);
                }
                if (!m.containsKey(name)) {
                    throw new IllegalArgumentException(where + ".required: names " + name + ", which the block does not map");
                }
                out.add(name);
            }
            return List.copyOf(out);
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
         * One record as an entry in the registry format, member by member. Absent is absent; present but unusable
         * is said for the member. A member whose path matches nothing (or null) is left out. One that finds something
         * of the wrong kind (an object where text belongs, text where a list or an object must be, a date that is not
         * one) cannot be read, and is named with why in {@link Mapped#unusable}: a malformed {@code validUntil} must
         * not make a party valid forever, nor a list of doctypes written as one string leave an IACA unconstrained.
         * So is a configured {@code status} that yields nothing, an authorization item that lacks a member its mapping
         * configures, and a {@code required} member that yields nothing. What the caller makes of a record that
         * cannot be read completely depends on what it is (see {@link #IDENTIFYING}). No member can name a file
         * ({@code certificateLocation} is not one of them): a document from elsewhere never makes the service read one.
         */
        Mapped map(Object record, Object root) {
            Reader r = new Reader();
            if (entity) {
                // What identifies the record first: what it says about whom matters most.
                r.read("id", () -> text("id", record, root));
                r.read("roles", () -> roles(record, root));
                r.read("identifiers", () -> objects("identifiers", record, root, Set.of("type", "value"), Items.WHOLE));
                r.read("certificates", () -> texts("certificates", record, root));
                r.read("name", () -> text("name", record, root));
                r.read("display", () -> objects("display", record, root, Set.of("name"), Items.LEAVE_OUT));
                r.read("authorizations", () -> objects("authorizations", record, root, Set.of(), Items.STRICT));
                r.read("status", () -> text("status", record, root));
                r.read("validFrom", () -> instant("validFrom", record, root));
                r.read("validUntil", () -> instant("validUntil", record, root));
                r.read("contexts", () -> contexts(record, root));
                r.read("attributes", () -> attributes(record, root));
                r.read("metadataPolicy", () -> policy(record, root));
            } else {
                r.read("id", () -> text("id", record, root));
                r.read("domain", () -> text("domain", record, root));
                r.read("certificate", () -> text("certificate", record, root));
                r.read("entity", () -> text("entity", record, root));
                r.read("status", () -> text("status", record, root));
                r.read("docTypes", () -> texts("docTypes", record, root));
                r.read("crlUrls", () -> texts("crlUrls", record, root));
                r.read("crl", () -> text("crl", record, root));
            }
            r.read("framework", () -> text("framework", record, root));
            if (fields.get("status") != null && !r.values.containsKey("status")) {
                // A state the mapping does not know is not good standing, and a status left out reads as ACTIVE.
                r.unusable.putIfAbsent("status", "status yields nothing (no value at its path, or one its translation does not "
                        + "know); give status a default to say what such a record is");
            }
            for (String member : required) {
                if (!r.values.containsKey(member)) {
                    r.unusable.putIfAbsent(member, member + " is required and yields nothing");
                }
            }
            Map<String, Object> out = new LinkedHashMap<>(r.values);
            if (!entity) {
                Map<String, Object> constraints = new LinkedHashMap<>();
                for (String c : List.of("docTypes", "crlUrls", "crl")) {
                    if (out.containsKey(c)) {
                        constraints.put(c, out.remove(c));
                    }
                }
                Object framework = out.remove("framework");
                if (!constraints.isEmpty()) {
                    out.put("constraints", constraints);
                }
                if (framework != null) {
                    out.put("framework", framework);
                }
            }
            return new Mapped(out, java.util.Collections.unmodifiableMap(r.unusable), r.text);
        }

        /**
         * Reads one member at a time: what it yields, or why it cannot be read. A member that would take the record's
         * mapped text beyond {@link #MAX_RECORD_TEXT} cannot be read either.
         */
        private static final class Reader {
            final Map<String, Object> values = new LinkedHashMap<>();
            final Map<String, String> unusable = new LinkedHashMap<>();
            int text;

            void read(String member, java.util.function.Supplier<Object> value) {
                try {
                    Object v = value.get();
                    if (v != null && !(v instanceof List<?> l && l.isEmpty()) && !(v instanceof Map<?, ?> m && m.isEmpty())) {
                        int weight = weight(v, member, MAX_RECORD_TEXT - text);
                        if (text + weight > MAX_RECORD_TEXT) {
                            throw new IllegalArgumentException(member + ": the record's mapped text would be more than "
                                    + MAX_RECORD_TEXT + " characters");
                        }
                        text += weight;
                        values.put(member, v);
                    }
                } catch (RuntimeException e) {
                    unusable.put(member, e.getMessage() == null ? member + " cannot be read (" + e.getClass().getSimpleName() + ")"
                            : e.getMessage());
                }
            }
        }

        private Map<String, Object> attributes(Object record, Object root) {
            Map<String, Object> attributes = new LinkedHashMap<>();
            @SuppressWarnings("unchecked")
            Map<String, Value> named = (Map<String, Value>) fields.get("attributes");
            named.forEach((k, v) -> {
                Object found = first(v, "attributes." + k, record, root);
                weight(found, "attributes." + k, MAX_RECORD_TEXT);   // an object's texts are mapped text too
                put(attributes, k, found);
            });
            return attributes;
        }

        private Object policy(Object record, Object root) {
            Value policy = (Value) fields.get("metadataPolicy");
            Object p = policy == null ? null : first(policy, "metadataPolicy", record, root);
            if (p != null && !(p instanceof Map<?, ?>)) {
                throw new IllegalArgumentException("metadataPolicy is not an object");
            }
            return p;
        }

        /** A value form evaluated for one member: what is wrong with what it finds is said for that member. */
        private static Object first(Value v, String member, Object current, Object root) {
            try {
                return v.first(current, root);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(member + ": " + e.getMessage(), e);
            }
        }

        private static List<Object> all(Value v, String member, Object current, Object root) {
            try {
                return v.all(current, root);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(member + ": " + e.getMessage(), e);
            }
        }

        private static List<Object> select(JsonPath p, String member, Object current, Object root) {
            try {
                return p.select(current, root);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(member + ": " + e.getMessage(), e);
            }
        }

        private static void put(Map<String, Object> out, String key, Object value) {
            if (value != null) {
                out.put(key, value);
            }
        }

        private String text(String member, Object record, Object root) {
            Value v = (Value) fields.get(member);
            return v == null ? null : scalar(first(v, member, record, root), member);
        }

        private List<String> texts(String member, Object record, Object root) {
            List<String> out = new ArrayList<>();
            for (Value v : values(fields.get(member))) {
                for (Object o : all(v, member, record, root)) {
                    out.add(scalar(o, member));
                }
                bounded(out, member);
            }
            return out;
        }

        /** A member yields at most {@link Value#MAX_VALUES} values for one record, all its forms and items together. */
        private static void bounded(List<?> values, String member) {
            if (values.size() > Value.MAX_VALUES) {
                throw new IllegalArgumentException(member + ": " + Value.tooMany().getMessage());
            }
        }

        /**
         * A date as an ISO instant: an ISO date-time or date, or seconds since the epoch (a whole number, or digits,
         * of at most twelve digits). Anything else is not a date: a time in milliseconds is not one in seconds.
         */
        private String instant(String member, Object record, Object root) {
            Value v = (Value) fields.get(member);
            Object found = v == null ? null : first(v, member, record, root);
            if (found == null) {
                return null;
            }
            Instant i = Mapping.instant(found);
            if (i == null) {
                throw new IllegalArgumentException(member + " is not a date: " + quote(found));
            }
            return i.toString();
        }

        /** The roles: a value the roles' translation does not know (and no default) is one the mapping cannot read. */
        private List<String> roles(Object record, Object root) {
            List<String> out = texts("roles", record, root);
            for (Value v : values(fields.get("roles"))) {
                if (v instanceof Value.Translated t) {
                    Object unknown = t.untranslated(record, root);
                    if (unknown != null) {
                        throw new IllegalArgumentException("roles: " + quote(unknown) + " is not one of the values its translation knows, "
                                + "and it has no default");
                    }
                }
            }
            return out;
        }

        /** What an item that is not all there is (see {@link #objects}). */
        enum Items {
            /** Left out (display, context URLs): it restricts nothing and identifies nobody. */
            LEAVE_OUT,
            /**
             * Absent when no member that reads the document yields anything; otherwise every member it needs must yield
             * (identifiers): an identifier whose value is there but not its type would leave the party's key without
             * its entry.
             */
            WHOLE,
            /**
             * Every member the mapping configures must yield, and an item yields something (authorizations): an
             * authorization without its type would cover every type of its format, and one without anything would
             * leave the entity unconstrained for a lenient client.
             */
            STRICT
        }

        /** Nested items: one per match of the item's {@code each}, or one; {@code needs} are the members an item must have. */
        private List<Map<String, Object>> objects(String member, Object record, Object root, Set<String> needs, Items rule) {
            return objects(items(fields.get(member)), member, record, root, needs, rule);
        }

        private static List<Map<String, Object>> objects(List<Item> items, String member, Object record, Object root,
                                                         Set<String> needs, Items rule) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Item item : items) {
                List<Object> matches = item.each == null ? List.of(record) : select(item.each, member, record, root);
                bounded(matches, member);   // before any is mapped: each costs the evaluation of the item's members
                for (Object match : matches) {
                    if (match == null) {
                        continue;
                    }
                    Map<String, Object> o = new LinkedHashMap<>();
                    List<String> fromDocument = new ArrayList<>();
                    for (Map.Entry<String, Value> e : item.members.entrySet()) {
                        String k = e.getKey();
                        put(o, k, scalar(first(e.getValue(), member + "." + k, match, root), member + "." + k));
                        if (rule == Items.STRICT && !o.containsKey(k)) {
                            throw new IllegalArgumentException(member + ": an item yields no " + k
                                    + "; an authorization is never left open where the document does not say so");
                        }
                        if (o.containsKey(k) && !(e.getValue() instanceof Value.Constant)) {
                            fromDocument.add(k);
                        }
                    }
                    if (o.keySet().containsAll(needs) && !o.isEmpty()) {
                        out.add(o);
                    } else if (rule == Items.WHOLE && !fromDocument.isEmpty()) {
                        List<String> missing = needs.stream().filter(k -> !o.containsKey(k)).sorted().toList();
                        throw new IllegalArgumentException(member + ": an item yields " + String.join(" and ", fromDocument) + " but no "
                                + String.join(" or ", missing));
                    }
                }
                bounded(out, member);
            }
            return out;
        }

        private List<Object> contexts(Object record, Object root) {
            List<Object> out = new ArrayList<>();
            @SuppressWarnings("unchecked")
            List<Object> entries = (List<Object>) fields.get("contexts");
            for (Object e : entries) {
                if (e instanceof Value v) {
                    for (Object o : all(v, "contexts", record, root)) {
                        out.add(scalar(o, "contexts"));
                    }
                } else {
                    out.addAll(objects(List.of((Item) e), "contexts", record, root, Set.of("url"), Items.LEAVE_OUT));
                }
                bounded(out, "contexts");
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
            if (t.length() > Value.MAX_TEXT) {
                throw new IllegalArgumentException(member + ": a value of " + t.length() + " characters, more than " + Value.MAX_TEXT);
            }
            return t;
        }
    }

    /** A value from a document, quoted, cut short and with its control characters escaped, for a message. */
    static String quote(Object v) {
        String s = String.valueOf(Value.text(v) != null ? Value.text(v) : v instanceof Map<?, ?> ? "{...}" : "[...]");
        return "'" + escape(s.length() <= 40 ? s : s.substring(0, 40) + "…") + "'";
    }

    /**
     * Text with its control characters (CR, LF and the others below 0x20, and DEL) written as escapes: text from a
     * document goes into messages that are written to the log, where a line break would let it forge a log line.
     */
    static String escape(String s) {
        StringBuilder out = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                if (out == null) {
                    out = new StringBuilder(s.length() + 16).append(s, 0, i);
                }
                switch (c) {
                    case '\r' -> out.append("\\r");
                    case '\n' -> out.append("\\n");
                    case '\t' -> out.append("\\t");
                    default -> out.append(String.format("\\u%04x", (int) c));
                }
            } else if (out != null) {
                out.append(c);
            }
        }
        return out == null ? s : out.toString();
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
        for (String k : new TreeSet<>(allowed)) {   // in a fixed order, so that a message names the same member each time
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

    /**
     * A whole number from 0 to 18 digits: a number without a fraction ({@code 5.0} is 5) or a string of digits; null for
     * anything else. Bounded whatever the number: a document holds only numbers {@link StrictJson} found small.
     */
    static Long whole(Object v) {
        try {
            if (v instanceof Number n) {
                BigDecimal d = StrictJson.decimal(n);
                if (d == null || d.signum() < 0) {
                    return null;
                }
                BigDecimal s = d.stripTrailingZeros();
                return s.scale() > 0 || s.precision() - s.scale() > 18 ? null : s.longValueExact();
            }
            return v instanceof String s && s.matches("[0-9]{1,18}") ? Long.valueOf(s) : null;
        } catch (ArithmeticException e) {
            return null;
        }
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

    /**
     * An ISO date-time or date, or seconds since the epoch: a string of one to twelve digits, or a whole number in that
     * range. Null for anything else, which is not a date.
     */
    static Instant instant(Object v) {
        try {
            if (v instanceof Number n) {
                return epochSeconds(n, true);
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
