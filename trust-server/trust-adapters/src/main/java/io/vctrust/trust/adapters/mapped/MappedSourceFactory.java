package io.vctrust.trust.adapters.mapped;

import io.vctrust.trust.adapters.support.AdapterSupport;
import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code type: mapped}: an external trust service or list that speaks JSON, read by configuration alone. The
 * properties say where the document is ({@code location}), what authenticates it ({@code format}, {@code verify}), what
 * to send with requests to its origin ({@code headers}) and how its structure maps onto the registry ({@code mapping}
 * or {@code mappingLocation}; see {@link Mapping}). Every record is turned into an entry in the registry format and
 * read by {@link TrustedEntityParser}, so a mapped record is held to the rules of a hand-written one.
 *
 * <p>The document is someone else's and is read as hostile input: strictly parsed and bounded in depth, pages and
 * records; it can name web locations only on the origin of {@code location}, never a file of this host; its
 * entries land in the source's framework or nowhere. The configuration is checked when the source is created; an
 * error in it (an unknown property, mapping member, value form or enum value) makes every load fail with that
 * message, which the source's state shows.
 */
public final class MappedSourceFactory implements TrustSourceFactory {

    static final String TYPE = "mapped";

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public TrustSource create(SourceDefinition definition, SourceContext context) {
        return new MappedSource(definition, context);
    }

    static final Set<String> PROPERTIES = Set.of("location", "publicUri", "headers", "format", "verify", "allowUnverified",
            "allowExpired", "mapping", "mappingLocation", "limits");
    static final int DEFAULT_MAX_ENTITIES = 5_000;
    static final int DEFAULT_MAX_ANCHORS = 1_000;
    /** The characters of mapped text one load may yield, all records together (64 Mi). */
    static final int DEFAULT_MAX_TEXT = 67_108_864;
    /** How long a load may still be fetching pages: whoever serves them slowly would otherwise hold the load forever. */
    static final Duration DEFAULT_MAX_DURATION = Duration.ofMinutes(5);
    static final int MAX_WARNINGS = 50;
    static final Duration ON_DEMAND_TTL = Duration.ofMinutes(10);
    static final Duration ON_DEMAND_NEGATIVE_TTL = Duration.ofMinutes(1);
    static final Duration ON_DEMAND_FAILURE_TTL = Duration.ofSeconds(30);
    static final int ON_DEMAND_MAX_ENTRIES = 5_000;
    /** The characters of mapped text the remembered lookups may hold, all together (16 Mi). */
    static final long ON_DEMAND_MAX_TEXT = 16_777_216;
    /** The longest identifier a lookup asks about. */
    static final int MAX_IDENTIFIER = 4_096;
    /** A list issued further in the future than this would make every genuine list after it look older. */
    static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    /** How long after its iat a signed lookup answer without exp counts, unless lookup.maxAge says otherwise. */
    static final Duration DEFAULT_LOOKUP_MAX_AGE = Duration.ofHours(24);
    /** The identifiers the admin API accepts for an entry: an id from a document is held to the same rule. */
    private static final Pattern ENTRY_ID = TrustedEntityParser.ENTRY_ID;
    private static final String ENTRY_ID_RULE = "its id is not 1 to 128 letters, digits or . _ : @ ~ - starting with a letter or digit";
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    /** A document from elsewhere names no file: whatever would load one is refused. */
    private static final ResourceLoader NO_FILES = location -> {
        throw new IOException("A mapped record cannot name a location");
    };

    /** The configuration, as read and checked when the source is created. */
    record Config(String location, URI origin, String publicUri, Map<String, String> headers, boolean jws, PinnedKeys keys,
                  boolean allowUnverified, boolean allowExpired, int maxEntities, int maxAnchors, int maxText, Duration maxDuration,
                  Mapping mapping) {

        /**
         * Header names only, and the location without its query: header values are credentials, a query often holds
         * one, and a record's own text would carry them into any log line.
         */
        @Override
        public String toString() {
            return "Config[location=" + withoutQueries(location) + ", headers=" + new TreeSet<>(headers.keySet()) + ", format="
                    + (jws ? "jws" : "json") + ", pinnedKeys=" + keys.configured() + ", allowUnverified=" + allowUnverified
                    + ", allowExpired=" + allowExpired + "]";
        }
    }

    /**
     * A web URL up to its query (group 1), and its query and fragment up to the next whitespace (group 2). Possessive:
     * linear in the text. Not anchored at a word boundary: {@code x_https://...} is a URL too.
     */
    private static final Pattern QUERY = Pattern.compile("(?i)(https?://[^\\s?#]*+)([?#]\\S*+)");
    /** Punctuation that ends a sentence or a quotation rather than a query, kept after a URL cut short. */
    private static final String TRAILING = ".,:;)]>'\"";
    /** The longest message this source hands to anyone (a source state shows less: the registry's bound). */
    static final int MAX_MESSAGE = 2_000;
    /** The longest warning: warnings are many, and each names one record. */
    static final int MAX_WARNING = 300;

    /**
     * Text with every web URL in it cut before its query and fragment, up to the next whitespace or the end. The query
     * of {@code location}, of a page URL or of a lookup URL is where a credential is often put (an API key, a signed
     * link); the outbound client names whole URLs in its errors, so no message, warning, state or log line of this
     * source names a URL with its query. Punctuation right after a URL ("... from https://host/list?key=x: refused",
     * a closing quote) is the sentence's, and stays.
     */
    static String withoutQueries(String text) {
        if (text == null) {
            return null;
        }
        Matcher m = QUERY.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        while (m.find()) {
            String query = m.group(2);
            int end = query.length();
            while (end > 1 && TRAILING.indexOf(query.charAt(end - 1)) >= 0) {
                end--;
            }
            m.appendReplacement(out, Matcher.quoteReplacement(m.group(1) + query.substring(end)));
        }
        m.appendTail(out);
        return out.toString();
    }

    /**
     * Text as this source hands it to anyone (an exception's message, a warning, the list's issuer): without the query
     * of any URL in it, its control, format and separator characters escaped, at most {@code max} characters. In one
     * place, so that text from outside (a JWS header, a certificate's names, a document's values, a client's identifier)
     * cannot reach a caller raw, nor make what this source holds and throws half a megabyte long, wherever it came in.
     * What a source state and a log line show of it, the registry bounds again for every source (ForeignText, 500
     * characters); it leaves an escape written here as it is.
     */
    static String told(String text, int max) {
        if (text == null) {
            return null;
        }
        String t = Mapping.escape(withoutQueries(text));
        return t.length() <= max ? t : t.substring(0, max - 1) + "…";
    }

    static Config read(SourceDefinition def, ResourceLoader resources) throws IOException {
        Map<String, Object> p = def.properties();
        TreeSet<String> unknown = new TreeSet<>(p.keySet());
        unknown.removeAll(PROPERTIES);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("unknown propert" + (unknown.size() > 1 ? "ies " : "y ") + unknown
                    + "; known: " + new TreeSet<>(PROPERTIES));
        }
        String location = text(p, "location");
        URI origin = null;
        if (location != null && ResourceLoader.isRemote(location)) {
            URI u = uri(location, "location");
            if (u.getRawUserInfo() != null) {
                throw new IllegalArgumentException("location must not hold credentials; send them in headers");
            }
            origin = u;
        }
        String format = text(p, "format");
        if (format != null && !format.equals("json") && !format.equals("jws")) {
            throw new IllegalArgumentException("format must be json or jws, not '" + format + "'");
        }
        boolean jws = "jws".equals(format);
        PinnedKeys keys = PinnedKeys.none();
        if (p.containsKey("verify")) {
            if (!jws) {
                throw new IllegalArgumentException("verify applies to format: jws only");
            }
            keys = PinnedKeys.read(Mapping.members(p.get("verify"), "verify", PinnedKeys.MEMBERS), resources);
        }
        boolean allowUnverified = bool(p, "allowUnverified");
        if (p.containsKey("allowUnverified") && !jws) {
            throw new IllegalArgumentException("allowUnverified applies to format: jws only");
        }
        if (allowUnverified && keys.configured()) {
            throw new IllegalArgumentException("allowUnverified and pinned keys contradict each other; remove one");
        }
        if (jws && !keys.configured() && !allowUnverified) {
            throw new IllegalArgumentException("format: jws needs the keys the list is signed with (verify: jwks, jwksLocation, "
                    + "certificates or certificateLocation), or allowUnverified: true to load it on the strength of its transport alone");
        }
        Object rawMapping;
        if (p.containsKey("mapping") == p.containsKey("mappingLocation")) {
            throw new IllegalArgumentException("give either mapping or mappingLocation");
        }
        if (p.containsKey("mappingLocation")) {
            String ml = text(p, "mappingLocation");
            if (ml == null || ResourceLoader.isRemote(ml)) {
                throw new IllegalArgumentException("mappingLocation must be a file: or classpath: location or a path, not one on the network");
            }
            rawMapping = AdapterSupport.parseYamlOrJson(resources.load(ml));
        } else {
            rawMapping = p.get("mapping");
        }
        Mapping mapping = Mapping.parse(rawMapping);
        if (location == null) {
            if (mapping.lookup == null) {
                throw new IllegalArgumentException("location is required (only a source that looks up and lists nothing goes without)");
            }
            if (!mapping.entities.isEmpty() || !mapping.anchors.isEmpty() || mapping.list != null || mapping.pages != null) {
                throw new IllegalArgumentException("mapping.entities, anchors, list and pages read the document at location, "
                        + "which this source does not have");
            }
            origin = uri(mapping.lookup.url().replace("{identifier}", "x"), "mapping.lookup.url");
        } else if (mapping.entities.isEmpty() && mapping.anchors.isEmpty()) {
            throw new IllegalArgumentException("mapping has no entities or anchors to read from location");
        }
        if (mapping.pages != null && (location == null || !ResourceLoader.isRemote(location))) {
            throw new IllegalArgumentException("mapping.pages needs an https location: the next pages are on its origin");
        }
        if (!jws && mapping.lookup != null && mapping.lookup.maxAge() != null) {
            throw new IllegalArgumentException("mapping.lookup.maxAge applies to format: jws: it bounds how long after its iat "
                    + "a signed answer counts");
        }
        if (jws && mapping.pages != null && (mapping.list == null || mapping.list.sequence() == null && mapping.list.issuedAt() == null)) {
            throw new IllegalArgumentException("format: jws with pages needs list.sequence or list.issuedAt mapped: each page is "
                    + "signed on its own, and only a fact that every page repeats ties a page to the others (a page of an older "
                    + "list, or another document of the same signer, would otherwise pass for one)");
        }
        Map<String, String> headers = headers(p.get("headers"), origin);
        String publicUri = text(p, "publicUri");
        if (publicUri != null) {
            URI u = uri(publicUri, "publicUri");
            if (u.getRawUserInfo() != null) {
                throw new IllegalArgumentException("publicUri must not hold credentials");
            }
        }
        int maxEntities = DEFAULT_MAX_ENTITIES;
        int maxAnchors = DEFAULT_MAX_ANCHORS;
        int maxText = DEFAULT_MAX_TEXT;
        Duration maxDuration = DEFAULT_MAX_DURATION;
        if (p.containsKey("limits")) {
            Map<String, Object> l = Mapping.members(p.get("limits"), "limits", Set.of("entities", "anchors", "text", "duration"));
            maxEntities = l.containsKey("entities") ? Mapping.positive(l.get("entities"), "limits.entities") : maxEntities;
            maxAnchors = l.containsKey("anchors") ? Mapping.positive(l.get("anchors"), "limits.anchors") : maxAnchors;
            maxText = l.containsKey("text") ? Mapping.positive(l.get("text"), "limits.text") : maxText;
            maxDuration = l.containsKey("duration") ? Mapping.duration(l.get("duration"), "limits.duration", "PT5M") : maxDuration;
        }
        return new Config(location, origin, publicUri, headers, jws, keys, allowUnverified, bool(p, "allowExpired"),
                maxEntities, maxAnchors, maxText, maxDuration, mapping);
    }

    private static String text(Map<String, Object> p, String key) {
        Object v = p.get(key);
        if (v == null) {
            return null;
        }
        if (!(v instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException(key + " must be text");
        }
        return s.trim();
    }

    private static boolean bool(Map<String, Object> p, String key) {
        Object v = p.get(key);
        if (v == null || Boolean.FALSE.equals(v) || "false".equals(v)) {
            return false;
        }
        if (Boolean.TRUE.equals(v) || "true".equals(v)) {
            return true;
        }
        throw new IllegalArgumentException(key + " must be true or false");
    }

    private static URI uri(String s, String what) {
        try {
            URI u = new URI(s);
            if (u.getHost() == null || !("https".equals(u.getScheme()) || "http".equals(u.getScheme()))) {
                throw new IllegalArgumentException(what + " must be an http(s) URL with a host");
            }
            return u;
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException(what + " is not a URL");
        }
    }

    /** Header names are checked; their values are never repeated in a message. */
    private static Map<String, String> headers(Object raw, URI origin) {
        if (raw == null) {
            return Map.of();
        }
        if (!(raw instanceof Map<?, ?> m) || m.isEmpty()) {
            throw new IllegalArgumentException("headers must be a map of header names to values");
        }
        if (origin == null) {
            throw new IllegalArgumentException("headers are sent to the origin of an https location; this source has none");
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            String name = String.valueOf(e.getKey());
            if (!HEADER_NAME.matcher(name).matches() || name.equalsIgnoreCase("Host")) {
                throw new IllegalArgumentException("headers: '" + name + "' cannot be sent as a header name");
            }
            if (!(e.getValue() instanceof String value) || value.chars().anyMatch(c -> c < 0x20 && c != '\t' || c == 0x7f)) {
                throw new IllegalArgumentException("headers: the value of " + name + " must be text on one line");
            }
            out.put(name, value);
        }
        return Map.copyOf(out);
    }

    /** RFC 6454 origin: scheme, host, port (the scheme's default when none is written). */
    static boolean sameOrigin(URI a, URI b) {
        return a != null && b != null && a.getScheme() != null && a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getHost() != null && a.getHost().equalsIgnoreCase(b.getHost()) && port(a) == port(b);
    }

    private static int port(URI u) {
        return u.getPort() != -1 ? u.getPort() : "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
    }

    static final class MappedSource implements TrustSource, OnDemandResolver {

        private static final Logger log = LoggerFactory.getLogger(MappedSource.class);

        private final SourceDefinition def;
        private final SourceContext ctx;
        private final Config config;
        private final String configError;
        private final Memo<Optional<TrustedEntity>> answers;

        MappedSource(SourceDefinition def, SourceContext ctx) {
            this.def = def;
            this.ctx = ctx;
            Config c = null;
            String error = null;
            try {
                c = read(def, ctx.resources());
            } catch (IOException | RuntimeException e) {
                error = withoutQueries("Source '" + def.id() + "' (mapped): " + e.getMessage());
            }
            this.config = c;
            this.configError = error;
            this.answers = new Memo<>(ON_DEMAND_MAX_ENTRIES, ON_DEMAND_MAX_TEXT, ctx.clock());
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        /**
         * The failure of a load or a lookup as this source reports it ({@link #told}): without the query of any URL it
         * names, its control characters escaped, at most {@link #MAX_MESSAGE} characters; and without the exception it
         * came from, whose message may name a URL.
         */
        private static TrustSourceException reported(TrustSourceException e) {
            String message = told(e.getMessage(), MAX_MESSAGE);
            return message != null && message.equals(e.getMessage()) ? e : new TrustSourceException(message);
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
            try {
                return loadList();
            } catch (TrustSourceException e) {
                throw reported(e);
            } catch (RuntimeException e) {
                throw reported(unexpected(e));
            }
        }

        /**
         * Whatever else goes wrong inside a load or a lookup is that load's or that lookup's failure: no exception of
         * another kind leaves this source, whatever a document holds.
         */
        private static TrustSourceException unexpected(RuntimeException e) {
            return new TrustSourceException("The document cannot be read (" + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage()) + ")");
        }

        private SourceLoadResult loadList() throws TrustSourceException {
            if (configError != null) {
                throw new TrustSourceException(configError);
            }
            Instant now = ctx.clock().instant();
            Warnings warnings = new Warnings();
            Provenance provenance = Provenance.of(def.id(), TYPE, def.frameworkId(), publishedLocation(), now);
            if (config.location() == null) {
                return new SourceLoadResult(List.of(), List.of(), new ListInfo(null, null, null, null, signature(),
                        Map.of("lookupOnly", true)), List.of());
            }
            if (config.allowUnverified()) {
                log.warn("Trust source '{}' (mapped): the list's signature is not verified (allowUnverified)", def.id());
                warnings.add("The list's signature is not verified (allowUnverified)");
            }
            Mapping.Pages paging = config.mapping().pages;
            if (config.jws() && paging != null && (paging.number() == null || paging.count() == null)) {
                // Each page is signed on its own: a page served at another's address, or a next link that ends early,
                // is a signed page all the same. The numbers alone do not show a list ended early, and the count alone
                // does not show one page served twice in place of another: only both together tie the pages.
                log.warn("Trust source '{}' (mapped): the list's pages do not say both their number and their count; whoever "
                        + "serves them can leave one out", def.id());
                warnings.add("The list comes in pages that are signed one by one and do not say both their number and their count "
                        + "(mapping.pages.number, mapping.pages.count): whoever serves them can leave one out");
            }
            Numbering numbering = new Numbering();
            Tally[] entityTallies = tallies(config.mapping().entities);
            Tally[] anchorTallies = tallies(config.mapping().anchors);
            Text text = new Text(config.maxText(), "The list's records");
            List<TrustedEntity> entities = new ArrayList<>();
            List<TrustAnchor> anchors = new ArrayList<>();
            int entityRecords = 0;
            int anchorRecords = 0;
            Facts first = null;
            Facts facts = null;
            Set<String> visited = new HashSet<>();
            List<Unread> unread = new ArrayList<>();
            Document page = null;
            int pages = 0;
            try {
                while (true) {
                    if (page == null) {
                        page = ResourceLoader.isRemote(config.location()) ? fetch(URI.create(config.location()), now, warnings)
                                : new Document(document(ctx.resources().load(config.location()), now, warnings, false), null);
                        first = mapped(page.root());
                        facts = facts(first, page.root(), now, warnings);
                        if (page.uri() != null) {
                            // The address asked and the one the page was finally read from, after redirects: a later
                            // page read from either is this one again, served in place of another.
                            visited.add(URI.create(config.location()).toString());
                            visited.add(page.uri().toString());
                        }
                    }
                    pages++;
                    numbered(page.root(), pages, numbering);
                    for (int b = 0; b < config.mapping().entities.size(); b++) {
                        Mapping.Block block = config.mapping().entities.get(b);
                        List<Object> records = block.records(page.root());
                        entityRecords += records.size();
                        if (entityRecords > config.maxEntities()) {
                            throw new TrustSourceException("The list has more than " + config.maxEntities() + " entity records (limits.entities)");
                        }
                        for (Object record : records) {
                            Tally t = entityTallies[b];
                            t.count(mapEntity(block, record, page.root(), provenance, t.records + 1, text), warnings);
                        }
                    }
                    for (int b = 0; b < config.mapping().anchors.size(); b++) {
                        Mapping.Block block = config.mapping().anchors.get(b);
                        List<Object> records = block.records(page.root());
                        anchorRecords += records.size();
                        if (anchorRecords > config.maxAnchors()) {
                            throw new TrustSourceException("The list has more than " + config.maxAnchors() + " anchor records (limits.anchors)");
                        }
                        for (Object record : records) {
                            Object mapped = mapAnchor(block, record, page.root(), provenance, text);
                            if (mapped instanceof Skipped s && !s.certificates().isEmpty()) {
                                unread.add(new Unread(anchorTallies[b].records + 1, s));
                            }
                            anchorTallies[b].count(mapped, warnings);
                        }
                    }
                    for (Tally t : entityTallies) {
                        entities.addAll(t.take(TrustedEntity.class));
                    }
                    for (Tally t : anchorTallies) {
                        anchors.addAll(t.take(TrustAnchor.class));
                    }
                    URI next = next(page, visited, pages);
                    if (numbering.count != null && (next == null) != (pages == numbering.count)) {
                        throw new TrustSourceException("The list says it has " + numbering.count + " pages, and "
                                + (next == null ? pages + " were read" : "page " + pages + " links to another"));
                    }
                    if (next == null) {
                        break;
                    }
                    inTime(now);
                    page = fetch(next, now, warnings);
                    inTime(now);
                    if (!page.uri().toString().equals(next.toString()) && !visited.add(page.uri().toString())) {
                        throw new TrustSourceException("Page " + (pages + 1) + " of the list was read from an address already read, "
                                + "after a redirect: a page served again in place of another");
                    }
                    samePage(first, page.root(), pages + 1);
                }
            } catch (IOException e) {
                throw new TrustSourceException("Cannot read the list: " + e.getMessage(), e);
            } catch (IllegalArgumentException e) {
                throw new TrustSourceException("The list cannot be read: " + e.getMessage(), e);
            }
            for (Tally t : entityTallies) {
                t.check(warnings);
            }
            for (Tally t : anchorTallies) {
                t.check(warnings);
            }
            anchors = onePerId(anchors);
            unread(anchors, unread);
            entities = strictest(entities, warnings);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("pages", pages);
            details.put("format", config.jws() ? "jws" : "json");
            // The list's issuer goes into the source's state and the log, as a message does: escaped and cut the same way.
            ListInfo info = new ListInfo(told(facts.issuer(), MAX_MESSAGE), facts.sequence(), facts.issuedAt(), facts.nextUpdate(),
                    signature(), details);
            return new SourceLoadResult(entities, anchors, info, warnings.list());
        }

        /**
         * One anchor per id. Records of one load that map to the same id must say the same thing (certificate, domain,
         * status, entity, constraints), and then are one anchor; otherwise the load fails. The registry keeps the first
         * anchor of an id, so a CA withdrawn further down the list would stay active. Records with the same domain and
         * certificate must agree on status, entity and constraints whatever their ids: a CA listed active as
         * {@code row-1} and withdrawn as {@code row-7} would otherwise be trusted through {@code row-1}.
         */
        private static List<TrustAnchor> onePerId(List<TrustAnchor> anchors) throws TrustSourceException {
            Map<String, TrustAnchor> byId = new LinkedHashMap<>();
            Map<List<Object>, TrustAnchor> byCertificate = new java.util.HashMap<>();
            for (TrustAnchor a : anchors) {
                TrustAnchor same = byCertificate.putIfAbsent(List.of(a.domain().name(), a.certificate()), a);
                if (same != null && !Objects.equals(same.id(), a.id())) {
                    List<String> differ = new ArrayList<>();
                    if (same.status() != a.status()) {
                        differ.add("status");
                    }
                    if (!Objects.equals(same.entityId(), a.entityId())) {
                        differ.add("entity");
                    }
                    if (!same.constraints().equals(a.constraints())) {
                        differ.add("constraints");
                    }
                    if (!differ.isEmpty()) {
                        throw new TrustSourceException("Anchors " + Mapping.quote(same.id()) + " and " + Mapping.quote(a.id())
                                + " have the same certificate in domain " + a.domain().name() + " and a different "
                                + String.join(" and ", differ.size() <= 2 ? differ : List.of(String.join(", ", differ.subList(0, differ.size() - 1)),
                                differ.getLast())) + ": which one holds cannot be told");
                    }
                }
                TrustAnchor held = byId.putIfAbsent(a.id(), a);
                if (held == null) {
                    continue;
                }
                List<String> differ = new ArrayList<>();
                if (!held.certificate().equals(a.certificate())) {
                    differ.add("certificate");
                }
                if (!held.domain().equals(a.domain())) {
                    differ.add("domain");
                }
                if (held.status() != a.status()) {
                    differ.add("status");
                }
                if (!Objects.equals(held.entityId(), a.entityId())) {
                    differ.add("entity");
                }
                if (!held.constraints().equals(a.constraints())) {
                    differ.add("constraints");
                }
                if (!differ.isEmpty()) {
                    throw new TrustSourceException("Anchor " + Mapping.quote(a.id()) + " is given twice in the list with a different "
                            + String.join(" and ", differ.size() <= 2 ? differ : List.of(String.join(", ", differ.subList(0, differ.size() - 1)),
                            differ.getLast())) + ": which one holds cannot be told");
                }
            }
            return List.copyOf(byId.values());
        }

        /**
         * Records of one load that give one id are one entity: the registry merges them (one entity per country of a
         * certificate list, say), taking the union of what they list. Within the load none of them may relax or hide
         * what another states: each gets the strictest status, the latest validFrom and the earliest validUntil of
         * them all, with a warning when they disagreed. (The registry's merge kept the stricter status already, but the
         * first record's validity, so that a later record's earlier end was lost.)
         */
        private static List<TrustedEntity> strictest(List<TrustedEntity> entities, Warnings warnings) {
            Map<String, List<TrustedEntity>> byId = new LinkedHashMap<>();
            entities.forEach(e -> byId.computeIfAbsent(e.id(), k -> new ArrayList<>()).add(e));
            if (byId.size() == entities.size()) {
                return entities;
            }
            Map<String, TrustedEntity> strictest = new LinkedHashMap<>();
            byId.forEach((id, records) -> {
                if (records.size() == 1) {
                    return;
                }
                EntityStatus status = records.getFirst().status();
                Instant from = null;
                Instant until = null;
                for (TrustedEntity e : records) {
                    status = e.status().ordinal() > status.ordinal() ? e.status() : status;   // as the registry ranks them
                    from = e.validFrom() == null || from != null && !e.validFrom().isAfter(from) ? from : e.validFrom();
                    until = e.validUntil() == null || until != null && !e.validUntil().isBefore(until) ? until : e.validUntil();
                }
                EntityStatus s = status;
                Instant f = from;
                Instant u = until;
                if (records.stream().anyMatch(e -> e.status() != s || !Objects.equals(e.validFrom(), f) || !Objects.equals(e.validUntil(), u))) {
                    warnings.add("Entity " + Mapping.quote(id) + " has " + records.size() + " records that disagree on its status or "
                            + "validity; each keeps the strictest: status " + s + ", valid from " + (f == null ? "always" : f)
                            + ", valid until " + (u == null ? "no end" : u));
                    strictest.put(id, records.getFirst().toBuilder().status(s).validFrom(f).validUntil(u).build());
                }
            });
            if (strictest.isEmpty()) {
                return entities;
            }
            List<TrustedEntity> out = new ArrayList<>(entities.size());
            for (TrustedEntity e : entities) {
                TrustedEntity s = strictest.get(e.id());
                out.add(s == null ? e : e.toBuilder().status(s.status()).validFrom(s.validFrom()).validUntil(s.validUntil()).build());
            }
            return out;
        }

        /**
         * Several records about one party: the first, with the strictest status, the latest validFrom and the earliest
         * validUntil of them all, as {@link #strictest} does for the records of one id in a list. Which record comes
         * first in an answer must not decide that a party revoked in another one is in good standing.
         */
        private static TrustedEntity strictestOf(List<TrustedEntity> records) {
            TrustedEntity first = records.getFirst();
            EntityStatus status = first.status();
            Instant from = first.validFrom();
            Instant until = first.validUntil();
            for (TrustedEntity e : records) {
                status = e.status().ordinal() > status.ordinal() ? e.status() : status;
                from = e.validFrom() != null && (from == null || e.validFrom().isAfter(from)) ? e.validFrom() : from;
                until = e.validUntil() != null && (until == null || e.validUntil().isBefore(until)) ? e.validUntil() : until;
            }
            return records.size() == 1 ? first : first.toBuilder().status(status).validFrom(from).validUntil(until).build();
        }

        /**
         * Where this source says its content comes from, by the rule every adapter shares
         * ({@link AdapterSupport#publishedLocation}): {@code publicUri} when set, else its location when that is an
         * http(s) URL, without any query. A location on this host (a path, {@code file:}, {@code classpath:}) is not
         * published.
         */
        private String publishedLocation() {
            return AdapterSupport.publishedLocation(def, config.location());
        }

        private ListInfo.SignatureStatus signature() {
            if (!config.jws()) {
                return ListInfo.SignatureStatus.NOT_SIGNED;
            }
            return config.keys().configured() ? ListInfo.SignatureStatus.VERIFIED : ListInfo.SignatureStatus.NOT_CHECKED;
        }

        private record Document(Object root, URI uri) {
        }

        /**
         * A load still fetching pages {@code limits.duration} after it started fails: whoever serves the pages slowly
         * (each within the outbound client's timeouts) would otherwise hold the load, and the refresh of this source,
         * for as long as it likes. Checked before and after each page after the first.
         */
        private void inTime(Instant started) throws TrustSourceException {
            if (ctx.clock().instant().isAfter(started.plus(config.maxDuration()))) {
                throw new TrustSourceException("The list is still being read after " + config.maxDuration() + " (limits.duration)");
            }
        }

        /** What the first page says about the pages: the count, when it is mapped. */
        private static final class Numbering {
            Long count;
        }

        /**
         * Page {@code k} says what the mapping reads from it about the pages: with {@code pages.number}, its own number
         * (the first page {@code pages.first}, every later one the next); with {@code pages.count}, the count the first
         * page says. Each page of a signed list is signed on its own, so only this ties a page to its place: page 3
         * served at page 2's address, with page 2 left out, would otherwise pass. Which number the first page has is
         * the configuration's to say: a list that counts from 0 would otherwise begin at its page 1, whichever page
         * is served first.
         */
        private void numbered(Object root, int k, Numbering n) throws TrustSourceException {
            Mapping.Pages p = config.mapping().pages;
            if (p == null) {
                return;
            }
            if (p.number() != null) {
                long said = pageFact(p.number(), "number", root, k);
                long expected = p.first() + k - 1L;
                if (said != expected) {
                    throw new TrustSourceException("Page " + k + " of the list says it is page " + said + ", not " + expected
                            + (k == 1 ? " (mapping.pages.first)" : ""));
                }
            }
            if (p.count() != null) {
                long said = pageFact(p.count(), "count", root, k);
                if (k == 1) {
                    if (said < 1 || said > p.max()) {
                        throw new TrustSourceException("The list says it has " + said + " pages, " + (said < 1 ? "none"
                                : "more than " + p.max() + " (mapping.pages.max)"));
                    }
                    n.count = said;
                } else if (said != n.count) {
                    throw new TrustSourceException("Page " + k + " of the list says it has " + said + " pages where page 1 says " + n.count);
                }
            }
        }

        private static long pageFact(Value v, String member, Object root, int k) throws TrustSourceException {
            Object found = v.first(root, root);
            Long n = Mapping.whole(found);
            if (n == null) {
                throw new TrustSourceException("mapping.pages." + member + ": page " + k + " of the list has no number there"
                        + (found == null ? "" : ": " + Mapping.quote(found)));
            }
            return n;
        }

        /** The next page: on the origin of location, never one already read, at most pages.max in all. */
        private URI next(Document page, Set<String> visited, int pages) throws TrustSourceException {
            Mapping.Pages p = config.mapping().pages;
            if (p == null) {
                return null;
            }
            Object raw = p.next().first(page.root(), page.root());
            String text = Value.text(raw);
            if (raw != null && text == null) {
                throw new TrustSourceException("mapping.pages.next is not a URL in the document");
            }
            if (text == null || text.isBlank()) {
                return null;
            }
            URI next;
            // The next page is named without its query (a cursor, a signature), as every URL this source names.
            String shown = Mapping.quote(text.trim().split("[?#]", 2)[0]);
            try {
                next = page.uri().resolve(new URI(text.trim()));
            } catch (java.net.URISyntaxException | IllegalArgumentException e) {
                throw new TrustSourceException("The next page " + shown + " is not a URL");
            }
            if (!sameOrigin(next, config.origin())) {
                throw new TrustSourceException("The next page " + shown + " is not on the origin of location");
            }
            if (!visited.add(next.toString())) {
                throw new TrustSourceException("The pages link back to a page already read");
            }
            if (pages >= p.max()) {
                throw new TrustSourceException("The list has more than " + p.max() + " pages (mapping.pages.max)");
            }
            return next;
        }

        /** GET with the configured headers when the URL is on the origin of location, and Accept otherwise. */
        private HttpFetcher.Response get(URI uri) throws IOException {
            Map<String, String> h = new LinkedHashMap<>();
            if (sameOrigin(uri, config.origin())) {
                h.putAll(config.headers());
            }
            if (h.keySet().stream().noneMatch("Accept"::equalsIgnoreCase)) {
                h.put("Accept", config.jws() ? "application/jwt, application/jose" : "application/json");
            }
            return ctx.http().execute(new HttpFetcher.Request("GET", uri, h, null, null));
        }

        private Document fetch(URI uri, Instant now, Warnings warnings) throws IOException, TrustSourceException {
            HttpFetcher.Response r = get(uri);
            if (!r.isSuccess()) {
                throw new HttpFetcher.HttpStatusException(uri, r.status());
            }
            return new Document(document(r.body(), now, warnings, false), r.finalUri() == null ? uri : r.finalUri());
        }

        /**
         * The JSON of a document: for a JWS, its payload once the signature has verified.
         *
         * @param answer whether it is a lookup answer, which {@code allowExpired} never covers
         */
        private Object document(byte[] body, Instant now, Warnings warnings, boolean answer) throws TrustSourceException {
            byte[] json = body;
            if (config.jws()) {
                String compact = new String(body, StandardCharsets.US_ASCII).trim();
                json = config.keys().configured() ? config.keys().verify(compact, now) : config.keys().unverifiedPayload(compact);
            }
            Object root;
            try {
                root = StrictJson.parse(json);
            } catch (IllegalArgumentException e) {
                throw new TrustSourceException("The document is " + e.getMessage());
            }
            if (config.jws()) {
                // A payload that is not an object has no claims: none that verify.issuer asks for, either.
                jwtClaims(root instanceof Map<?, ?> claims ? claims : Map.of(), now, warnings, answer);
            }
            return root;
        }

        /**
         * A JWS whose payload is a JWT is held to its claims (RFC 7519 section 4.1): not after {@code exp}, not before
         * {@code nbf}, only when addressed to this service when it names an audience at all, and only from the issuer
         * {@code verify.issuer} names, when it names one. An {@code iat} must be a NumericDate too. {@code allowExpired}
         * is for a list an operator decides to keep using; a lookup answer past its {@code exp} is never accepted.
         */
        private void jwtClaims(Map<?, ?> claims, Instant now, Warnings warnings, boolean answer) throws TrustSourceException {
            numericDate(claims, "iat");
            String issuer = config.keys().issuer();
            if (issuer != null) {
                Object iss = claims.get("iss");
                if (iss == null) {
                    throw new TrustSourceException("The document names no issuer (iss); verify.issuer is '" + issuer + "'");
                }
                if (!issuer.equals(iss)) {
                    throw new TrustSourceException("The document's issuer (iss) is " + Mapping.quote(iss) + ", not '" + issuer
                            + "' (verify.issuer)");
                }
            }
            Instant exp = numericDate(claims, "exp");
            if (exp != null && now.isAfter(exp.plus(Duration.ofSeconds(60)))) {
                if (answer) {
                    throw new TrustSourceException("The answer expired at " + exp + " (exp); allowExpired does not apply to lookup answers");
                }
                if (!config.allowExpired()) {
                    throw new TrustSourceException("The list expired at " + exp + " (exp) and is not loaded (allowExpired: true overrides)");
                }
                log.warn("Trust source '{}' (mapped): the list expired at {} (exp); loaded because of allowExpired", def.id(), exp);
                warnings.add("The list expired at " + exp + " (exp; allowExpired)");
            }
            Instant nbf = numericDate(claims, "nbf");
            if (nbf != null && nbf.isAfter(now.plus(Duration.ofSeconds(60)))) {
                throw new TrustSourceException("The list is not valid before " + nbf + " (nbf)");
            }
            Object aud = claims.get("aud");
            if (aud != null) {
                List<String> audiences = aud instanceof List<?> l ? l.stream().map(String::valueOf).toList() : List.of(String.valueOf(aud));
                String mine = config.keys().audience();
                if (mine == null || !audiences.contains(mine)) {
                    throw new TrustSourceException("The list is addressed to " + Mapping.quote(String.join(", ", audiences))
                            + (mine == null ? "; name this service's audience there in verify.audience" : ", not to '" + mine + "'"));
                }
            }
        }

        private static Instant numericDate(Map<?, ?> claims, String name) throws TrustSourceException {
            Object v = claims.get(name);
            if (v == null) {
                return null;
            }
            Instant i = v instanceof Number n ? Mapping.epochSeconds(n, false) : null;
            if (i == null) {
                throw new TrustSourceException("The list's " + name + " is not a NumericDate");
            }
            return i;
        }

        private record Facts(String issuer, String sequence, Instant issuedAt, Instant nextUpdate) {
        }

        /** The list facts the mapping names. One it names that the document lacks fails the load: the format has changed. */
        private Facts mapped(Object root) throws TrustSourceException {
            Mapping.ListFacts l = config.mapping().list;
            if (l == null) {
                return new Facts(null, null, null, null);
            }
            return new Facts(fact(l.issuer(), "issuer", root), sequence(l.sequence(), root),
                    date(l.issuedAt(), "issuedAt", root), date(l.nextUpdate(), "nextUpdate", root));
        }

        /**
         * The list's sequence, which orders lists: a list numbered lower than the one held is refused. Only a whole
         * number of at most 18 digits can do that ({@code 5.0} is 5, written as 5); {@code v5}, {@code 1.2.3} or a
         * 19-digit number would order nothing, and a list that replays an older one would pass.
         */
        private static String sequence(Value v, Object root) throws TrustSourceException {
            if (v == null) {
                return null;
            }
            Object found = v.first(root, root);
            if (found == null) {
                throw new TrustSourceException("mapping.list.sequence: the document has no value for it");
            }
            Long n = Mapping.whole(found);
            if (n == null) {
                throw new TrustSourceException("mapping.list.sequence: " + Mapping.quote(found) + " is not a whole number of at most "
                        + "18 digits, so it cannot order lists; map issuedAt instead");
            }
            return n.toString();
        }

        /**
         * A page after the first repeats the facts of the first: every one the mapping names, with the same value. Each
         * page is fetched (and, for a JWS, signed) on its own; a page of an older list, or another document of the same
         * signer, is not a page of this one, and a list that changed between two requests is not one list either.
         */
        private void samePage(Facts first, Object root, int page) throws TrustSourceException {
            Facts these;
            try {
                these = mapped(root);
            } catch (TrustSourceException e) {
                throw new TrustSourceException("Page " + page + " of the list: " + e.getMessage());
            }
            differs("issuer", first.issuer(), these.issuer(), page);
            differs("sequence", first.sequence(), these.sequence(), page);
            differs("issuedAt", first.issuedAt(), these.issuedAt(), page);
            differs("nextUpdate", first.nextUpdate(), these.nextUpdate(), page);
        }

        private static void differs(String fact, Object first, Object here, int page) throws TrustSourceException {
            if (!Objects.equals(first, here)) {
                throw new TrustSourceException("Page " + page + " of the list says " + fact + " " + shown(here)
                        + " where page 1 says " + shown(first) + ": the pages are not of one list");
            }
        }

        private static String shown(Object fact) {
            return fact == null ? "nothing" : fact instanceof Instant i ? i.toString() : Mapping.quote(fact);
        }

        /**
         * Page 1's facts, held to what they say: not past the next update, not issued in the future. When the mapping
         * names no issue time, a signed list's own ({@code iat}) is the list's: a list older than the one held is then
         * refused without any mapping.
         */
        private Facts facts(Facts f, Object root, Instant now, Warnings warnings) throws TrustSourceException {
            String issuer = f.issuer();
            String sequence = f.sequence();
            Instant issuedAt = f.issuedAt();
            Instant nextUpdate = f.nextUpdate();
            if (issuedAt == null && config.jws() && root instanceof Map<?, ?> claims) {
                issuedAt = numericDate(claims, "iat");
            }
            if (nextUpdate != null && now.isAfter(nextUpdate)) {
                if (!config.allowExpired()) {
                    throw new TrustSourceException("The list is past its next update " + nextUpdate
                            + " and is not loaded (allowExpired: true overrides)");
                }
                log.warn("Trust source '{}' (mapped): the list is past its next update {}; loaded because of allowExpired", def.id(), nextUpdate);
                warnings.add("The list is past its next update " + nextUpdate + " (allowExpired)");
            }
            if (issuedAt != null && issuedAt.isAfter(now.plus(CLOCK_SKEW))) {
                throw new TrustSourceException("The list says it was issued at " + issuedAt + ", in the future");
            }
            return new Facts(issuer, sequence, issuedAt, nextUpdate);
        }

        private static String fact(Value v, String name, Object root) throws TrustSourceException {
            if (v == null) {
                return null;
            }
            String t = Value.text(v.first(root, root));
            if (t == null) {
                throw new TrustSourceException("mapping.list." + name + ": the document has no value for it");
            }
            if (t.length() > Value.MAX_TEXT) {
                throw new TrustSourceException("mapping.list." + name + ": a value of " + t.length() + " characters, more than "
                        + Value.MAX_TEXT);
            }
            return t;
        }

        private static Instant date(Value v, String name, Object root) throws TrustSourceException {
            if (v == null) {
                return null;
            }
            Object found = v.first(root, root);
            Instant i = Mapping.instant(found);
            if (i == null) {
                throw new TrustSourceException("mapping.list." + name + ": the document has " + (found == null ? "no value for it"
                        : "no date there: " + Mapping.quote(found)));
            }
            return i;
        }

        /**
         * One record as an entity. A record that cannot be read completely is never dropped: leaving its entry out
         * would leave out every restriction it states, while a chain to an anchor of the list still decides trusted
         * (by design, also without an entity). So:
         *
         * <ul>
         *   <li>when what says whom the record is about ({@link Mapping#IDENTIFYING}) cannot be read, or there is no
         *       id, listing the record could keep nobody out: the load fails, naming the record and the member;</li>
         *   <li>when anything else cannot be read, the entity is listed with what could be read, not in good standing
         *       (SUSPENDED, or the stricter status the record states), and a warning says what was left out and why;</li>
         *   <li>so when its id is text the registry cannot take as an entry's id ({@link #refusedId}): it is listed
         *       under an id derived from it ({@link #derivedId}), not in good standing, and the warning gives both.
         *       Refused, or left out by the registry, the record would restrict nobody.</li>
         * </ul>
         *
         * @param number the record's number in its block, for messages
         * @return a {@link TrustedEntity} read completely, a {@link Noted} or an {@link Incomplete} one
         * @throws TrustSourceException when the record cannot be listed at all
         */
        private Object mapEntity(Mapping.Block block, Object record, Object root, Provenance provenance, int number, Text text)
                throws TrustSourceException {
            Mapping.Mapped m = block.map(record, root);
            text.charge(m.weight());
            Map<String, Object> entry = new LinkedHashMap<>(m.entry());
            Map<String, String> unusable = new LinkedHashMap<>(m.unusable());
            String id = entry.get("id") instanceof String s ? s : null;
            String label = label(number, id);
            for (String member : Mapping.IDENTIFYING) {
                if (unusable.containsKey(member)) {
                    throw unreadable(block, label, unusable.get(member));
                }
            }
            if (id == null) {
                throw unreadable(block, label, "it yields no id");
            }
            if (!entry.containsKey("roles")) {
                // The evaluator considers only the entries that have the role asked about: listed without one, the
                // record would restrict nobody, and its party's key would be left to whatever anchor it chains to.
                throw unreadable(block, label, "it yields no role");
            }
            String notAnId = refusedId(id);
            if (notAnId != null) {
                String derived = derivedId(id);
                unusable.put("id", "its id " + Mapping.quote(id) + " is listed as '" + derived + "': it " + notAnId);
                entry.put("id", derived);
                id = derived;
                label = label(number, derived);
            }
            TrustedEntity entity;
            try {
                entity = TrustedEntityParser.entity(entry, def.frameworkId(), provenance, NO_FILES);
            } catch (Exception e) {
                // Which members the registry format refuses: each is read on its own, with the record's id.
                for (String member : List.copyOf(entry.keySet())) {
                    if (member.equals("id")) {
                        continue;
                    }
                    try {
                        TrustedEntityParser.entity(Map.of("id", id, member, entry.get(member)), def.frameworkId(), provenance, NO_FILES);
                    } catch (Exception refused) {
                        String why = member + ": " + message(refused);
                        if (Mapping.IDENTIFYING.contains(member)) {
                            throw unreadable(block, label, why);
                        }
                        unusable.put(member, why);
                        entry.remove(member);
                    }
                }
                try {
                    entity = TrustedEntityParser.entity(entry, def.frameworkId(), provenance, NO_FILES);
                } catch (Exception refused) {
                    throw unreadable(block, label, message(refused));
                }
            }
            // Text that only describes the party and was too long to keep is left out, and said: the record is read.
            String leftOut = m.leftOut().isEmpty() ? null : "without text too long to keep: " + String.join("; ", m.leftOut());
            if (unusable.isEmpty()) {
                return leftOut == null ? entity : new Noted(entity, label + " is listed " + leftOut);
            }
            EntityStatus status = entity.status().ordinal() > EntityStatus.SUSPENDED.ordinal() ? entity.status() : EntityStatus.SUSPENDED;
            return new Incomplete(entity.toBuilder().status(status).build(),
                    label + " is listed " + status + ": " + Mapping.escape(String.join("; ", unusable.values()))
                            + (leftOut == null ? "" : "; and " + leftOut));
        }

        /**
         * Why the registry cannot take {@code id} as an entry's id, or null when it can. The admin API's rule
         * ({@link #ENTRY_ID}); and a name that ends in {@code @} and the id of another framework, which the registry keeps
         * for the entries of that framework (an entry listed there when another framework has its id) and does not load
         * from any other. Which frameworks the service has is not this source's to know: an id with an {@code @} in it
         * is taken only when it has one, followed by the id of the source's own framework.
         */
        private String refusedId(String id) {
            if (!ENTRY_ID.matcher(id).matches()) {
                return "is not 1 to 128 letters, digits or . _ : @ ~ - starting with a letter or digit";
            }
            int at = id.indexOf('@');
            if (at >= 0 && (at != id.lastIndexOf('@') || def.frameworkId() == null || !id.substring(at + 1).equals(def.frameworkId()))) {
                return "has an @ not followed by this source's framework: such a name is kept for the framework it ends in";
            }
            return null;
        }

        /** The id an entity is listed under when its own cannot be one: {@code sha256:} and 32 hex digits of its SHA-256. */
        static String derivedId(String id) {
            try {
                byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8));
                return "sha256:" + java.util.HexFormat.of().formatHex(digest).substring(0, 32);
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        /** A record by its number, and by its id when it has one that may be shown. */
        private static String label(int number, String id) {
            return "record " + number + (id == null || !ENTRY_ID.matcher(id).matches() ? "" : " (id " + Mapping.quote(id) + ")");
        }

        private static TrustSourceException unreadable(Mapping.Block block, String label, String why) {
            return new TrustSourceException(block.where + ": " + label + " cannot be read: " + Mapping.escape(why)
                    + "; a record whose id, roles, identifiers or certificates cannot be read fails the load");
        }

        private static String message(Exception e) {
            return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        }

        /**
         * One record as an anchor, or why not. An anchor is one certificate. Leaving an anchor out removes trust; a
         * record that is left out still says which certificate it is about, when that can be read ({@link #unread}).
         */
        private Object mapAnchor(Mapping.Block block, Object record, Object root, Provenance provenance, Text text)
                throws TrustSourceException {
            Mapping.Mapped m = block.map(record, root);
            text.charge(m.weight());
            String id = m.entry().get("id") instanceof String s ? s : null;
            String shown = id != null && ENTRY_ID.matcher(id).matches() ? id : null;
            if (!m.unusable().isEmpty()) {
                return skipped(block, shown, String.join("; ", m.unusable().values()), m.entry());
            }
            if (id != null && shown == null) {
                return skipped(block, null, ENTRY_ID_RULE, m.entry());
            }
            try {
                List<TrustAnchor> parsed = TrustedEntityParser.anchors(m.entry(), def.frameworkId(), provenance, NO_FILES);
                if (parsed.size() != 1) {
                    return skipped(block, id, "its certificate holds " + parsed.size() + " certificates; an anchor is one", m.entry());
                }
                return parsed.getFirst();
            } catch (Exception e) {
                return skipped(block, shown, message(e), m.entry());
            }
        }

        /** A skipped anchor record, with the certificates and the domain it names as far as they can be read. */
        private static Skipped skipped(Mapping.Block block, String id, String reason, Map<String, Object> entry) {
            List<java.security.cert.X509Certificate> certificates = List.of();
            if (entry.get("certificate") instanceof String text) {
                try {
                    certificates = AdapterSupport.parseCertificateText(text);
                } catch (RuntimeException e) {
                    // a certificate that cannot be read names no CA that another record could list
                }
            }
            String domain = null;
            if (entry.get("domain") instanceof String d) {
                try {
                    domain = io.vctrust.trust.core.model.TrustDomain.of(d).name();
                } catch (RuntimeException e) {
                    // a domain that cannot be read could be any: the certificate alone is compared
                }
            }
            return new Skipped(block, id, reason, certificates, domain);
        }

        /**
         * A record that is skipped, and why. For an anchor record, the certificates it names (empty when none can be
         * read) and its domain (null when it cannot be read).
         */
        private record Skipped(Mapping.Block block, String id, String reason, List<java.security.cert.X509Certificate> certificates,
                               String domain) {
            /** The reason may quote the document unquoted (the registry format's parser names what it refuses): escaped. */
            Skipped {
                reason = reason == null ? "it cannot be read" : Mapping.escape(reason);
            }
        }

        /** An anchor record that is skipped, by its number in its block. */
        private record Unread(int number, Skipped record) {
        }

        /**
         * Two records about one certificate must agree, as {@link #onePerId} requires of readable ones; a record that
         * cannot be read cannot be said to agree. A CA listed active as {@code row-1} and, by {@code row-7}, in a way
         * the mapping cannot read (a withdrawal in an unknown status, doctypes in another shape) would otherwise be
         * trusted through {@code row-1}: the load fails, naming both. A skipped record whose domain cannot be read is
         * compared by its certificate alone.
         */
        private static void unread(List<TrustAnchor> listed, List<Unread> unread) throws TrustSourceException {
            for (Unread u : unread) {
                for (TrustAnchor a : listed) {
                    if (u.record().certificates().contains(a.certificate())
                            && (u.record().domain() == null || u.record().domain().equals(a.domain().name()))) {
                        throw new TrustSourceException("Anchor " + Mapping.quote(a.id()) + " and record " + u.number() + " of "
                                + u.record().block().where + (u.record().id() == null ? "" : " (id " + Mapping.quote(u.record().id()) + ")")
                                + " have the same certificate in domain " + a.domain().name() + ", and the record cannot be read: which "
                                + "one holds cannot be told");
                    }
                }
            }
        }

        /** An entity listed without what could not be read, not in good standing; and the warning that says so. */
        private record Incomplete(TrustedEntity entity, String warning) {
        }

        /** An entity read completely, but for text that only describes it and was too long to keep; and the warning. */
        private record Noted(TrustedEntity entity, String warning) {
        }

        /**
         * What a load (or a lookup answer) has yielded, all its records together, against {@code limits.text}: the
         * characters of its mapped text, and one for each node ({@link Mapping.Weight}), so that nulls and empty lists
         * repeated into every record weigh something too. Each record is bounded, and so is what they make together.
         */
        private static final class Text {
            private final int max;
            private final String what;
            private long used;

            Text(int max, String what) {
                this.max = max;
                this.what = what;
            }

            void charge(long weight) throws TrustSourceException {
                used += weight;
                if (used > max) {
                    throw new TrustSourceException(what + " yield more than " + max + " characters and nodes of mapped text (limits.text)");
                }
            }
        }

        private static Tally[] tallies(List<Mapping.Block> blocks) {
            Tally[] out = new Tally[blocks.size()];
            for (int i = 0; i < out.length; i++) {
                out[i] = new Tally(blocks.get(i));
            }
            return out;
        }

        /** Per block: how many records the document had, how many were read completely, and why the first one was not. */
        private static final class Tally {
            final Mapping.Block block;
            int records;
            int mapped;
            String firstFailure;
            final List<Object> pending = new ArrayList<>();

            Tally(Mapping.Block block) {
                this.block = block;
            }

            void count(Object result, Warnings warnings) {
                records++;
                String why = null;
                if (result instanceof Skipped s) {
                    why = "record " + records + (s.id() == null ? "" : " (id " + Mapping.quote(s.id()) + ")") + " is skipped: " + s.reason();
                } else if (result instanceof Incomplete i) {
                    why = i.warning();
                    pending.add(i.entity());
                } else if (result instanceof Noted n) {
                    mapped++;
                    pending.add(n.entity());
                    warnings.add(block.where + ": " + n.warning());
                } else {
                    mapped++;
                    pending.add(result);
                }
                if (why != null) {
                    if (firstFailure == null) {
                        firstFailure = why;
                    }
                    warnings.add(block.where + ": " + why);
                }
            }

            <T> List<T> take(Class<T> type) {
                List<T> out = pending.stream().map(type::cast).toList();
                pending.clear();
                return out;
            }

            /**
             * Records none of which could be read completely mean that the document's format has changed: the load
             * fails, and the last good content is better than suspending everyone. So does a block that finds no
             * record in any page, unless it says {@code allowEmpty}: a document of another kind signed by the same
             * key, or an empty answer, must not pass for a list that has emptied.
             */
            void check(Warnings warnings) throws TrustSourceException {
                if (records == 0) {
                    if (!block.allowEmpty) {
                        throw new TrustSourceException(block.where + ": the document has no record at " + block.each.text()
                                + "; a block that finds none fails the load unless it says allowEmpty: true");
                    }
                } else if (mapped == 0) {
                    throw new TrustSourceException(block.where + ": none of the " + records + " records at " + block.each.text()
                            + (block.entity ? " could be read completely; " : " could be mapped; ") + firstFailure);
                }
            }
        }

        /** Warnings, at most {@link #MAX_WARNINGS} of them, then how many more there were. */
        private static final class Warnings {
            private final List<String> kept = new ArrayList<>();
            private int more;

            void add(String warning) {
                if (kept.size() < MAX_WARNINGS) {
                    kept.add(told(warning, MAX_WARNING));
                } else {
                    more++;
                }
            }

            List<String> list() {
                if (more == 0) {
                    return kept;
                }
                List<String> out = new ArrayList<>(kept);
                out.add("… and " + more + " more warnings");
                return out;
            }
        }

        /**
         * Whether this source asks about an identifier: of a listed type, with a listed prefix, and no longer than
         * {@link #MAX_IDENTIFIER} characters (callers choose what is asked; an identifier of megabytes would be sent,
         * and kept in the memo, as it is).
         */
        @Override
        public boolean canResolve(Identifier identifier) {
            Mapping.Lookup l = config == null ? null : config.mapping().lookup;
            return l != null && identifier != null && identifier.value() != null && identifier.value().length() <= MAX_IDENTIFIER
                    && l.types().contains(identifier.type()) && l.prefixes().stream().anyMatch(identifier.value()::startsWith);
        }

        /**
         * Asks the external service about one identifier. The identifier is URL-encoded into the URL; the answer
         * counts only when the entity it maps to carries that identifier. Answers and misses are kept for a while, in a
         * bounded map, since callers choose what is asked.
         */
        @Override
        public Optional<TrustedEntity> resolve(Identifier identifier) throws TrustSourceException {
            if (!canResolve(identifier)) {
                return Optional.empty();
            }
            Optional<Optional<TrustedEntity>> cached = answers.get(identifier.key());
            if (cached.isPresent()) {
                return cached.get();
            }
            Instant now = ctx.clock().instant();
            Answer answer;
            try {
                try {
                    answer = ask(identifier, now);
                } catch (RuntimeException | StackOverflowError e) {
                    throw e instanceof RuntimeException r ? unexpected(r) : new TrustSourceException("The answer cannot be read: it is "
                            + "nested too deeply to follow");
                }
            } catch (TrustSourceException e) {
                // Remembered like a miss, for a short time: every client request about the identifier would otherwise
                // send one to a registry that is failing.
                answers.put(identifier.key(), Optional.empty(), now.plus(ON_DEMAND_FAILURE_TTL), 0);
                throw reported(e);
            }
            // Remembered no longer than the answer is good for, when that is sooner.
            Instant until = now.plus(answer.entity().isPresent() ? ON_DEMAND_TTL : ON_DEMAND_NEGATIVE_TTL);
            if (answer.goodUntil() != null && answer.goodUntil().isBefore(until)) {
                until = answer.goodUntil();
            }
            answers.put(identifier.key(), answer.entity(), until, answer.weight());
            return answer.entity();
        }

        /**
         * What a lookup found, until when a signed answer says it is good (null for one that is not signed), and what the
         * entity found weighs (its characters of mapped text and nodes, {@link Mapping.Weight}).
         */
        private record Answer(Optional<TrustedEntity> entity, Instant goodUntil, long weight) {
        }

        private Answer ask(Identifier identifier, Instant now) throws TrustSourceException {
            Mapping.Lookup l = config.mapping().lookup;
            // Percent-encoding with %20 for a space: the identifier cannot add a path segment, a query or a fragment.
            URI uri = URI.create(l.url().replace("{identifier}",
                    URLEncoder.encode(identifier.value(), StandardCharsets.UTF_8).replace("+", "%20")));
            Optional<TrustedEntity> found = Optional.empty();
            Instant goodUntil = null;
            long weight = 0;
            try {
                HttpFetcher.Response r = get(uri);
                if (!l.missStatus().contains(r.status())) {
                    if (!r.isSuccess()) {
                        throw new TrustSourceException("The lookup at " + uri.getHost() + " answered HTTP " + r.status());
                    }
                    Warnings ignored = new Warnings();
                    Object root = document(r.body(), now, ignored, true);
                    if (config.jws()) {
                        goodUntil = fresh(root, now, l);
                    }
                    Provenance provenance = Provenance.of(def.id(), TYPE, def.frameworkId(), publishedLocation(), now);
                    List<Object> records = l.entity().records(root);
                    if (records.size() > config.maxEntities()) {
                        throw new TrustSourceException("The lookup answered with more than " + config.maxEntities() + " records");
                    }
                    Text text = new Text(config.maxText(), "The answer's records");
                    List<TrustedEntity> about = new ArrayList<>();
                    for (int i = 0; i < records.size(); i++) {
                        // A record about the identifier that cannot be read completely answers with a suspended entity,
                        // not with "not found"; one whose identifying members cannot be read fails the lookup.
                        long before = text.used;
                        Object mapped = mapEntity(l.entity(), records.get(i), root, provenance, i + 1, text);
                        TrustedEntity e = mapped instanceof TrustedEntity te ? te : mapped instanceof Incomplete inc ? inc.entity()
                                : mapped instanceof Noted n ? n.entity() : null;
                        if (e != null) {
                            if (e.identifiers().contains(identifier)) {
                                // The entity remembered is the first about the identifier (strictestOf).
                                weight = about.isEmpty() ? text.used - before : weight;
                                about.add(e);
                            } else {
                                log.debug("Trust source '{}' (mapped): an answer about {} maps to an entity without that identifier",
                                        def.id(), told(identifier.toString(), MAX_WARNING));
                            }
                        }
                    }
                    found = about.isEmpty() ? Optional.empty() : Optional.of(strictestOf(about));
                }
            } catch (IOException e) {
                throw new TrustSourceException("The lookup failed: " + e.getMessage(), e);
            } catch (IllegalArgumentException e) {
                throw new TrustSourceException("The answer cannot be read: " + e.getMessage(), e);
            }
            return new Answer(found, goodUntil, weight);
        }

        /**
         * A signed answer says when it was made. With {@code exp}, that decides ({@link #jwtClaims}); without it, the
         * answer counts for {@code lookup.maxAge} after its {@code iat}; with neither, an answer recorded once could
         * be replayed for as long as the key is pinned, and is refused.
         *
         * @return until when the answer is good: its {@code exp}, or its {@code iat} plus {@code lookup.maxAge}
         */
        private Instant fresh(Object root, Instant now, Mapping.Lookup l) throws TrustSourceException {
            Map<?, ?> claims = root instanceof Map<?, ?> m ? m : Map.of();
            Instant exp = numericDate(claims, "exp");
            Instant iat = numericDate(claims, "iat");
            if (iat != null && iat.isAfter(now.plus(CLOCK_SKEW))) {
                throw new TrustSourceException("The answer says it was issued at " + iat + ", in the future");
            }
            if (exp != null) {
                return exp;
            }
            if (iat == null) {
                throw new TrustSourceException("The answer states neither exp nor iat: how old it is cannot be told");
            }
            Duration maxAge = l.maxAge() == null ? DEFAULT_LOOKUP_MAX_AGE : l.maxAge();
            if (now.isAfter(iat.plus(maxAge))) {
                throw new TrustSourceException("The answer was issued at " + iat + ", more than " + maxAge + " ago (lookup.maxAge)");
            }
            return iat.plus(maxAge);
        }
    }
}
