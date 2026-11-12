package io.vctrust.trust.adapters.mapped;

import io.vctrust.trust.adapters.support.AdapterSupport;
import io.vctrust.trust.adapters.support.TrustedEntityParser;
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
import io.vctrust.trust.core.util.ExpiringMap;
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
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
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
    static final int MAX_WARNINGS = 50;
    static final Duration ON_DEMAND_TTL = Duration.ofMinutes(10);
    static final Duration ON_DEMAND_NEGATIVE_TTL = Duration.ofMinutes(1);
    static final int ON_DEMAND_MAX_ENTRIES = 5_000;
    /** A list issued further in the future than this would make every genuine list after it look older. */
    static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    /** The identifiers the admin API accepts for an entry: an id from a document is held to the same rule. */
    private static final Pattern ENTRY_ID = Pattern.compile("[A-Za-z0-9._:@~-]{1,128}");
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    /** A document from elsewhere names no file: whatever would load one is refused. */
    private static final ResourceLoader NO_FILES = location -> {
        throw new IOException("A mapped record cannot name a location");
    };

    /** The configuration, as read and checked when the source is created. */
    record Config(String location, URI origin, String publicUri, Map<String, String> headers, boolean jws, PinnedKeys keys,
                  boolean allowUnverified, boolean allowExpired, int maxEntities, int maxAnchors, Mapping mapping) {

        /** Header names only: their values are credentials, and a record's own text would carry them into any log line. */
        @Override
        public String toString() {
            return "Config[location=" + location + ", headers=" + new TreeSet<>(headers.keySet()) + ", format=" + (jws ? "jws" : "json")
                    + ", pinnedKeys=" + keys.configured() + ", allowUnverified=" + allowUnverified + ", allowExpired=" + allowExpired + "]";
        }
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
        if (p.containsKey("limits")) {
            Map<String, Object> l = Mapping.members(p.get("limits"), "limits", Set.of("entities", "anchors"));
            maxEntities = l.containsKey("entities") ? Mapping.positive(l.get("entities"), "limits.entities") : maxEntities;
            maxAnchors = l.containsKey("anchors") ? Mapping.positive(l.get("anchors"), "limits.anchors") : maxAnchors;
        }
        return new Config(location, origin, publicUri, headers, jws, keys, allowUnverified, bool(p, "allowExpired"),
                maxEntities, maxAnchors, mapping);
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
        private final ExpiringMap<String, Optional<TrustedEntity>> answers;

        MappedSource(SourceDefinition def, SourceContext ctx) {
            this.def = def;
            this.ctx = ctx;
            Config c = null;
            String error = null;
            try {
                c = read(def, ctx.resources());
            } catch (IOException | RuntimeException e) {
                error = "Source '" + def.id() + "' (mapped): " + e.getMessage();
            }
            this.config = c;
            this.configError = error;
            this.answers = new ExpiringMap<>(ON_DEMAND_MAX_ENTRIES, ctx.clock());
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
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
            Tally[] entityTallies = tallies(config.mapping().entities);
            Tally[] anchorTallies = tallies(config.mapping().anchors);
            List<TrustedEntity> entities = new ArrayList<>();
            List<TrustAnchor> anchors = new ArrayList<>();
            int entityRecords = 0;
            int anchorRecords = 0;
            Facts facts = null;
            Set<String> visited = new HashSet<>();
            Document page = null;
            int pages = 0;
            try {
                while (true) {
                    if (page == null) {
                        page = ResourceLoader.isRemote(config.location()) ? fetch(URI.create(config.location()), now, warnings)
                                : new Document(document(ctx.resources().load(config.location()), now, warnings), null);
                        facts = facts(page.root(), now, warnings);
                        if (page.uri() != null) {
                            visited.add(page.uri().toString());
                        }
                    }
                    pages++;
                    for (int b = 0; b < config.mapping().entities.size(); b++) {
                        Mapping.Block block = config.mapping().entities.get(b);
                        List<Object> records = block.records(page.root());
                        entityRecords += records.size();
                        if (entityRecords > config.maxEntities()) {
                            throw new TrustSourceException("The list has more than " + config.maxEntities() + " entity records (limits.entities)");
                        }
                        for (Object record : records) {
                            entityTallies[b].count(mapEntity(block, record, page.root(), provenance), warnings);
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
                            anchorTallies[b].count(mapAnchor(block, record, page.root(), provenance), warnings);
                        }
                    }
                    for (Tally t : entityTallies) {
                        entities.addAll(t.take(TrustedEntity.class));
                    }
                    for (Tally t : anchorTallies) {
                        anchors.addAll(t.take(TrustAnchor.class));
                    }
                    URI next = next(page, visited, pages);
                    if (next == null) {
                        break;
                    }
                    page = fetch(next, now, warnings);
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
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("pages", pages);
            details.put("format", config.jws() ? "jws" : "json");
            ListInfo info = new ListInfo(facts.issuer(), facts.sequence(), facts.issuedAt(), facts.nextUpdate(), signature(), details);
            return new SourceLoadResult(entities, anchors, info, warnings.list());
        }

        /**
         * Where this source says its content comes from: {@code publicUri} when set, else its location when that is an
         * http(s) URL. A location on this host (a path, {@code file:}, {@code classpath:}) is not published.
         */
        private String publishedLocation() {
            if (config.publicUri() != null) {
                return config.publicUri();
            }
            return ResourceLoader.isRemote(config.location()) ? config.location() : null;
        }

        private ListInfo.SignatureStatus signature() {
            if (!config.jws()) {
                return ListInfo.SignatureStatus.NOT_SIGNED;
            }
            return config.keys().configured() ? ListInfo.SignatureStatus.VERIFIED : ListInfo.SignatureStatus.NOT_CHECKED;
        }

        private record Document(Object root, URI uri) {
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
            try {
                next = page.uri().resolve(new URI(text.trim()));
            } catch (java.net.URISyntaxException | IllegalArgumentException e) {
                throw new TrustSourceException("The next page " + Mapping.quote(text) + " is not a URL");
            }
            if (!sameOrigin(next, config.origin())) {
                throw new TrustSourceException("The next page " + Mapping.quote(text) + " is not on the origin of location");
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
            return new Document(document(r.body(), now, warnings), r.finalUri() == null ? uri : r.finalUri());
        }

        /** The JSON of a document: for a JWS, its payload once the signature has verified. */
        private Object document(byte[] body, Instant now, Warnings warnings) throws TrustSourceException {
            byte[] json = body;
            if (config.jws()) {
                String compact = new String(body, StandardCharsets.US_ASCII).trim();
                json = config.keys().configured() ? config.keys().verify(compact, now) : PinnedKeys.unverifiedPayload(compact);
            }
            Object root;
            try {
                root = StrictJson.parse(json);
            } catch (IllegalArgumentException e) {
                throw new TrustSourceException("The document is " + e.getMessage());
            }
            if (config.jws() && root instanceof Map<?, ?> claims) {
                jwtClaims(claims, now, warnings);
            }
            return root;
        }

        /**
         * A JWS whose payload is a JWT is held to its claims (RFC 7519 section 4.1): not after {@code exp}, not before
         * {@code nbf}, and only when addressed to this service when it names an audience at all.
         */
        private void jwtClaims(Map<?, ?> claims, Instant now, Warnings warnings) throws TrustSourceException {
            Instant exp = numericDate(claims, "exp");
            if (exp != null && now.isAfter(exp.plus(Duration.ofSeconds(60)))) {
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
            if (!(v instanceof Number n)) {
                throw new TrustSourceException("The list's " + name + " is not a NumericDate");
            }
            try {
                return Instant.ofEpochSecond(n.longValue());
            } catch (RuntimeException e) {
                throw new TrustSourceException("The list's " + name + " is not a NumericDate");
            }
        }

        private record Facts(String issuer, String sequence, Instant issuedAt, Instant nextUpdate) {
        }

        /** The list facts the mapping names. One it names that the document lacks fails the load: the format has changed. */
        private Facts facts(Object root, Instant now, Warnings warnings) throws TrustSourceException {
            Mapping.ListFacts l = config.mapping().list;
            if (l == null) {
                return new Facts(null, null, null, null);
            }
            String issuer = fact(l.issuer(), "issuer", root);
            String sequence = fact(l.sequence(), "sequence", root);
            Instant issuedAt = date(l.issuedAt(), "issuedAt", root);
            Instant nextUpdate = date(l.nextUpdate(), "nextUpdate", root);
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

        /** One record as an entity, or why not. */
        private Object mapEntity(Mapping.Block block, Object record, Object root, Provenance provenance) {
            String id = null;
            try {
                Map<String, Object> entry = block.map(record, root);
                id = entry.get("id") instanceof String s ? s : null;
                if (id != null && !ENTRY_ID.matcher(id).matches()) {
                    return new Skipped(block, null, "its id is not 1 to 128 letters, digits or . _ : @ ~ -");
                }
                return TrustedEntityParser.entity(entry, def.frameworkId(), provenance, NO_FILES);
            } catch (Exception e) {
                return new Skipped(block, id, e.getMessage());
            }
        }

        /** One record as an anchor, or why not. An anchor is one certificate. */
        private Object mapAnchor(Mapping.Block block, Object record, Object root, Provenance provenance) {
            String id = null;
            try {
                Map<String, Object> entry = block.map(record, root);
                id = entry.get("id") instanceof String s ? s : null;
                if (id != null && !ENTRY_ID.matcher(id).matches()) {
                    return new Skipped(block, null, "its id is not 1 to 128 letters, digits or . _ : @ ~ -");
                }
                List<TrustAnchor> parsed = TrustedEntityParser.anchors(entry, def.frameworkId(), provenance, NO_FILES);
                if (parsed.size() != 1) {
                    return new Skipped(block, id, "its certificate holds " + parsed.size() + " certificates; an anchor is one");
                }
                return parsed.getFirst();
            } catch (Exception e) {
                return new Skipped(block, id, e.getMessage());
            }
        }

        private record Skipped(Mapping.Block block, String id, String reason) {
            Skipped {
                reason = reason == null ? "it cannot be read" : reason;
            }
        }

        private static Tally[] tallies(List<Mapping.Block> blocks) {
            Tally[] out = new Tally[blocks.size()];
            for (int i = 0; i < out.length; i++) {
                out[i] = new Tally(blocks.get(i));
            }
            return out;
        }

        /** Per block: how many records the document had, how many mapped, and why the first one did not. */
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
                if (result instanceof Skipped s) {
                    String why = "record " + records + (s.id() == null ? "" : " (id " + Mapping.quote(s.id()) + ")") + " is skipped: " + s.reason();
                    if (firstFailure == null) {
                        firstFailure = why;
                    }
                    warnings.add(block.where + ": " + why);
                } else {
                    mapped++;
                    pending.add(result);
                }
            }

            <T> List<T> take(Class<T> type) {
                List<T> out = pending.stream().map(type::cast).toList();
                pending.clear();
                return out;
            }

            /** Records that all fail to map mean that the document's format has changed: the load fails. */
            void check(Warnings warnings) throws TrustSourceException {
                if (records == 0) {
                    warnings.add(block.where + ": the document has no record at " + block.each.text());
                } else if (mapped == 0) {
                    throw new TrustSourceException(block.where + ": none of the " + records + " records at " + block.each.text()
                            + " could be mapped; " + firstFailure);
                }
            }
        }

        /** Warnings, at most {@link #MAX_WARNINGS} of them, then how many more there were. */
        private static final class Warnings {
            private final List<String> kept = new ArrayList<>();
            private int more;

            void add(String w) {
                if (kept.size() < MAX_WARNINGS) {
                    kept.add(w.length() <= 300 ? w : w.substring(0, 300) + "…");
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

        @Override
        public boolean canResolve(Identifier identifier) {
            Mapping.Lookup l = config == null ? null : config.mapping().lookup;
            return l != null && identifier != null && l.types().contains(identifier.type())
                    && l.prefixes().stream().anyMatch(identifier.value()::startsWith);
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
            Mapping.Lookup l = config.mapping().lookup;
            Instant now = ctx.clock().instant();
            // Percent-encoding with %20 for a space: the identifier cannot add a path segment, a query or a fragment.
            URI uri = URI.create(l.url().replace("{identifier}",
                    URLEncoder.encode(identifier.value(), StandardCharsets.UTF_8).replace("+", "%20")));
            Optional<TrustedEntity> found = Optional.empty();
            try {
                HttpFetcher.Response r = get(uri);
                if (!l.missStatus().contains(r.status())) {
                    if (!r.isSuccess()) {
                        throw new TrustSourceException("The lookup at " + uri.getHost() + " answered HTTP " + r.status());
                    }
                    Warnings ignored = new Warnings();
                    Object root = document(r.body(), now, ignored);
                    Provenance provenance = Provenance.of(def.id(), TYPE, def.frameworkId(), publishedLocation(), now);
                    List<Object> records = l.entity().records(root);
                    if (records.size() > config.maxEntities()) {
                        throw new TrustSourceException("The lookup answered with more than " + config.maxEntities() + " records");
                    }
                    for (Object record : records) {
                        if (mapEntity(l.entity(), record, root, provenance) instanceof TrustedEntity e) {
                            if (e.identifiers().contains(identifier)) {
                                found = Optional.of(e);
                                break;
                            }
                            log.debug("Trust source '{}' (mapped): an answer about {} maps to an entity without that identifier",
                                    def.id(), identifier);
                        }
                    }
                }
            } catch (IOException e) {
                throw new TrustSourceException("The lookup failed: " + e.getMessage(), e);
            }
            answers.put(identifier.key(), found, now.plus(found.isPresent() ? ON_DEMAND_TTL : ON_DEMAND_NEGATIVE_TTL));
            return found;
        }
    }
}
