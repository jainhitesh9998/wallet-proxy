package io.vctrust.trust.core.policy;

import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.x509.CertificateRequirements;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The operator's trust mechanisms, in the order they are tried: the first whose {@code for} matches a question governs
 * it, and a question none matches is decided as if there were none.
 *
 * <p>The configuration ({@code trust.mechanisms}) is read strictly: an unknown member, an unknown value, a duplicate id
 * or a member that makes no sense (an {@code x509} block when {@code keys} does not accept {@code x5c}) is an error that
 * names the mechanism, and the service does not start. A rule that is ignored is a rule an operator believes in and
 * clients do not apply. The client library reads the {@link #claim()} as strictly, and refuses a snapshot whose
 * mechanisms it cannot apply exactly (evaluation/mechanisms.ts).
 */
public final class TrustMechanisms {

    public static final TrustMechanisms NONE = new TrustMechanisms(List.of());

    /** The roles a mechanism can govern, by the names the configuration and the claim use. */
    private static final Map<String, EntityRole> ROLES = orderedRoles();
    /** As an entry id of the registry: it is reported in decisions. */
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:@~-]{1,128}");
    /**
     * A trust domain as the registry holds it (lower-case, no spaces), in printable ASCII so that the client library
     * compares it with an anchor's domain as the same string.
     */
    private static final Pattern DOMAIN = Pattern.compile("[\\x21-\\x40\\x5b-\\x7e]{1,200}");
    /** A type, or a prefix followed by '*': printable ASCII, '*' only at the end and after at least one character. */
    private static final Pattern TYPE = Pattern.compile("[\\x21-\\x29\\x2b-\\x7e]{1,512}\\*?");
    /** A dotted OID; an arc of more than 15 digits is beyond what the client library's parser reads. */
    private static final Pattern OID = Pattern.compile("[0-2](\\.(0|[1-9][0-9]{0,14}))+");
    /** DID Core section 3.1: method-name. */
    private static final Pattern DID_METHOD = Pattern.compile("[a-z0-9]{1,64}");
    private static final List<String> FORMATS = List.of(CredentialFormats.MSO_MDOC, CredentialFormats.SD_JWT_VC, CredentialFormats.LDP_VC,
            CredentialFormats.JWT_VC_JSON, CredentialFormats.JWT_VC_JSON_LD);
    /** Longer than any real validity period: an IACA is valid for at most 20 years. */
    private static final int MAX_DAYS = 36_500;
    /** A chain is read up to 10 certificates (TrustEvaluator.MAX_CHAIN): at most 9 between the leaf and the anchor. */
    private static final int MAX_INTERMEDIATES = 9;

    private final List<TrustMechanism> list;

    public TrustMechanisms(List<TrustMechanism> list) {
        Set<String> ids = new LinkedHashSet<>();
        for (TrustMechanism m : list) {
            if (!ids.add(m.id())) {
                throw new IllegalArgumentException("Trust mechanism id '" + m.id() + "' is used twice: ids must be unique");
            }
        }
        this.list = List.copyOf(list);
    }

    public List<TrustMechanism> list() {
        return list;
    }

    public boolean isEmpty() {
        return list.isEmpty();
    }

    public List<String> ids() {
        return list.stream().map(TrustMechanism::id).toList();
    }

    /**
     * The mechanism that governs a question: the first whose {@code for} matches; null when none does.
     *
     * @param format the question's format, canonical ({@link CredentialFormats#canonical}); null when it names none
     * @param types  every type the question asserts
     */
    public TrustMechanism select(EntityRole role, String format, Collection<String> types) {
        if (role == null) {
            return null;
        }
        for (TrustMechanism m : list) {
            if (m.question().matches(role, format, types)) {
                return m;
            }
        }
        return null;
    }

    /** The {@code mechanisms} claim of the snapshot, in the listed order. */
    public List<Map<String, Object>> claim() {
        return list.stream().map(TrustMechanism::claim).toList();
    }

    static String roleName(EntityRole role) {
        return ROLES.entrySet().stream().filter(e -> e.getValue() == role).map(Map.Entry::getKey).findFirst().orElseThrow();
    }

    private static Map<String, EntityRole> orderedRoles() {
        Map<String, EntityRole> roles = new LinkedHashMap<>();
        roles.put("issuer", EntityRole.CREDENTIAL_ISSUER);
        roles.put("verifier", EntityRole.VERIFIER);
        roles.put("wallet_provider", EntityRole.WALLET_PROVIDER);
        roles.put("status_list_provider", EntityRole.STATUS_LIST_PROVIDER);
        return roles;
    }

    /**
     * Reads {@code trust.mechanisms} as the configuration states it: a list of trees of maps, lists and scalars
     * (kebab-case member names, as everywhere under {@code trust.*}). Scalars may be typed (YAML) or text (properties,
     * environment): {@code true}, {@code 7}, or {@code "true"}, {@code "7"}.
     *
     * @throws IllegalArgumentException naming the mechanism and the member, for anything that is not exactly understood
     */
    public static TrustMechanisms fromConfiguration(List<?> configured) {
        List<TrustMechanism> out = new ArrayList<>();
        Map<String, Integer> seen = new HashMap<>();
        for (int i = 0; i < configured.size(); i++) {
            TrustMechanism m = new Reader("trust.mechanisms[" + i + "]").mechanism(configured.get(i));
            Integer first = seen.putIfAbsent(m.id(), i);
            if (first != null) {
                throw new IllegalArgumentException("Trust mechanism trust.mechanisms[" + i + "] ('" + m.id() + "'): the id is already used by trust.mechanisms["
                        + first + "]; ids must be unique");
            }
            out.add(m);
        }
        return new TrustMechanisms(out);
    }

    /** One mechanism's configuration, read member by member; every error names the mechanism and the member. */
    private static final class Reader {
        private String where;

        Reader(String where) {
            this.where = where;
        }

        TrustMechanism mechanism(Object value) {
            if (value instanceof Map<?, ?> raw && raw.get("id") instanceof String named && ID.matcher(named).matches()) {
                where = where + " ('" + named + "')";
            }
            Map<String, Object> m = map(value, "", Set.of("id", "for", "keys", "x509", "did"));
            String id = string(require(m, "id"), "id");
            if (!ID.matcher(id).matches()) {
                throw error("id", "must be 1 to 128 letters, digits or . _ : @ ~ -");
            }
            Map<String, Object> q = map(require(m, "for"), "for", Set.of("role", "formats", "types"));
            String roleName = string(require(q, "role", "for."), "for.role");
            EntityRole role = ROLES.get(roleName);
            if (role == null) {
                throw error("for.role", "'" + roleName + "' is not one of " + String.join(", ", ROLES.keySet()));
            }
            List<String> formats = q.containsKey("formats") ? formats(q.get("formats")) : null;
            List<String> types = q.containsKey("types") ? strings(q.get("types"), "for.types", TYPE,
                    "a type, or a prefix followed by '*' (printable ASCII without spaces)") : null;
            List<String> keys = m.containsKey("keys") ? strings(m.get("keys"), "keys", null, null) : null;
            if (keys != null) {
                for (String k : keys) {
                    if (!TrustMechanism.KEY_KINDS.contains(k)) {
                        throw error("keys", "'" + k + "' is not one of " + String.join(", ", TrustMechanism.KEY_KINDS));
                    }
                }
            }
            TrustMechanism.X509 x509 = null;
            if (m.containsKey("x509")) {
                if (keys != null && !keys.contains("x5c")) {
                    throw error("x509", "is given, but keys does not accept x5c: it would never apply");
                }
                x509 = x509(m.get("x509"));
            }
            TrustMechanism.Did did = null;
            if (m.containsKey("did")) {
                if (keys != null && !keys.contains("did")) {
                    throw error("did", "is given, but keys does not accept did: it would never apply");
                }
                Map<String, Object> d = map(m.get("did"), "did", Set.of("methods"));
                did = new TrustMechanism.Did(strings(require(d, "methods", "did."), "did.methods", DID_METHOD, "a DID method name (lower-case letters and digits)"));
            }
            return new TrustMechanism(id, new TrustMechanism.Question(role, formats, types), keys, x509, did);
        }

        private List<String> formats(Object value) {
            List<String> listed = strings(value, "for.formats", null, null);
            List<String> out = new ArrayList<>();
            for (String f : listed) {
                String canonical = CredentialFormats.canonical(f);
                if (!FORMATS.contains(canonical)) {
                    throw error("for.formats", "'" + f + "' is not a credential format: " + String.join(", ", FORMATS));
                }
                if (out.contains(canonical)) {
                    throw error("for.formats", "lists " + canonical + " twice");
                }
                out.add(canonical);
            }
            return out;
        }

        private TrustMechanism.X509 x509(Object value) {
            Map<String, Object> x = nonEmpty(map(value, "x509", Set.of("domain", "profile", "revocation")), "x509");
            String domain = null;
            if (x.containsKey("domain")) {
                domain = string(x.get("domain"), "x509.domain");
                if (!DOMAIN.matcher(domain).matches()) {
                    throw error("x509.domain", "must be a trust domain as anchors name it: lower-case printable ASCII without spaces");
                }
            }
            CertificateRequirements profile = x.containsKey("profile") ? profile(x.get("profile")) : null;
            boolean revocationRequired = false;
            if (x.containsKey("revocation")) {
                String r = string(x.get("revocation"), "x509.revocation");
                if (!"required".equals(r)) {
                    throw error("x509.revocation", "'" + r + "' is not a value: 'required', or leave it out to let the client profile decide");
                }
                revocationRequired = true;
            }
            return new TrustMechanism.X509(domain, profile, revocationRequired);
        }

        private CertificateRequirements profile(Object value) {
            Map<String, Object> p = nonEmpty(map(value, "x509.profile", Set.of("leaf", "max-intermediates")), "x509.profile");
            boolean leafNotCa = false;
            List<String> keyUsage = List.of();
            List<String> eku = List.of();
            boolean sameCountry = false;
            Integer maxDays = null;
            boolean crlDp = false;
            if (p.containsKey("leaf")) {
                Map<String, Object> leaf = nonEmpty(map(p.get("leaf"), "x509.profile.leaf", Set.of("ca", "key-usage", "extended-key-usage",
                        "same-country-as-anchor", "max-validity-days", "crl-distribution-point")), "x509.profile.leaf");
                if (leaf.containsKey("ca")) {
                    if (bool(leaf.get("ca"), "x509.profile.leaf.ca")) {
                        throw error("x509.profile.leaf.ca", "must be false: a mechanism can require that the signing certificate is not a CA");
                    }
                    leafNotCa = true;
                }
                if (leaf.containsKey("key-usage")) {
                    keyUsage = strings(leaf.get("key-usage"), "x509.profile.leaf.key-usage", null, null);
                    for (String k : keyUsage) {
                        if (!CertificateRequirements.KEY_USAGE_BITS.contains(k)) {
                            throw error("x509.profile.leaf.key-usage", "'" + k + "' is not one of " + String.join(", ", CertificateRequirements.KEY_USAGE_BITS));
                        }
                    }
                }
                if (leaf.containsKey("extended-key-usage")) {
                    eku = strings(leaf.get("extended-key-usage"), "x509.profile.leaf.extended-key-usage", OID, "a dotted OID");
                }
                if (leaf.containsKey("same-country-as-anchor")) {
                    if (!bool(leaf.get("same-country-as-anchor"), "x509.profile.leaf.same-country-as-anchor")) {
                        throw error("x509.profile.leaf.same-country-as-anchor", "must be true, or left out");
                    }
                    sameCountry = true;
                }
                if (leaf.containsKey("max-validity-days")) {
                    maxDays = integer(leaf.get("max-validity-days"), "x509.profile.leaf.max-validity-days", 1, MAX_DAYS);
                }
                if (leaf.containsKey("crl-distribution-point")) {
                    if (!bool(leaf.get("crl-distribution-point"), "x509.profile.leaf.crl-distribution-point")) {
                        throw error("x509.profile.leaf.crl-distribution-point", "must be true, or left out");
                    }
                    crlDp = true;
                }
            }
            Integer maxIntermediates = p.containsKey("max-intermediates")
                    ? integer(p.get("max-intermediates"), "x509.profile.max-intermediates", 0, MAX_INTERMEDIATES) : null;
            return new CertificateRequirements(leafNotCa, keyUsage, eku, sameCountry, maxDays, crlDp, maxIntermediates);
        }

        private Object require(Map<String, Object> m, String key) {
            return require(m, key, "");
        }

        private Object require(Map<String, Object> m, String key, String prefix) {
            if (!m.containsKey(key) || m.get(key) == null) {
                throw error(prefix + key, "is required");
            }
            return m.get(key);
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> map(Object value, String path, Set<String> members) {
            if (!(value instanceof Map<?, ?> m)) {
                throw error(path.isEmpty() ? "the entry" : path, "must be a map of members");
            }
            for (Object k : m.keySet()) {
                if (!members.contains(String.valueOf(k))) {
                    throw error(path.isEmpty() ? String.valueOf(k) : path + "." + k, "is not a member this service knows ("
                            + (path.isEmpty() ? "" : path + ": ") + String.join(", ", members.stream().sorted().toList()) + ")");
                }
            }
            return (Map<String, Object>) m;
        }

        private Map<String, Object> nonEmpty(Map<String, Object> m, String path) {
            if (m.isEmpty()) {
                throw error(path, "is empty: leave it out, or state what it requires");
            }
            return m;
        }

        private String string(Object value, String path) {
            if (!(value instanceof String s)) {
                throw error(path, "must be a string");
            }
            return s;
        }

        /** A non-empty list of distinct strings, each matching {@code pattern} when one is given. */
        private List<String> strings(Object value, String path, Pattern pattern, String what) {
            if (!(value instanceof List<?> l)) {
                throw error(path, "must be a list");
            }
            if (l.isEmpty()) {
                throw error(path, "is empty: leave it out, or list what it accepts");
            }
            List<String> out = new ArrayList<>();
            for (Object o : l) {
                String s = string(o, path);
                if (pattern != null && !pattern.matcher(s).matches()) {
                    throw error(path, "'" + abbreviated(s) + "' is not " + what);
                }
                if (out.contains(s)) {
                    throw error(path, "lists '" + s + "' twice");
                }
                out.add(s);
            }
            return out;
        }

        private boolean bool(Object value, String path) {
            if (value instanceof Boolean b) {
                return b;
            }
            if ("true".equals(value) || "false".equals(value)) {
                return "true".equals(value);
            }
            throw error(path, "must be true or false");
        }

        private int integer(Object value, String path, int min, int max) {
            long v;
            if (value instanceof Integer || value instanceof Long) {
                v = ((Number) value).longValue();
            } else if (value instanceof String s && s.matches("0|[1-9][0-9]{0,9}")) {
                v = Long.parseLong(s);
            } else {
                throw error(path, "must be a whole number");
            }
            if (v < min || v > max) {
                throw error(path, "must be from " + min + " to " + max);
            }
            return (int) v;
        }

        private IllegalArgumentException error(String path, String problem) {
            return new IllegalArgumentException("Trust mechanism " + where + ": " + path + " " + problem);
        }

        private static String abbreviated(String s) {
            return s.length() <= 80 ? s : s.substring(0, 80) + "…";
        }
    }
}
