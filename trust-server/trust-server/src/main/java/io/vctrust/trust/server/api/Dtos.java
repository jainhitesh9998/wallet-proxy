package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Request bodies of the native API (camelCase JSON), and their translation into the core's queries. */
public final class Dtos {

    private Dtos() {
    }

    public record EvaluateRequest(String role, Subject subject, Context context) {
        public TrustQuery toQuery() {
            Subject s = subject == null ? new Subject(null, null, null, null) : subject;
            Context c = context == null ? new Context(null, null, null, null, null, null, null) : context;
            // A null is neither a type nor the absence of one: the request is broken, and is refused as such.
            if (c.credentialTypes() != null && c.credentialTypes().contains(null)) {
                throw new IllegalArgumentException("credentialTypes must list types (strings); it contains null");
            }
            return new TrustQuery(parseRole(role), new TrustQuery.Subject(s.identifier(), s.x5c(), s.jwk(), s.kid()),
                    new TrustQuery.Context(c.protocol(), c.credentialFormat(), c.credentialType(), c.time(), c.responseUri(),
                            c.trustedAuthorities() == null ? List.of() : c.trustedAuthorities().stream()
                                    .map(t -> new TrustQuery.TrustedAuthority(t.type(), t.values())).toList(),
                            c.credentialTypes()));
        }
    }

    public record Subject(String identifier, List<String> x5c, Map<String, Object> jwk, String kid) {
    }

    public record Context(String protocol, String credentialFormat, String credentialType, Instant time,
                          String responseUri, List<TrustedAuthority> trustedAuthorities, List<String> credentialTypes) {
    }

    public record TrustedAuthority(String type, List<String> values) {
    }

    /**
     * The spellings of a role this API reads, and the role each names. The client library reads a query's role by the
     * same rule and the same list (readRole in evaluation/local.ts), and conformance/evaluation/roles.json holds both to
     * it: a role one side reads and the other does not would decide a question under one mechanism on one side and under
     * another, or none, on the other.
     */
    public static final Map<String, EntityRole> ROLES = roles();

    private static final Pattern BLANK = Pattern.compile("[ \\t\\r\\n]*");
    private static final Pattern AROUND = Pattern.compile("^[ \\t\\r\\n]+|[ \\t\\r\\n]+\\z");

    private static Map<String, EntityRole> roles() {
        Map<String, EntityRole> roles = new LinkedHashMap<>();
        roles.put("issuer", EntityRole.CREDENTIAL_ISSUER);
        roles.put("credential_issuer", EntityRole.CREDENTIAL_ISSUER);
        roles.put("verifier", EntityRole.VERIFIER);
        roles.put("relying_party", EntityRole.VERIFIER);
        roles.put("rp", EntityRole.VERIFIER);
        roles.put("wallet", EntityRole.WALLET_PROVIDER);
        roles.put("wallet_provider", EntityRole.WALLET_PROVIDER);
        roles.put("authorization_server", EntityRole.AUTHORIZATION_SERVER);
        roles.put("as", EntityRole.AUTHORIZATION_SERVER);
        roles.put("accreditation_authority", EntityRole.ACCREDITATION_AUTHORITY);
        roles.put("status_list_provider", EntityRole.STATUS_LIST_PROVIDER);
        roles.put("other", EntityRole.OTHER);
        return Collections.unmodifiableMap(roles);
    }

    /**
     * A query's role: none when it is absent, empty or only spaces, tabs or line breaks; otherwise, without those around
     * it, with ASCII letters in lower case and '-' read as '_', one of {@link #ROLES}. Anything else is refused. Only ASCII
     * is folded, so that the rule is the same in every language (Unicode case mappings and notions of white space differ).
     */
    public static EntityRole parseRole(String role) {
        if (role == null || BLANK.matcher(role).matches()) {
            return null;
        }
        StringBuilder spelling = new StringBuilder();
        for (char c : AROUND.matcher(role).replaceAll("").toCharArray()) {
            spelling.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c == '-' ? '_' : c);
        }
        EntityRole r = ROLES.get(spelling.toString());
        if (r == null) {
            throw new IllegalArgumentException("Unknown role '" + (role.length() <= 40 ? role : role.substring(0, 40) + "…") + "': the roles are "
                    + String.join(", ", ROLES.keySet()));
        }
        return r;
    }
}
