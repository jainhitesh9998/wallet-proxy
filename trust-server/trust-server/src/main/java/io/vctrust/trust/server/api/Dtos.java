package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.TokenStreamContext;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.annotation.JsonDeserialize;

import java.time.Instant;
import java.util.ArrayList;
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

    public record Subject(@JsonDeserialize(using = Text.class) String identifier,
                          @JsonDeserialize(contentUsing = TextElement.class) List<String> x5c, Map<String, Object> jwk,
                          @JsonDeserialize(using = Text.class) String kid) {
    }

    public record Context(String protocol, @JsonDeserialize(using = Text.class) String credentialFormat,
                          @JsonDeserialize(using = Text.class) String credentialType, Instant time,
                          @JsonDeserialize(using = Text.class) String responseUri, List<TrustedAuthority> trustedAuthorities,
                          @JsonDeserialize(contentUsing = TextElement.class) List<String> credentialTypes) {
    }

    /**
     * A member of a request that is not of the type it is declared as: the request is refused (400), and the message
     * names the member ({@code subject.x5c[0] must be a string}).
     */
    public static final class WrongType extends IllegalArgumentException {
        WrongType(String member) {
            super(member + " must be a string");
        }
    }

    /**
     * A string member, held to being one. Jackson reads a number or a boolean into a string as its text: a credential
     * type 7 would be the type "7" here, and no type at all to the client library, which reads the same request. Any
     * value that is not a string is refused instead; null is the member's absence.
     */
    static class Text extends ValueDeserializer<String> {
        @Override
        public String deserialize(JsonParser p, DeserializationContext ctxt) {
            if (p.currentToken() != JsonToken.VALUE_STRING) {
                throw new WrongType(member(p));
            }
            return p.getString();
        }
    }

    /** A string in a list: null is no element, and is refused too (the core would otherwise meet it as a value). */
    static final class TextElement extends Text {
        @Override
        public String getNullValue(DeserializationContext ctxt) {
            throw new WrongType(member(ctxt.getParser()));
        }
    }

    /** Where the parser is in the request, as {@code subject.x5c[0]}. */
    static String member(JsonParser p) {
        TokenStreamContext c = p.streamReadContext();
        if (p.currentToken() == JsonToken.START_OBJECT || p.currentToken() == JsonToken.START_ARRAY) {
            c = c.getParent();  // the value's own context is open already; the member is its parent's
        }
        List<String> parts = new ArrayList<>();
        for (; c != null; c = c.getParent()) {
            if (c.inArray()) {
                parts.addFirst("[" + c.getCurrentIndex() + "]");
            } else if (c.inObject() && c.currentName() != null) {
                parts.addFirst("." + c.currentName());
            }
        }
        String path = String.join("", parts);
        return path.startsWith(".") ? path.substring(1) : path;
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
