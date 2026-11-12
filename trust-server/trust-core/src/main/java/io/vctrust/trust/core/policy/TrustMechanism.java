package io.vctrust.trust.core.policy;

import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.x509.CertificateRequirements;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A rule an operator writes for a class of questions: which proof of key is accepted for them, which trust anchors
 * count, what the certificate must look like, and whether its revocation status must be known. It travels in the
 * snapshot (the {@code mechanisms} claim) and the client library applies it exactly as {@code TrustEvaluator} does.
 *
 * <p>A mechanism only tightens: everything built in keeps applying to the questions it governs (RFC 5280, the built-in
 * profile of the question, the anchor's doctypes, what binds a certificate to the question, DID relationships, the
 * entity's standing and authorizations). It adds requirements and chooses which anchors count; nothing switches a
 * built-in check off.
 *
 * @param id       reported in the evidence of every decision it governs
 * @param question the questions it governs
 * @param keys     the proofs of key accepted ({@link #KEY_KINDS}); null: all of them
 * @param x509     what an {@code x5c} chain must satisfy; null: nothing beyond what is built in
 * @param did      what a DID key must satisfy; null: nothing beyond what is built in
 */
public record TrustMechanism(String id, Question question, List<String> keys, X509 x509, Did did) {

    /** An {@code x5c} certificate chain, a DID key ({@code kid} a DID URL), a bare JWK. */
    public static final List<String> KEY_KINDS = List.of("x5c", "did", "jwk");

    /**
     * Which questions a mechanism governs. Every member given must match.
     *
     * @param role    the role asked about
     * @param formats credential formats in their canonical spelling; null: any
     * @param types   doctypes, vcts or VC types: exact, or a prefix followed by {@code *}; null: any
     */
    public record Question(EntityRole role, List<String> formats, List<String> types) {
        public Question {
            Objects.requireNonNull(role, "role");
            formats = formats == null ? null : List.copyOf(formats);
            types = types == null ? null : List.copyOf(types);
        }

        /**
         * @param format the question's format, canonical; null when it names none
         * @param types  every type the question asserts (the primary type and, for a W3C credential, all of
         *               {@code credentialTypes}): one that matches is enough, so that a restrictive mechanism cannot be
         *               dodged by listing the types in another order. A question that asserts none matches only a
         *               mechanism without {@code types}.
         */
        boolean matches(EntityRole role, String format, Collection<String> types) {
            return this.role == role
                    && (formats == null || (format != null && formats.contains(format)))
                    && (this.types == null || types.stream().anyMatch(t -> this.types.stream().anyMatch(p -> typeMatches(p, t))));
        }
    }

    /**
     * @param domain             the trust domain whose anchors count instead of the default one; null: the default
     * @param profile            requirements on the chain on top of the built-in profile; null: none
     * @param revocationRequired an unknown revocation status is an error, whatever the client profile says
     */
    public record X509(String domain, CertificateRequirements profile, boolean revocationRequired) {
    }

    /** @param methods the DID methods accepted for a DID key */
    public record Did(List<String> methods) {
        public Did {
            methods = List.copyOf(methods);
        }
    }

    public TrustMechanism {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(question, "question");
        keys = keys == null ? null : List.copyOf(keys);
    }

    /** Whether the questions of this class may present their key as {@code kind} ({@link #KEY_KINDS}). */
    public boolean accepts(String kind) {
        return keys == null || keys.contains(kind);
    }

    /** A type pattern: exact, or a prefix followed by {@code *}. Compared as strings, as the client library compares them. */
    static boolean typeMatches(String pattern, String type) {
        return pattern.endsWith("*") ? type.startsWith(pattern.substring(0, pattern.length() - 1)) : type.equals(pattern);
    }

    /** The one JSON form of the snapshot claim: camelCase members, in this order, absent when not configured. */
    public Map<String, Object> claim() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("role", TrustMechanisms.roleName(question.role()));
        if (question.formats() != null) {
            q.put("formats", question.formats());
        }
        if (question.types() != null) {
            q.put("types", question.types());
        }
        m.put("for", q);
        if (keys != null) {
            m.put("keys", keys);
        }
        if (x509 != null) {
            Map<String, Object> x = new LinkedHashMap<>();
            if (x509.domain() != null) {
                x.put("domain", x509.domain());
            }
            if (x509.profile() != null) {
                x.put("profile", profileClaim(x509.profile()));
            }
            if (x509.revocationRequired()) {
                x.put("revocation", "required");
            }
            m.put("x509", x);
        }
        if (did != null) {
            m.put("did", Map.of("methods", did.methods()));
        }
        return m;
    }

    private static Map<String, Object> profileClaim(CertificateRequirements r) {
        Map<String, Object> leaf = new LinkedHashMap<>();
        if (r.leafNotCa()) {
            leaf.put("ca", false);
        }
        if (!r.keyUsage().isEmpty()) {
            leaf.put("keyUsage", r.keyUsage());
        }
        if (!r.extendedKeyUsage().isEmpty()) {
            leaf.put("extendedKeyUsage", r.extendedKeyUsage());
        }
        if (r.sameCountryAsAnchor()) {
            leaf.put("sameCountryAsAnchor", true);
        }
        if (r.maxValidityDays() != null) {
            leaf.put("maxValidityDays", r.maxValidityDays());
        }
        if (r.crlDistributionPoint()) {
            leaf.put("crlDistributionPoint", true);
        }
        Map<String, Object> p = new LinkedHashMap<>();
        if (!leaf.isEmpty()) {
            p.put("leaf", leaf);
        }
        if (r.maxIntermediates() != null) {
            p.put("maxIntermediates", r.maxIntermediates());
        }
        return p;
    }
}
