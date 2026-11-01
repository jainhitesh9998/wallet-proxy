package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.model.EntityRole;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * A spec-agnostic trust question: "is this {@code subject}, acting as {@code role}, trusted for this
 * {@code context}?". Every field except {@code subject} is optional; the more is supplied, the more is checked.
 */
public record TrustQuery(EntityRole role, Subject subject, Context context) {

    public TrustQuery {
        subject = subject == null ? new Subject(null, null, null, null) : subject;
        context = context == null ? Context.EMPTY : context;
    }

    /**
     * @param identifier a credential_issuer URL, a DID, an OpenID4VP client_id (with prefix), a federation
     *                   entity id, ...
     * @param x5c        certificate chain, leaf first, base64 DER (JOSE x5c / COSE x5chain)
     * @param jwk        a public JWK the subject signs with
     * @param kid        a key id, typically a DID URL from a JWS header or Data Integrity
     *                   {@code verificationMethod}
     */
    public record Subject(String identifier, List<String> x5c, Map<String, Object> jwk, String kid) {
        public Subject {
            x5c = x5c == null ? List.of() : List.copyOf(x5c);
        }
    }

    /**
     * @param protocol           {@code oid4vci} | {@code oid4vp} | free text
     * @param credentialFormat   OpenID4VCI format identifier
     * @param credentialType     doctype, vct or VC type
     * @param responseUri        OpenID4VP response_uri / redirect_uri, checked against x509_san_dns
     * @param trustedAuthorities DCQL {@code trusted_authorities} to match the subject against
     * @param credentialTypes    every specific type a W3C VC asserts; each must be authorized
     */
    public record Context(String protocol, String credentialFormat, String credentialType, Instant time,
                          String responseUri, List<TrustedAuthority> trustedAuthorities, List<String> credentialTypes) {
        public static final Context EMPTY = new Context(null, null, null, null, null, List.of());

        public Context {
            trustedAuthorities = trustedAuthorities == null ? List.of() : List.copyOf(trustedAuthorities);
            credentialTypes = credentialTypes == null ? List.of() : List.copyOf(credentialTypes);
        }

        public Context(String protocol, String credentialFormat, String credentialType, Instant time,
                       String responseUri, List<TrustedAuthority> trustedAuthorities) {
            this(protocol, credentialFormat, credentialType, time, responseUri, trustedAuthorities, List.of());
        }
    }

    /** DCQL Trusted Authorities Query (OpenID4VP §6.1.1). */
    public record TrustedAuthority(String type, List<String> values) {
    }
}
