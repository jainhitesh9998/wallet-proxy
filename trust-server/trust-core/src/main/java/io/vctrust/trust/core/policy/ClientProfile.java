package io.vctrust.trust.core.policy;

import java.util.Set;

/**
 * Per-client trust policy. Each wallet or verifier deployment authenticates as a client and sees only the
 * frameworks it accepts.
 *
 * @param frameworks                 accepted framework ids; {@link #ALL_FRAMEWORKS} accepts every one, an empty set none
 * @param strictAuthorization        when true, entities without explicit authorizations are not authorized
 *                                   for any credential type
 * @param allowUnregisteredMetadata  whether the metadata proxy serves issuers absent from the registry
 *                                   (their decision is then UNKNOWN)
 * @param requireRevocationStatus    when true a certificate whose revocation status cannot be determined fails
 *                                   validation; otherwise it is a warning
 * @param requireSignedIssuerMetadata issuer metadata must be signed by a certificate under a credential-issuer anchor
 *                                   (HAIP 1.0 §4.1 ecosystems); unsigned metadata is refused
 */
public record ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                            boolean allowUnregisteredMetadata, boolean admin, boolean requireRevocationStatus,
                            boolean requireSignedIssuerMetadata) {

    /** The wildcard an operator writes to give a client every framework; nothing is granted by leaving the list empty. */
    public static final String ALL_FRAMEWORKS = "*";

    public ClientProfile {
        frameworks = frameworks == null ? Set.of() : Set.copyOf(frameworks);
    }

    public ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                         boolean allowUnregisteredMetadata, boolean admin) {
        this(clientId, name, frameworks, strictAuthorization, allowUnregisteredMetadata, admin, false, false);
    }

    /** A profile that accepts every framework: for tests and tools, never the default for a client. */
    public static ClientProfile unrestricted(String clientId) {
        return new ClientProfile(clientId, clientId, Set.of(ALL_FRAMEWORKS), false, true, false);
    }

    /** The same policy, limited to {@code frameworks}. */
    public ClientProfile withFrameworks(Set<String> frameworks) {
        return new ClientProfile(clientId, name, frameworks, strictAuthorization, allowUnregisteredMetadata, admin,
                requireRevocationStatus, requireSignedIssuerMetadata);
    }

    public boolean acceptsAll() {
        return frameworks.contains(ALL_FRAMEWORKS);
    }

    public boolean accepts(String frameworkId) {
        return acceptsAll() || (frameworkId != null && frameworks.contains(frameworkId));
    }
}
