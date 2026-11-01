package io.vctrust.trust.core.policy;

import java.util.Set;

/**
 * Per-client trust policy. Each wallet or verifier deployment authenticates as a client and sees only the
 * frameworks it accepts.
 *
 * @param frameworks                 accepted framework ids; empty means all
 * @param strictAuthorization        when true, entities without explicit authorizations are not authorized
 *                                   for any credential type
 * @param allowUnregisteredMetadata  whether the metadata proxy serves issuers absent from the registry
 *                                   (their decision is then UNKNOWN)
 * @param requireRevocationStatus    when true a certificate whose revocation status cannot be determined fails
 *                                   validation; otherwise it is a warning
 * @param requireSignedIssuerMetadata issuer metadata must be signed by a certificate under a credential-issuer anchor
 *                                   (HAIP 1.0 §4.1 ecosystems); unsigned metadata is refused
 * @param allowRelaxedProfiles       honour {@code relaxProfile} on anchors (operator-accepted deviations such as sandbox
 *                                   issuers become warnings); when false the certificate profile is always enforced
 */
public record ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                            boolean allowUnregisteredMetadata, boolean admin, boolean requireRevocationStatus,
                            boolean requireSignedIssuerMetadata, boolean allowRelaxedProfiles) {

    public ClientProfile {
        frameworks = frameworks == null ? Set.of() : Set.copyOf(frameworks);
    }

    public ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                         boolean allowUnregisteredMetadata, boolean admin) {
        this(clientId, name, frameworks, strictAuthorization, allowUnregisteredMetadata, admin, false);
    }

    public ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                         boolean allowUnregisteredMetadata, boolean admin, boolean requireRevocationStatus) {
        this(clientId, name, frameworks, strictAuthorization, allowUnregisteredMetadata, admin, requireRevocationStatus, false, true);
    }

    /** The same policy, limited to {@code frameworks}. */
    public ClientProfile withFrameworks(Set<String> frameworks) {
        return new ClientProfile(clientId, name, frameworks, strictAuthorization, allowUnregisteredMetadata, admin,
                requireRevocationStatus, requireSignedIssuerMetadata, allowRelaxedProfiles);
    }

    public static ClientProfile anonymous(Set<String> frameworks) {
        return new ClientProfile("anonymous", "Anonymous", frameworks, false, true, false);
    }

    public boolean accepts(String frameworkId) {
        return frameworks.isEmpty() || (frameworkId != null && frameworks.contains(frameworkId));
    }
}
