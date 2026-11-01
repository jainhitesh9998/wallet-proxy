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
 */
public record ClientProfile(String clientId, String name, Set<String> frameworks, boolean strictAuthorization,
                            boolean allowUnregisteredMetadata, boolean admin) {

    public ClientProfile {
        frameworks = frameworks == null ? Set.of() : Set.copyOf(frameworks);
    }

    public static ClientProfile anonymous(Set<String> frameworks) {
        return new ClientProfile("anonymous", "Anonymous", frameworks, false, true, false);
    }

    public boolean accepts(String frameworkId) {
        return frameworks.isEmpty() || (frameworkId != null && frameworks.contains(frameworkId));
    }
}
