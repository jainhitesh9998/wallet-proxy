package io.vctrust.trust.core.metadata;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * A validated OpenID4VCI issuer metadata bundle: the Credential Issuer metadata plus the metadata of each
 * Authorization Server it names.
 *
 * @param signedMetadata         the {@code openidvci-issuer-metadata+jwt} if the issuer served one
 * @param signedMetadataVerified whether its signature verified against an {@code x5c} chain (trust is
 *                               evaluated separately)
 * @param policyApplied          true when a registry metadata policy modified the live metadata
 */
public record IssuerMetadata(String credentialIssuer, Map<String, Object> issuer,
                             Map<String, Map<String, Object>> authorizationServers, String signedMetadata,
                             Boolean signedMetadataVerified, boolean policyApplied, Instant fetchedAt,
                             Instant expiresAt, List<String> warnings) {

    public IssuerMetadata {
        authorizationServers = authorizationServers == null ? Map.of() : Map.copyOf(authorizationServers);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
