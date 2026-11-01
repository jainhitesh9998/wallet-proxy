package io.vctrust.trust.core.model;

/**
 * The role a {@link TrustedEntity} plays in a credential ecosystem.
 *
 * <p>Roles are protocol-neutral: an OpenID4VCI credential issuer, an ETSI "QEAA provider" service and an
 * EBSI "Trusted Issuer" all map to {@link #CREDENTIAL_ISSUER}.
 */
public enum EntityRole {
    CREDENTIAL_ISSUER,
    VERIFIER,
    WALLET_PROVIDER,
    AUTHORIZATION_SERVER,
    /** An authority that accredits other entities (EBSI TAO / RootTAO, a federation intermediate, a CA operator). */
    ACCREDITATION_AUTHORITY,
    STATUS_LIST_PROVIDER,
    OTHER
}
