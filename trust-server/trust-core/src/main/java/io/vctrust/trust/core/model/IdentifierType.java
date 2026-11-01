package io.vctrust.trust.core.model;

/** Kinds of identifiers by which an entity can be looked up. */
public enum IdentifierType {
    /** A DID, without fragment (e.g. {@code did:web:issuer.example}). */
    DID,
    /** An HTTPS URL identifier, e.g. an OpenID4VCI {@code credential_issuer} or an OAuth issuer. */
    URL,
    /** An OpenID4VP client identifier, including its prefix (e.g. {@code x509_hash:...}). */
    CLIENT_ID,
    /** A DNS name (from an X.509 SAN dNSName or a client_id prefix). */
    DNS,
    /** RFC 4514 subject distinguished name of a certificate. */
    X509_SUBJECT,
    /** Base64url Subject Key Identifier of a certificate. */
    X509_SKI,
    /** Base64url SHA-256 of a DER certificate (the OpenID4VP {@code x509_hash} value). */
    X509_SHA256,
    /** RFC 7638 JWK thumbprint (base64url, SHA-256). */
    JWK_THUMBPRINT,
    /** OpenID Federation entity identifier. */
    FEDERATION_ENTITY,
    OTHER
}
