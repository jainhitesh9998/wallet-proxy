package io.vctrust.trust.core.model;

import java.util.Locale;
import java.util.Objects;

/**
 * A named X.509 trust domain: a set of trust anchors used for one purpose. Keeping purposes apart prevents
 * a verifier access CA from vouching for an mDL Document Signer, and so on. Domains are open-ended strings;
 * the well-known ones are provided as constants.
 */
public record TrustDomain(String name) {

    /** ISO/IEC 18013-5 IACA roots: anchors for mdoc Document Signer certificates. */
    public static final TrustDomain MDOC_IACA = new TrustDomain("mdoc-iaca");
    /** Issuer CAs for SD-JWT VC / JWT credentials signed with an {@code x5c} chain. */
    public static final TrustDomain CREDENTIAL_ISSUER = new TrustDomain("credential-issuer");
    /** CAs issuing relying-party (verifier) access certificates used for OpenID4VP request signing. */
    public static final TrustDomain VERIFIER_ACCESS = new TrustDomain("verifier-access");
    /** Wallet provider CAs anchoring wallet / key attestations. */
    public static final TrustDomain WALLET_PROVIDER = new TrustDomain("wallet-provider");
    /** Signers of trust lists themselves (ETSI TL, VICAL, LoTE). */
    public static final TrustDomain LIST_SIGNER = new TrustDomain("list-signer");
    /** Token Status List signers. */
    public static final TrustDomain STATUS_LIST = new TrustDomain("status-list");

    public TrustDomain {
        Objects.requireNonNull(name, "name");
        name = name.trim().toLowerCase(Locale.ROOT);
    }

    public static TrustDomain of(String name) {
        return new TrustDomain(name);
    }

    /** The default domain for a credential's issuing chain. */
    public static TrustDomain forCredentialFormat(String format) {
        return CredentialFormats.MSO_MDOC.equals(CredentialFormats.canonical(format)) ? MDOC_IACA : CREDENTIAL_ISSUER;
    }

    @Override
    public String toString() {
        return name;
    }
}
