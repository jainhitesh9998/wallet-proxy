package io.vctrust.trust.core.model;

import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.x509.Certificates;

import javax.security.auth.x500.X500Principal;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A typed identifier. Identifiers are compared as the specifications compare them: URLs (credential issuer
 * identifiers, client identifiers, OpenID Federation entity identifiers) byte for byte, with no normalization
 * (RFC 8414 section 3.3, OpenID4VCI 1.0 section 12.2.1); DNS names without regard to case; DIDs without a fragment;
 * certificate subjects in their RFC 2253 form; a certificate's SHA-256 ({@code X509_SHA256}) as unpadded base64url,
 * however the digest is written ({@link #sha256Digest}).
 * A registry therefore lists a party's identifier exactly as that party writes it, and a client in any language
 * matches with a string comparison. The client library applies the same rules (identifierKey in evaluation/local.ts),
 * and conformance/evaluation/identifiers.json holds both to them.
 */
public record Identifier(IdentifierType type, String value) {

    /** A plain https URL: lower-case host of letters, digits, '-' and '.', optional port, then path, query or nothing. */
    private static final Pattern PLAIN_HTTPS = Pattern.compile("^https://([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?(?:[/?#].*)?$");
    /** 32 bytes in hexadecimal, in any case, with ':' between all the bytes or none (as openssl prints a fingerprint). */
    private static final Pattern HEX_DIGEST = Pattern.compile("[0-9A-Fa-f]{64}|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31}");
    /**
     * 32 bytes in base64 or base64url, padded or not. 43 characters hold 258 bits: the last character of an encoding of
     * 32 bytes leaves its 2 low bits zero, so it is one of {@code AEIMQUYcgkosw048}; one that does not encodes no digest.
     */
    private static final Pattern BASE64_DIGEST = Pattern.compile("(?:[A-Za-z0-9+/]{42}|[A-Za-z0-9_-]{42})[AEIMQUYcgkosw048]=?");

    public Identifier {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        value = canonical(type, value);
    }

    public static Identifier of(IdentifierType type, String value) {
        return new Identifier(type, value);
    }

    public static Identifier did(String did) {
        return new Identifier(IdentifierType.DID, did);
    }

    public static Identifier url(String url) {
        return new Identifier(IdentifierType.URL, url);
    }

    /** Index key used by registries. */
    public String key() {
        return type.name() + "|" + value;
    }

    private static String canonical(IdentifierType type, String value) {
        return switch (type) {
            case DID -> {
                int hash = value.indexOf('#');
                yield hash >= 0 ? value.substring(0, hash) : value;
            }
            case DNS -> value.toLowerCase(Locale.ROOT);
            case X509_SUBJECT -> rfc2253(value);
            case X509_SHA256 -> {
                String digest = sha256Digest(value);
                yield digest == null ? value : digest;
            }
            default -> value;
        };
    }

    /**
     * A SHA-256 digest (32 bytes) in the one form it is compared in, unpadded base64url (what both evaluators compute
     * from a certificate, and the OpenID4VP {@code x509_hash} value), from any of the ways it is commonly written:
     * hexadecimal in any case, with {@code :} between all the bytes or none, or base64 or base64url, padded or not.
     * Null for anything else: such a value is kept as written and matches nothing, and the registry format refuses it.
     * Written another way, a REVOKED entry would bind no certificate, and its party would be trusted through the CA.
     */
    public static String sha256Digest(String value) {
        if (HEX_DIGEST.matcher(value).matches()) {
            return Base64Url.encode(HexFormat.of().parseHex(value.replace(":", "")));
        }
        if (BASE64_DIGEST.matcher(value).matches()) {
            return value.replace("=", "").replace('+', '-').replace('/', '_');
        }
        return null;
    }

    /**
     * A certificate subject in the one form it is compared in ({@link Certificates#rfc2253(byte[])}: keywords for
     * CN, C, L, ST, O, OU, STREET, DC and UID; any other attribute type as its dotted OID with a hex value). A name
     * that cannot be parsed is kept as written, and matches nothing.
     */
    private static String rfc2253(String name) {
        try {
            return Certificates.rfc2253(new X500Principal(name).getEncoded());
        } catch (IllegalArgumentException e) {
            return name;
        }
    }

    /**
     * The host of a plain https URL, or null for anything else (another scheme, upper-case or non-ASCII host,
     * userinfo). Used where a host is compared with a certificate's dNSName; a URL this rule does not read is
     * refused there, so every implementation reads the same host without a URL parser.
     */
    public static String httpsHost(String url) {
        Matcher m = url == null ? null : PLAIN_HTTPS.matcher(url);
        return m != null && m.matches() ? m.group(1) : null;
    }

    @Override
    public String toString() {
        return type + ":" + value;
    }
}
