package io.vctrust.trust.core.model;

import io.vctrust.trust.core.x509.Certificates;

import javax.security.auth.x500.X500Principal;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A typed identifier. Identifiers are compared as the specifications compare them: URLs (credential issuer
 * identifiers, client identifiers, OpenID Federation entity identifiers) byte for byte, with no normalization
 * (RFC 8414 section 3.3, OpenID4VCI 1.0 section 12.2.1); DNS names without regard to case; DIDs without a fragment;
 * certificate subjects in their RFC 2253 form.
 * A registry therefore lists a party's identifier exactly as that party writes it, and a client in any language
 * matches with a string comparison.
 */
public record Identifier(IdentifierType type, String value) {

    /** A plain https URL: lower-case host of letters, digits, '-' and '.', optional port, then path, query or nothing. */
    private static final Pattern PLAIN_HTTPS = Pattern.compile("^https://([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?(?:[/?#].*)?$");

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
            default -> value;
        };
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
