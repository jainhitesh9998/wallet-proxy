package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.util.Hashes;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parsing and inspection helpers for X.509 certificates. */
public final class Certificates {

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s]+?)-----END CERTIFICATE-----");

    private Certificates() {
    }

    private static CertificateFactory factory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public static X509Certificate fromDer(byte[] der) {
        try {
            return (X509Certificate) factory().generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Invalid X.509 certificate: " + e.getMessage(), e);
        }
    }

    /** Parses a base64 / base64url DER certificate (as found in JOSE {@code x5c}). */
    public static X509Certificate fromBase64(String b64) {
        return fromDer(Base64Url.decodeLenient(b64));
    }

    public static List<X509Certificate> fromBase64List(Collection<String> chain) {
        List<X509Certificate> out = new ArrayList<>(chain.size());
        for (String c : chain) {
            out.add(fromBase64(c));
        }
        return out;
    }

    /** Parses all certificates in a PEM bundle. Falls back to DER / bare base64 when no PEM armour is present. */
    public static List<X509Certificate> fromPemBundle(byte[] data) {
        String text = new String(data, StandardCharsets.US_ASCII);
        Matcher m = PEM.matcher(text);
        List<X509Certificate> out = new ArrayList<>();
        while (m.find()) {
            out.add(fromDer(Base64.getMimeDecoder().decode(m.group(1))));
        }
        if (!out.isEmpty()) {
            return out;
        }
        if (data.length > 0 && data[0] == 0x30) {
            try {
                for (var c : factory().generateCertificates(new ByteArrayInputStream(data))) {
                    out.add((X509Certificate) c);
                }
                return out;
            } catch (CertificateException e) {
                throw new IllegalArgumentException("Invalid DER certificate data", e);
            }
        }
        return List.of(fromBase64(text.strip()));
    }

    public static byte[] der(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String toBase64(X509Certificate cert) {
        return Base64.getEncoder().encodeToString(der(cert));
    }

    public static String toPem(X509Certificate cert) {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der(cert))
                + "\n-----END CERTIFICATE-----\n";
    }

    /** Base64url SHA-256 of the DER encoding; equals the OpenID4VP {@code x509_hash} client identifier value. */
    public static String sha256Thumbprint(X509Certificate cert) {
        return Hashes.sha256B64u(der(cert));
    }

    public static Optional<String> subjectKeyIdentifier(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (ext == null) {
            return Optional.empty();
        }
        try {
            ASN1Primitive inner = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets());
            return Optional.of(Base64Url.encode(SubjectKeyIdentifier.getInstance(inner).getKeyIdentifier()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /** Base64url key identifier of the AuthorityKeyIdentifier extension (DCQL {@code aki} trusted authority). */
    public static Optional<String> authorityKeyIdentifier(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (ext == null) {
            return Optional.empty();
        }
        try {
            ASN1Primitive inner = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets());
            byte[] kid = AuthorityKeyIdentifier.getInstance(inner).getKeyIdentifierOctets();
            return kid == null ? Optional.empty() : Optional.of(Base64Url.encode(kid));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /** dNSName entries of the Subject Alternative Name extension. */
    public static List<String> dnsNames(X509Certificate cert) {
        return sanValues(cert, 2);
    }

    /** uniformResourceIdentifier entries of the Subject Alternative Name extension. */
    public static List<String> uriNames(X509Certificate cert) {
        return sanValues(cert, 6);
    }

    private static List<String> sanValues(X509Certificate cert, int type) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return List.of();
            }
            List<String> out = new ArrayList<>();
            for (List<?> san : sans) {
                if (san.size() >= 2 && san.get(0) instanceof Integer t && t == type) {
                    out.add(String.valueOf(san.get(1)));
                }
            }
            return out;
        } catch (CertificateParsingException e) {
            return List.of();
        }
    }

    /** URIs of the CRL Distribution Points extension (full names only). */
    public static List<String> crlDistributionPoints(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return List.of();
        }
        try {
            CRLDistPoint dp = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets()));
            List<String> out = new ArrayList<>();
            for (DistributionPoint p : dp.getDistributionPoints()) {
                out.addAll(fullNameUris(p.getDistributionPoint()));
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** uniformResourceIdentifier entries of a distribution point's full name. */
    public static List<String> fullNameUris(DistributionPointName name) {
        if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (GeneralName g : GeneralNames.getInstance(name.getName()).getNames()) {
            if (g.getTagNo() == GeneralName.uniformResourceIdentifier) {
                out.add(g.getName().toString());
            }
        }
        return out;
    }

    /** OCSP responder URLs from the Authority Information Access extension. */
    public static List<String> ocspUrls(X509Certificate cert) {
        byte[] ext = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ext == null) {
            return List.of();
        }
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
                    ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets()));
            List<String> out = new ArrayList<>();
            for (AccessDescription d : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(d.getAccessMethod())
                        && d.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                    out.add(d.getAccessLocation().getName().toString());
                }
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** True when subject and issuer names are equal (a root, or a self-issued key-rollover certificate). */
    public static boolean isSelfIssued(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    public static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isCa(X509Certificate cert) {
        return cert.getBasicConstraints() >= 0;
    }

    /** The attribute types written by keyword in a name; every other type is written as its dotted OID with a hex value. */
    private static final Map<String, String> NAME_KEYWORDS = Map.of(
            "2.5.4.3", "CN", "2.5.4.6", "C", "2.5.4.7", "L", "2.5.4.8", "ST", "2.5.4.10", "O", "2.5.4.11", "OU", "2.5.4.9", "STREET",
            "0.9.2342.19200300.100.1.25", "DC", "0.9.2342.19200300.100.1.1", "UID");
    private static final String COUNTRY = "2.5.4.6";

    /** The certificate's subject in the one form names are compared in; see {@link #rfc2253(byte[])}. */
    public static String subjectName(X509Certificate cert) {
        return rfc2253(cert.getSubjectX500Principal().getEncoded());
    }

    public static String issuerName(X509Certificate cert) {
        return rfc2253(cert.getIssuerX500Principal().getEncoded());
    }

    /**
     * A distinguished name as text, by rules simple enough to implement identically elsewhere (the client library
     * renders the same string from the same bytes, and the two are compared as strings):
     * <ul>
     *   <li>RFC 2253 order: the last RDN of the encoding first, RDNs joined by ',', the attributes of a multi-valued
     *       RDN in encoded order joined by '+';</li>
     *   <li>CN, C, L, ST, O, OU, STREET, DC and UID by keyword; any other attribute type as its dotted OID;</li>
     *   <li>the value as text when its type is written by keyword, it is a UTF8String, PrintableString or IA5String, and
     *       its bytes are valid UTF-8; otherwise '#' and the lower-case hex of the value's DER encoding;</li>
     *   <li>in text, {@code , = + < > # ; " \} are escaped with a backslash wherever they stand, NUL is written
     *       {@code \00}, and spaces at either end are escaped with a backslash.</li>
     * </ul>
     * {@link javax.security.auth.x500.X500Principal#getName()} differs from this for string types it decodes loosely.
     */
    public static String rfc2253(byte[] derName) {
        List<String> rdns = new ArrayList<>();
        for (ASN1Encodable rdn : ASN1Sequence.getInstance(derName)) {
            List<String> attributes = new ArrayList<>();
            for (ASN1Encodable a : ASN1Set.getInstance(rdn)) {
                ASN1Sequence attribute = ASN1Sequence.getInstance(a);
                String oid = ASN1ObjectIdentifier.getInstance(attribute.getObjectAt(0)).getId();
                byte[] value = der(attribute.getObjectAt(1));
                String keyword = NAME_KEYWORDS.get(oid);
                String text = keyword == null ? null : text(value);
                attributes.add(text == null ? (keyword == null ? oid : keyword) + "=#" + HexFormat.of().formatHex(value) : keyword + "=" + escape(text));
            }
            rdns.add(String.join("+", attributes));
        }
        java.util.Collections.reverse(rdns);
        return String.join(",", rdns);
    }

    /** The country of the subject: the first C attribute in encoded order whose value is text. */
    public static Optional<String> subjectCountry(X509Certificate cert) {
        return country(cert.getSubjectX500Principal().getEncoded());
    }

    public static Optional<String> issuerCountry(X509Certificate cert) {
        return country(cert.getIssuerX500Principal().getEncoded());
    }

    static Optional<String> country(byte[] derName) {
        for (ASN1Encodable rdn : ASN1Sequence.getInstance(derName)) {
            for (ASN1Encodable a : ASN1Set.getInstance(rdn)) {
                ASN1Sequence attribute = ASN1Sequence.getInstance(a);
                if (COUNTRY.equals(ASN1ObjectIdentifier.getInstance(attribute.getObjectAt(0)).getId())) {
                    String text = text(der(attribute.getObjectAt(1)));
                    if (text != null) {
                        return Optional.of(text);
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static byte[] der(ASN1Encodable value) {
        try {
            return value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** The text of a UTF8String, PrintableString or IA5String whose content is valid UTF-8; null for anything else. */
    private static String text(byte[] tlv) {
        int tag = tlv[0] & 0xff;
        if (tag != 0x0c && tag != 0x13 && tag != 0x16) {
            return null;
        }
        int header = (tlv[1] & 0x80) == 0 ? 2 : 2 + (tlv[1] & 0x7f);
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(tlv, header, tlv.length - header)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    private static String escape(String text) {
        int lead = 0;
        int trail = text.length() - 1;
        while (lead < text.length() && text.charAt(lead) == ' ') {
            lead++;
        }
        while (trail >= 0 && text.charAt(trail) == ' ') {
            trail--;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == 0) {
                out.append("\\00");
            } else if (",=+<>#;\"\\".indexOf(c) >= 0 || i < lead || i > trail) {
                out.append('\\').append(c);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public static List<String> extendedKeyUsage(X509Certificate cert) {
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            return eku == null ? List.of() : eku;
        } catch (CertificateParsingException e) {
            return List.of();
        }
    }
}
