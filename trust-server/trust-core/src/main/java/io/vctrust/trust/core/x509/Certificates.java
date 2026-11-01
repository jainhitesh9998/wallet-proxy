package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.util.Hashes;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
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

    /** Value of the country (C) RDN of the subject, if present. */
    public static Optional<String> subjectCountry(X509Certificate cert) {
        return rdn(cert.getSubjectX500Principal().getName(), "C");
    }

    public static Optional<String> issuerCountry(X509Certificate cert) {
        return rdn(cert.getIssuerX500Principal().getName(), "C");
    }

    static Optional<String> rdn(String rfc2253, String attr) {
        try {
            var ln = new javax.naming.ldap.LdapName(rfc2253);
            return ln.getRdns().stream()
                    .filter(r -> r.getType().equalsIgnoreCase(attr))
                    .map(r -> String.valueOf(r.getValue()))
                    .findFirst();
        } catch (Exception e) {
            return Optional.empty();
        }
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
