package io.vctrust.trust.core.x509;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/** A serializable, display-friendly view of a certificate. */
public record CertificateSummary(String subject, String issuer, String serialNumber, Instant notBefore,
                                 Instant notAfter, String sha256, String subjectKeyIdentifier,
                                 String authorityKeyIdentifier, List<String> dnsNames, boolean ca,
                                 String certificate) {

    public static CertificateSummary of(X509Certificate c) {
        return new CertificateSummary(
                c.getSubjectX500Principal().getName(),
                c.getIssuerX500Principal().getName(),
                c.getSerialNumber().toString(16),
                c.getNotBefore().toInstant(),
                c.getNotAfter().toInstant(),
                Certificates.sha256Thumbprint(c),
                Certificates.subjectKeyIdentifier(c).orElse(null),
                Certificates.authorityKeyIdentifier(c).orElse(null),
                Certificates.dnsNames(c),
                Certificates.isCa(c),
                Certificates.toBase64(c));
    }
}
