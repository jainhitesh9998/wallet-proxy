package io.vctrust.trust.core.x509;

import java.time.Instant;

/**
 * Revocation status of one certificate of a validated path.
 *
 * @param index        position in the path (0 = leaf)
 * @param serialNumber lowercase hex serial number
 * @param reason       the revocation reason (RFC 5280 name, e.g. {@code keyCompromise}) or why the status is unknown
 * @param method       {@code crl} or {@code ocsp}; null when nothing could be consulted
 * @param crlUrl       where the CRL (or OCSP response) came from; null for a CRL held from the trust list
 * @param source       who checked: {@code trust-service} on the server
 */
public record CertificateRevocation(int index, String serialNumber, String subject, Status status, String reason,
                                    Instant revokedAt, String method, String crlUrl, String source,
                                    Instant thisUpdate, Instant nextUpdate) {

    public enum Status { GOOD, REVOKED, ON_HOLD, UNKNOWN }
}
