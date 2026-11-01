package io.vctrust.trust.core.model;

import io.vctrust.trust.core.x509.Certificates;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An X.509 trust anchor within a {@link TrustDomain}.
 *
 * @param entityId    optional id of the {@link TrustedEntity} that operates this anchor (e.g. the issuing
 *                    authority behind an IACA); lets a path validation identify the entity
 * @param constraints source-specific constraints, e.g. {@code docTypes} for a VICAL entry or
 *                    {@code serviceType} for an ETSI service
 */
public record TrustAnchor(String id, TrustDomain domain, X509Certificate certificate, String frameworkId,
                          String entityId, EntityStatus status, Map<String, Object> constraints,
                          Provenance provenance) {

    public TrustAnchor {
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(certificate, "certificate");
        status = status == null ? EntityStatus.ACTIVE : status;
        constraints = constraints == null ? Map.of() : Map.copyOf(constraints);
        if (id == null) {
            id = domain.name() + ":" + Certificates.sha256Thumbprint(certificate);
        }
    }

    public String thumbprint() {
        return Certificates.sha256Thumbprint(certificate);
    }

    public boolean isUsableAt(Instant time) {
        return status.isUsable()
                && !time.isBefore(certificate.getNotBefore().toInstant())
                && !time.isAfter(certificate.getNotAfter().toInstant());
    }

    /** The doctypes this anchor may sign for, when constrained (VICAL {@code docType}). Empty = unconstrained. */
    @SuppressWarnings("unchecked")
    public List<String> docTypes() {
        Object v = constraints.get("docTypes");
        return v instanceof List<?> l ? (List<String>) l : List.of();
    }
}
