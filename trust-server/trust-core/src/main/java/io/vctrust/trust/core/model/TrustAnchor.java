package io.vctrust.trust.core.model;

import io.vctrust.trust.core.x509.Certificates;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
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

    /**
     * The most CRL locations an anchor record counts with, and the most the service fetches for one certificate of one
     * framework. A list decides how many there are, and every location is fetched by the service on each refresh and by
     * devices from the snapshot: without a bound, one list makes thousands of requests for one CA.
     */
    public static final int MAX_CRL_URLS = 8;

    /**
     * The http(s) locations where the record says the anchor's CA publishes its CRL ({@code constraints.crlUrls}: a list,
     * or one location), in the order named. Anything else (an {@code ldap:} URL, a path) is never fetched.
     */
    public List<String> crlUrls() {
        Object v = constraints.get("crlUrls");
        List<String> out = new ArrayList<>();
        if (v instanceof Collection<?> c) {
            c.forEach(x -> out.add(String.valueOf(x)));
        } else if (v instanceof String s && !s.isBlank()) {
            out.add(s);
        }
        return out.stream().filter(TrustAnchor::isHttp).toList();
    }

    /** Whether a location is an http(s) URL (the scheme in any case). */
    public static boolean isHttp(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        return u.startsWith("https://") || u.startsWith("http://");
    }
}
