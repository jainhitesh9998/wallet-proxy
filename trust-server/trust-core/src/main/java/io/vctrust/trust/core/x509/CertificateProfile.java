package io.vctrust.trust.core.x509;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Purpose-specific certificate checks applied on top of RFC 5280 path validation (e.g. the ISO 18013-5
 * Document Signer profile). Implementations are stateless.
 */
public interface CertificateProfile {

    String name();

    /**
     * @param path   the validated path, leaf first, excluding the anchor
     * @param anchor the trust anchor certificate the path chains to
     */
    List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext context);

    /** Inputs some profiles need beyond the certificates. */
    record ProfileContext(String expectedDnsName, String docType) {
        public static final ProfileContext NONE = new ProfileContext(null, null);
    }
}
