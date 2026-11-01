package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.TrustAnchor;

import java.time.Instant;
import java.util.List;

/**
 * Outcome of validating a certificate chain against the anchors of a trust domain.
 *
 * @param anchorFound false when no configured anchor could even be matched to the chain's issuer; callers use
 *                    this to distinguish "unknown" from "invalid"
 */
public record PathValidationResult(boolean valid, boolean anchorFound, TrustAnchor anchor,
                                   List<CertificateSummary> path, List<ValidationIssue> issues,
                                   String profile, Instant validationTime) {

    public PathValidationResult {
        path = path == null ? List.of() : List.copyOf(path);
        issues = issues == null ? List.of() : List.copyOf(issues);
    }
}
