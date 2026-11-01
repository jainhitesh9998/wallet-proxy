package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.x509.PathValidationResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The answer to a {@link TrustQuery}, with the evidence it rests on so that clients can display and audit it.
 *
 * @param source who produced the decision: {@code trust-service} here; client libraries set
 *               {@code snapshot} or {@code fallback} for locally derived decisions
 */
public record TrustDecision(Decision decision, String summary, List<Reason> reasons, EntityView entity,
                            TrustFramework framework, Evidence evidence, Instant evaluatedAt, Instant validUntil,
                            String source) {

    public TrustDecision {
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }

    public boolean isTrusted() {
        return decision == Decision.TRUSTED;
    }

    /** Evidence collected while evaluating. Absent parts were not applicable. */
    public record Evidence(PathValidationResult x509, DidEvidence did, AuthorizationEvidence authorization,
                           List<TrustedAuthorityMatch> trustedAuthorities, List<String> matchedIdentifiers,
                           Map<String, Object> clientId) {
        public Evidence {
            trustedAuthorities = trustedAuthorities == null ? List.of() : List.copyOf(trustedAuthorities);
            matchedIdentifiers = matchedIdentifiers == null ? List.of() : List.copyOf(matchedIdentifiers);
        }
    }

    public record DidEvidence(String did, boolean resolved, String error, String verificationMethod,
                              Boolean verificationMethodFound, String relationship, Boolean relationshipValid) {
    }

    public record AuthorizationEvidence(String format, String type, boolean authorized, String rule) {
    }

    public record TrustedAuthorityMatch(String type, List<String> values, boolean matched, String matchedValue) {
    }
}
