package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.x509.CertificateSummary;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Serializable projection of a {@link TrustedEntity} used in API responses and decisions. */
public record EntityView(String id, String frameworkId, Set<EntityRole> roles, List<Identifier> identifiers,
                         List<LocalizedDisplay> display, List<CredentialAuthorization> authorizations,
                         EntityStatus status, Instant validFrom, Instant validUntil,
                         List<CertificateSummary> certificates, Map<String, Object> attributes, Provenance provenance,
                         Set<String> metadataTypes) {

    public static EntityView of(TrustedEntity e) {
        if (e == null) {
            return null;
        }
        return new EntityView(e.id(), e.frameworkId(), e.roles(), e.identifiers(), e.display(), e.authorizations(),
                e.status(), e.validFrom(), e.validUntil(),
                e.certificates().stream().map(CertificateSummary::of).toList(), e.attributes(), e.provenance(),
                e.metadata().keySet());
    }
}
