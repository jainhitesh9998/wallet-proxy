package io.vctrust.trust.core.model;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The normalized, spec-agnostic view of a party that appears on some trust list.
 *
 * @param metadata       protocol metadata keyed by entity type, using OpenID Federation entity type names
 *                       ({@code openid_credential_issuer}, {@code oauth_authorization_server},
 *                       {@code openid_credential_verifier}, ...). Values are JSON objects as maps.
 * @param metadataPolicy optional OpenID Federation style metadata policy, keyed the same way, applied when
 *                       the service proxies the entity's live metadata
 * @param certificates   end-entity or CA certificates bound to the entity by its list (not trust anchors)
 */
public record TrustedEntity(String id, String frameworkId, Set<EntityRole> roles, List<Identifier> identifiers,
                            List<LocalizedDisplay> display, List<CredentialAuthorization> authorizations,
                            EntityStatus status, Instant validFrom, Instant validUntil,
                            List<X509Certificate> certificates, Map<String, Map<String, Object>> metadata,
                            Map<String, Map<String, Object>> metadataPolicy, Map<String, Object> attributes,
                            Provenance provenance) {

    public TrustedEntity {
        Objects.requireNonNull(id, "id");
        roles = roles == null || roles.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(roles));
        identifiers = identifiers == null ? List.of() : List.copyOf(identifiers);
        display = display == null ? List.of() : List.copyOf(display);
        authorizations = authorizations == null ? List.of() : List.copyOf(authorizations);
        status = status == null ? EntityStatus.ACTIVE : status;
        certificates = certificates == null ? List.of() : List.copyOf(certificates);
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        metadataPolicy = metadataPolicy == null ? Map.of() : Map.copyOf(metadataPolicy);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public boolean hasRole(EntityRole role) {
        return roles.contains(role);
    }

    public boolean isUsableAt(Instant time) {
        return status.isUsable()
                && (validFrom == null || !time.isBefore(validFrom))
                && (validUntil == null || !time.isAfter(validUntil));
    }

    /** Display name for the given locale, falling back to the first entry. */
    public String displayName(String locale) {
        return display.stream()
                .filter(d -> locale != null && locale.equalsIgnoreCase(d.locale()))
                .findFirst()
                .or(() -> display.stream().findFirst())
                .map(LocalizedDisplay::name)
                .orElse(id);
    }

    /**
     * Whether the entity may issue (or request) the given credential. Entities without any authorization
     * entries are unconstrained unless {@code strict} is set.
     */
    public boolean isAuthorizedFor(String format, String type, boolean strict) {
        if (authorizations.isEmpty()) {
            return !strict;
        }
        return authorizations.stream().anyMatch(a -> a.covers(format, type));
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    public static Builder builder(String id) {
        return new Builder(id);
    }

    /** Mutable builder; adapters assemble entities incrementally. */
    public static final class Builder {
        private String id;
        private String frameworkId;
        private final Set<EntityRole> roles = EnumSet.noneOf(EntityRole.class);
        private final List<Identifier> identifiers = new ArrayList<>();
        private final List<LocalizedDisplay> display = new ArrayList<>();
        private final List<CredentialAuthorization> authorizations = new ArrayList<>();
        private EntityStatus status = EntityStatus.ACTIVE;
        private Instant validFrom;
        private Instant validUntil;
        private final List<X509Certificate> certificates = new ArrayList<>();
        private final Map<String, Map<String, Object>> metadata = new LinkedHashMap<>();
        private final Map<String, Map<String, Object>> metadataPolicy = new LinkedHashMap<>();
        private final Map<String, Object> attributes = new LinkedHashMap<>();
        private Provenance provenance;

        private Builder(String id) {
            this.id = id;
        }

        private Builder(TrustedEntity e) {
            this.id = e.id;
            this.frameworkId = e.frameworkId;
            this.roles.addAll(e.roles);
            this.identifiers.addAll(e.identifiers);
            this.display.addAll(e.display);
            this.authorizations.addAll(e.authorizations);
            this.status = e.status;
            this.validFrom = e.validFrom;
            this.validUntil = e.validUntil;
            this.certificates.addAll(e.certificates);
            this.metadata.putAll(e.metadata);
            this.metadataPolicy.putAll(e.metadataPolicy);
            this.attributes.putAll(e.attributes);
            this.provenance = e.provenance;
        }

        public Builder id(String v) { this.id = v; return this; }
        public Builder framework(String v) { this.frameworkId = v; return this; }
        public Builder role(EntityRole v) { this.roles.add(v); return this; }
        public Builder roles(Iterable<EntityRole> v) { v.forEach(this.roles::add); return this; }
        /** The roles {@code v} and no others (where {@link #roles} adds to those the builder holds). */
        public Builder replaceRoles(Iterable<EntityRole> v) { this.roles.clear(); return roles(v); }
        public Builder identifier(Identifier v) { if (!identifiers.contains(v)) this.identifiers.add(v); return this; }
        public Builder identifier(IdentifierType t, String v) { return identifier(new Identifier(t, v)); }
        public Builder display(LocalizedDisplay v) { this.display.add(v); return this; }
        public Builder authorization(CredentialAuthorization v) { if (!authorizations.contains(v)) this.authorizations.add(v); return this; }
        public Builder status(EntityStatus v) { this.status = v; return this; }
        public Builder validFrom(Instant v) { this.validFrom = v; return this; }
        public Builder validUntil(Instant v) { this.validUntil = v; return this; }
        public Builder certificate(X509Certificate v) { this.certificates.add(v); return this; }
        public Builder metadata(String type, Map<String, Object> v) { this.metadata.put(type, v); return this; }
        public Builder metadataPolicy(String type, Map<String, Object> v) { this.metadataPolicy.put(type, v); return this; }
        public Builder attribute(String k, Object v) { if (v != null) this.attributes.put(k, v); return this; }
        public Builder provenance(Provenance v) { this.provenance = v; return this; }

        public boolean hasDisplay() { return !display.isEmpty(); }

        public TrustedEntity build() {
            return new TrustedEntity(id, frameworkId, roles, identifiers, display, authorizations, status,
                    validFrom, validUntil, certificates, metadata, metadataPolicy, attributes, provenance);
        }
    }
}
