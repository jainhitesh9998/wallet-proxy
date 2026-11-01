package io.vctrust.trust.core.evaluation;

import com.nimbusds.jose.jwk.JWK;
import io.vctrust.trust.core.did.Did;
import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.TrustDecision.AuthorizationEvidence;
import io.vctrust.trust.core.evaluation.TrustDecision.DidEvidence;
import io.vctrust.trust.core.evaluation.TrustDecision.Evidence;
import io.vctrust.trust.core.evaluation.TrustDecision.TrustedAuthorityMatch;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.x509.CertificateProfile;
import io.vctrust.trust.core.x509.CertificateProfiles;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.PathValidationResult;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.ValidationIssue;
import io.vctrust.trust.core.x509.X509PathValidator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluates {@link TrustQuery}s against the registry under a {@link ClientProfile}.
 *
 * <p>Evaluation is evidence-driven: each piece of supplied subject material (identifier, client_id prefix,
 * certificate chain, DID key reference, JWK) is checked independently, and the decision combines them:
 * <ul>
 *   <li>any contradicting evidence (invalid chain, revoked entity, unauthorized credential type, key not in
 *       the DID document, x509_hash mismatch) → {@link Decision#NOT_TRUSTED};</li>
 *   <li>otherwise a registry entity or a validated trust anchor → {@link Decision#TRUSTED};</li>
 *   <li>otherwise → {@link Decision#UNKNOWN}.</li>
 * </ul>
 */
public class TrustEvaluator {

    private final TrustRegistry registry;
    private final TrustSourceManager sources;
    private final DidResolver didResolver;
    private final X509PathValidator pathValidator;
    private final Clock clock;
    private final Duration decisionTtl;
    private final RevocationChecker revocation;

    public TrustEvaluator(TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                          X509PathValidator pathValidator, Clock clock, Duration decisionTtl) {
        this(registry, sources, didResolver, pathValidator, clock, decisionTtl, null);
    }

    /** @param revocation certificate revocation checking for chains (null: not checked) */
    public TrustEvaluator(TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                          X509PathValidator pathValidator, Clock clock, Duration decisionTtl, RevocationChecker revocation) {
        this.registry = registry;
        this.sources = sources;
        this.didResolver = didResolver;
        this.pathValidator = pathValidator;
        this.clock = clock;
        this.decisionTtl = decisionTtl;
        this.revocation = revocation;
    }

    /** Parsed OpenID4VP client identifier (OID4VP 1.0 §5.9.3). */
    public record ClientId(String raw, String prefix, String value) {
        static final Set<String> PREFIXES = Set.of("redirect_uri", "x509_san_dns", "x509_hash",
                "decentralized_identifier", "verifier_attestation", "openid_federation", "origin");

        public static ClientId parse(String raw) {
            int i = raw.indexOf(':');
            if (i > 0) {
                String p = raw.substring(0, i);
                if (PREFIXES.contains(p)) {
                    return new ClientId(raw, p, raw.substring(i + 1));
                }
            }
            return new ClientId(raw, "pre-registered", raw);
        }
    }

    public TrustDecision evaluate(TrustQuery query, ClientProfile profile) {
        Instant now = query.context().time() != null ? query.context().time() : clock.instant();
        RegistrySnapshot snap = registry.snapshot();
        List<Reason> reasons = new ArrayList<>();
        // ids: proven by the presented key material; identIds: only claimed by the identifier (see step 5)
        Set<Identifier> ids = new LinkedHashSet<>();
        Set<Identifier> identIds = new LinkedHashSet<>();
        EntityRole role = query.role();
        String format = CredentialFormats.canonical(query.context().credentialFormat());
        String type = query.context().credentialType();

        // 1. Identifiers from the identifier string (incl. OpenID4VP client_id prefixes)
        String expectedDns = null;
        String expectedHash = null;
        Map<String, Object> clientIdEvidence = null;
        String identifier = query.subject().identifier();
        if (identifier != null && !identifier.isBlank()) {
            if (role == EntityRole.VERIFIER) {
                ClientId cid = ClientId.parse(identifier);
                clientIdEvidence = new LinkedHashMap<>(Map.of("clientId", cid.raw(), "prefix", cid.prefix()));
                identIds.add(Identifier.of(IdentifierType.CLIENT_ID, cid.raw()));
                switch (cid.prefix()) {
                    case "x509_san_dns" -> {
                        expectedDns = cid.value();
                        identIds.add(Identifier.of(IdentifierType.DNS, cid.value()));
                    }
                    case "x509_hash" -> {
                        expectedHash = cid.value();
                        identIds.add(Identifier.of(IdentifierType.X509_SHA256, cid.value()));
                    }
                    case "decentralized_identifier" -> identIds.add(Identifier.did(cid.value()));
                    case "redirect_uri", "origin" -> identIds.add(Identifier.url(cid.value()));
                    case "openid_federation" -> {
                        identIds.add(Identifier.of(IdentifierType.FEDERATION_ENTITY, cid.value()));
                        identIds.add(Identifier.url(cid.value()));
                    }
                    case "verifier_attestation" -> reasons.add(Reason.info("client_id.verifier_attestation",
                            "Verifier attestation JWT must be validated by the wallet; matching registry by client_id only"));
                    default -> {
                        // pre-registered: matched by CLIENT_ID only
                    }
                }
                if (("x509_san_dns".equals(cid.prefix()) || "x509_hash".equals(cid.prefix()))
                        && query.subject().x5c().isEmpty()) {
                    reasons.add(Reason.error("client_id.x5c_required",
                            "Client identifier prefix " + cid.prefix() + " requires the request object's x5c chain"));
                }
            } else {
                identIds.addAll(identifiersFor(identifier));
            }
        }

        // 2. DID from kid
        String did = null;
        if (query.subject().kid() != null && query.subject().kid().startsWith("did:")) {
            try {
                did = Did.parse(query.subject().kid()).did();
                ids.add(Identifier.did(did));
            } catch (IllegalArgumentException e) {
                reasons.add(Reason.error("did.invalid", "kid is not a valid DID URL: " + e.getMessage()));
            }
        } else if (identifier != null && identifier.startsWith("did:")) {
            did = Identifier.did(identifier).value();
        }

        // 3. JWK thumbprint
        if (query.subject().jwk() != null && !query.subject().jwk().isEmpty()) {
            try {
                ids.add(Identifier.of(IdentifierType.JWK_THUMBPRINT,
                        JWK.parse(query.subject().jwk()).computeThumbprint().toString()));
            } catch (Exception e) {
                reasons.add(Reason.warning("jwk.invalid", "Unparseable JWK: " + e.getMessage()));
            }
        }

        // 4. Certificate chain
        List<X509Certificate> chain = List.of();
        if (!query.subject().x5c().isEmpty()) {
            try {
                chain = Certificates.fromBase64List(query.subject().x5c());
            } catch (IllegalArgumentException e) {
                reasons.add(Reason.error("x509.parse", e.getMessage()));
            }
        }
        PathValidationResult x509 = null;
        TrustAnchor validatedAnchor = null;
        if (!chain.isEmpty()) {
            X509Certificate leaf = chain.getFirst();
            String leafHash = Certificates.sha256Thumbprint(leaf);
            // The leaf's hash is a pin (the caller verifies with the leaf's key); its other names count only once the chain validates.
            ids.add(Identifier.of(IdentifierType.X509_SHA256, leafHash));
            if (expectedHash != null && !expectedHash.equals(leafHash)) {
                reasons.add(Reason.error("client_id.x509_hash_mismatch",
                        "x509_hash client_id does not match the SHA-256 hash of the leaf certificate"));
            }
            TrustDomain domain = domainFor(role, format);
            List<TrustAnchor> anchors = snap.anchors(domain).stream()
                    .filter(a -> profile.accepts(a.frameworkId())).toList();
            CertificateProfile certProfile = CertificateProfiles.forDomain(domain);
            String docType = CredentialFormats.MSO_MDOC.equals(format) ? type : null;
            x509 = pathValidator.validate(chain, anchors, new X509PathValidator.Options(now, certProfile,
                    new CertificateProfile.ProfileContext(expectedDns, docType), null)
                    .withRevocation(revocation, profile.requireRevocationStatus()).withRelaxedProfiles(profile.allowRelaxedProfiles()));
            if (x509.valid()) {
                validatedAnchor = x509.anchor();
                // The leaf's names are authenticated once the chain validates; use them to find the registered entity.
                Certificates.subjectKeyIdentifier(leaf).ifPresent(s -> ids.add(Identifier.of(IdentifierType.X509_SKI, s)));
                ids.add(Identifier.of(IdentifierType.X509_SUBJECT, leaf.getSubjectX500Principal().getName()));
                Certificates.dnsNames(leaf).forEach(n -> ids.add(Identifier.of(IdentifierType.DNS, n)));
                Certificates.uriNames(leaf).forEach(u -> ids.add(Identifier.url(u)));
                reasons.add(Reason.info("x509.valid", "Certificate chain validates to trust anchor "
                        + validatedAnchor.certificate().getSubjectX500Principal().getName() + " in domain " + domain));
                x509.issues().stream().filter(i -> i.code().startsWith("x509.revocation")
                        && i.severity() == ValidationIssue.Severity.WARNING).map(Reason::of).forEach(reasons::add);
            } else if (!x509.anchorFound()) {
                reasons.add(Reason.warning("x509.no_anchor", anchors.isEmpty()
                        ? "No trust anchors configured for domain '" + domain + "' in accepted frameworks"
                        : "Certificate chain does not lead to any trust anchor in domain '" + domain + "'"));
            } else {
                x509.issues().stream().filter(i -> i.isError()).map(Reason::of).forEach(reasons::add);
            }
            final String dnsToMatch = expectedDns;
            if (dnsToMatch != null && !x509.anchorFound()
                    && Certificates.dnsNames(leaf).stream().noneMatch(d -> d.equalsIgnoreCase(dnsToMatch))) {
                reasons.add(Reason.error("client_id.san_dns_mismatch",
                        "Leaf certificate has no SAN dNSName equal to the x509_san_dns client_id"));
            }
        }

        // 5. Registry candidates. With key material (x5c, DID kid, JWK) the entity must be bound to that key: by the
        // key's own identifiers, a pinned leaf certificate or the anchor's entity. The identifier alone is only a claim
        // then; it counts when the validated anchor is not tied to one entity and belongs to the identified entity's
        // framework. Without key material the identifier is a registry lookup (issuer metadata, or a key the caller
        // fetched from that identifier).
        boolean keyMaterial = !chain.isEmpty() || (query.subject().kid() != null && query.subject().kid().startsWith("did:"))
                || (query.subject().jwk() != null && !query.subject().jwk().isEmpty());
        Map<TrustedEntity, String> byIdentifier = new LinkedHashMap<>();
        for (Identifier id : identIds) {
            for (TrustedEntity e : snap.byIdentifier(id)) {
                if (profile.accepts(e.frameworkId())) byIdentifier.putIfAbsent(e, id.toString());
            }
        }
        Set<TrustedEntity> candidates = new LinkedHashSet<>();
        List<String> matched = new ArrayList<>();
        if (!keyMaterial) {
            byIdentifier.forEach((e, how) -> { if (candidates.add(e)) matched.add(how); });
        } else {
            for (Identifier id : ids) {
                for (TrustedEntity e : snap.byIdentifier(id)) {
                    if (profile.accepts(e.frameworkId()) && candidates.add(e)) matched.add(id.toString());
                }
            }
            if (!chain.isEmpty()) {
                X509Certificate leaf = chain.getFirst();
                snap.byCertificate(leaf).stream().filter(e -> profile.accepts(e.frameworkId())).forEach(e -> {
                    if (candidates.add(e)) matched.add("X509_CERT:" + Certificates.sha256Thumbprint(leaf));
                });
            }
            if (validatedAnchor != null && validatedAnchor.entityId() != null) {
                snap.entity(validatedAnchor.entityId()).filter(e -> profile.accepts(e.frameworkId())).ifPresent(e -> {
                    if (candidates.add(e)) matched.add("ANCHOR:" + e.id());
                });
            } else if (validatedAnchor != null && validatedAnchor.frameworkId() != null) {
                String fw = validatedAnchor.frameworkId();
                byIdentifier.forEach((e, how) -> {
                    if (fw.equals(e.frameworkId()) && candidates.add(e)) matched.add(how + " (anchor framework)");
                });
            }
            List<TrustedEntity> unbound = byIdentifier.keySet().stream()
                    .filter(e -> !candidates.contains(e) && (role == null || e.hasRole(role))).toList();
            if (!unbound.isEmpty()) {
                reasons.add(Reason.error("identifier.unbound", "The identifier names '" + unbound.getFirst().displayName("en")
                        + "', but the presented " + (chain.isEmpty() ? "key" : "certificate") + " is not bound to it"));
            }
        }
        if (candidates.isEmpty() && sources != null) {
            // On-demand discovery follows the same rule: the key's identifiers, or the identifier without key material.
            for (Identifier id : keyMaterial ? ids : identIds) {
                Optional<TrustedEntity> od = sources.resolveOnDemand(id, profile.frameworks());
                if (od.isPresent() && profile.accepts(od.get().frameworkId())) {
                    candidates.add(od.get());
                    matched.add(id + " (on-demand)");
                    break;
                }
            }
        }
        if (role != null) {
            List<TrustedEntity> withRole = candidates.stream().filter(e -> e.hasRole(role)).toList();
            if (!candidates.isEmpty() && withRole.isEmpty()) {
                reasons.add(Reason.warning("entity.role_mismatch", "Matching entity is registered, but not as " + role));
            }
            candidates.retainAll(withRole);
        }
        TrustedEntity entity = pick(candidates, validatedAnchor);

        // 6. DID evidence
        DidEvidence didEvidence = null;
        if (did != null && query.subject().kid() != null) {
            didEvidence = checkDid(did, query.subject().kid(), role, reasons);
        }

        // 7. Entity status and authorization
        AuthorizationEvidence authz = null;
        if (entity != null) {
            if (!entity.isUsableAt(now)) {
                reasons.add(Reason.error("entity.status", "Entity '" + entity.id() + "' is " + entity.status()
                        + (entity.validUntil() != null && now.isAfter(entity.validUntil()) ? " (expired)" : "")));
            }
            if (format != null || type != null) {
                // Every type the credential asserts must be authorized (a W3C VC may carry several).
                Set<String> types = new LinkedHashSet<>();
                if (type != null) types.add(type);
                types.addAll(query.context().credentialTypes());
                String denied = types.isEmpty()
                        ? (entity.isAuthorizedFor(format, null, profile.strictAuthorization()) ? null : "")
                        : types.stream().filter(t -> !entity.isAuthorizedFor(format, t, profile.strictAuthorization())).findFirst().orElse(null);
                boolean ok = denied == null;
                authz = new AuthorizationEvidence(format, type, ok, entity.authorizations().isEmpty()
                        ? (profile.strictAuthorization() ? "strict: no authorizations registered" : "unconstrained")
                        : "registered authorizations");
                if (!ok) {
                    String what = denied.isEmpty() ? (type == null ? "" : type) : denied;
                    reasons.add(Reason.error("entity.not_authorized", ("Entity '" + entity.id() + "' is not authorized for "
                            + (format == null ? "" : format + " ") + what).trim()));
                }
            }
        }
        if (validatedAnchor != null && validatedAnchor.frameworkId() != null && entity != null
                && !Objects.equals(validatedAnchor.frameworkId(), entity.frameworkId())) {
            reasons.add(Reason.info("framework.mixed", "Chain anchor framework '" + validatedAnchor.frameworkId()
                    + "' differs from entity framework '" + entity.frameworkId() + "'"));
        }

        // 8. OpenID4VP: response_uri host must match x509_san_dns (OID4VP §5.9.3), unless the RP is registered
        if (expectedDns != null && query.context().responseUri() != null) {
            String host = hostOf(query.context().responseUri());
            if (host != null && !host.equalsIgnoreCase(expectedDns)) {
                if (entity == null) {
                    reasons.add(Reason.error("client_id.response_uri_host",
                            "response_uri host '" + host + "' does not match x509_san_dns '" + expectedDns + "'"));
                } else {
                    reasons.add(Reason.warning("client_id.response_uri_host",
                            "response_uri host differs from x509_san_dns; accepted because the verifier is registered"));
                }
            }
        }

        // 9. DCQL trusted_authorities
        List<TrustedAuthorityMatch> taMatches = new ArrayList<>();
        for (TrustQuery.TrustedAuthority ta : query.context().trustedAuthorities()) {
            taMatches.add(matchAuthority(ta, chain, validatedAnchor, entity));
        }

        // 10. Decision
        boolean hasError = reasons.stream().anyMatch(Reason::isError);
        Decision decision;
        String summary;
        if (hasError) {
            decision = Decision.NOT_TRUSTED;
            summary = reasons.stream().filter(Reason::isError).findFirst().map(Reason::message).orElse("Not trusted");
        } else if (entity != null || validatedAnchor != null) {
            decision = Decision.TRUSTED;
            summary = entity != null
                    ? "Trusted " + (role == null ? "entity" : role.name().toLowerCase().replace('_', ' ')) + " '" + entity.displayName("en") + "'"
                    + (entity.frameworkId() == null ? "" : " in framework '" + entity.frameworkId() + "'")
                    : "Certificate chain validates to trusted anchor in framework '" + validatedAnchor.frameworkId() + "'";
        } else {
            decision = Decision.UNKNOWN;
            summary = "No trust information found for the subject in accepted frameworks";
        }
        String frameworkId = entity != null ? entity.frameworkId() : validatedAnchor != null ? validatedAnchor.frameworkId() : null;
        TrustFramework framework = frameworkId == null ? null : snap.framework(frameworkId).orElse(null);
        Instant validUntil = now.plus(decisionTtl);
        if (entity != null && entity.validUntil() != null && entity.validUntil().isBefore(validUntil)) {
            validUntil = entity.validUntil();
        }
        if (!chain.isEmpty() && chain.getFirst().getNotAfter().toInstant().isBefore(validUntil)) {
            validUntil = chain.getFirst().getNotAfter().toInstant();
        }
        List<String> provenance = new ArrayList<>();
        if (entity != null && entity.provenance() != null) {
            provenance.add(entity.provenance().sourceId());
        }
        if (validatedAnchor != null && validatedAnchor.provenance() != null
                && !provenance.contains(validatedAnchor.provenance().sourceId())) {
            provenance.add(validatedAnchor.provenance().sourceId());
        }
        if (clientIdEvidence != null) {
            clientIdEvidence.put("sources", provenance);
        }
        Evidence evidence = new Evidence(x509, didEvidence, authz, taMatches, matched, clientIdEvidence);
        return new TrustDecision(decision, summary, reasons, EntityView.of(entity), framework, evidence, now,
                validUntil, "trust-service");
    }

    /** Identifiers implied by a free-form identifier string. */
    public static List<Identifier> identifiersFor(String identifier) {
        List<Identifier> out = new ArrayList<>();
        if (identifier.startsWith("did:")) {
            out.add(Identifier.did(identifier));
        } else if (identifier.startsWith("https://") || identifier.startsWith("http://")) {
            out.add(Identifier.url(identifier));
            out.add(Identifier.of(IdentifierType.FEDERATION_ENTITY, identifier));
        } else {
            out.add(Identifier.of(IdentifierType.CLIENT_ID, identifier));
            out.add(Identifier.of(IdentifierType.OTHER, identifier));
        }
        return out;
    }

    /** Default trust domain for a role / format combination. */
    public static TrustDomain domainFor(EntityRole role, String format) {
        if (role == null) {
            return format == null ? TrustDomain.CREDENTIAL_ISSUER : TrustDomain.forCredentialFormat(format);
        }
        return switch (role) {
            case VERIFIER -> TrustDomain.VERIFIER_ACCESS;
            case WALLET_PROVIDER -> TrustDomain.WALLET_PROVIDER;
            case STATUS_LIST_PROVIDER -> TrustDomain.STATUS_LIST;
            default -> TrustDomain.forCredentialFormat(format);
        };
    }

    private DidEvidence checkDid(String did, String kid, EntityRole role, List<Reason> reasons) {
        DidResolutionResult res = didResolver.resolve(did);
        if (!res.isSuccess()) {
            String err = res.error().orElse("unknown");
            reasons.add(Reason.warning("did.unresolved", "DID " + did + " could not be resolved: " + err));
            return new DidEvidence(did, false, err, kid, null, null, null);
        }
        String vmRef = kid.contains("#") ? kid : null;
        if (vmRef == null) {
            return new DidEvidence(did, true, null, kid, null, null, null);
        }
        boolean found = res.verificationMethod(vmRef).isPresent();
        if (!found) {
            reasons.add(Reason.error("did.vm_not_found", "Verification method " + vmRef + " is not in the DID document"));
            return new DidEvidence(did, true, null, vmRef, false, null, null);
        }
        String relationship = role == EntityRole.VERIFIER || role == EntityRole.WALLET_PROVIDER ? "authentication" : "assertionMethod";
        boolean rel = res.hasRelationship(relationship, vmRef);
        if (!rel && res.hasRelationship(relationship, did)) {
            reasons.add(Reason.warning("did.relationship_lenient", relationship
                    + " lists the DID itself rather than the verification method; accepted leniently"));
            rel = true;
        } else if (!rel) {
            reasons.add(Reason.error("did.relationship", "Verification method " + vmRef + " is not authorized for " + relationship));
        }
        return new DidEvidence(did, true, null, vmRef, true, relationship, rel);
    }

    private static TrustedAuthorityMatch matchAuthority(TrustQuery.TrustedAuthority ta, List<X509Certificate> chain,
                                                        TrustAnchor anchor, TrustedEntity entity) {
        List<String> values = ta.values() == null ? List.of() : ta.values();
        switch (ta.type() == null ? "" : ta.type()) {
            case "aki" -> {
                Set<String> kids = new LinkedHashSet<>();
                for (X509Certificate c : chain) {
                    Certificates.authorityKeyIdentifier(c).ifPresent(kids::add);
                }
                if (anchor != null) {
                    Certificates.subjectKeyIdentifier(anchor.certificate()).ifPresent(kids::add);
                }
                return kids.stream().filter(values::contains).findFirst()
                        .map(v -> new TrustedAuthorityMatch(ta.type(), values, true, v))
                        .orElse(new TrustedAuthorityMatch(ta.type(), values, false, null));
            }
            case "etsi_tl", "openid_federation" -> {
                String attr = "etsi_tl".equals(ta.type()) ? "trustedListUri" : "trustAnchor";
                Set<String> have = new LinkedHashSet<>();
                if (anchor != null && anchor.provenance() != null) {
                    if (anchor.constraints().get(attr) != null) have.add(String.valueOf(anchor.constraints().get(attr)));
                    if (anchor.provenance().sourceUri() != null) have.add(anchor.provenance().sourceUri());
                }
                if (entity != null) {
                    if (entity.attributes().get(attr) != null) have.add(String.valueOf(entity.attributes().get(attr)));
                    if (entity.provenance() != null && entity.provenance().sourceUri() != null) have.add(entity.provenance().sourceUri());
                }
                return have.stream().filter(values::contains).findFirst()
                        .map(v -> new TrustedAuthorityMatch(ta.type(), values, true, v))
                        .orElse(new TrustedAuthorityMatch(ta.type(), values, false, null));
            }
            default -> {
                return new TrustedAuthorityMatch(ta.type(), values, false, null);
            }
        }
    }

    private static TrustedEntity pick(Set<TrustedEntity> candidates, TrustAnchor anchor) {
        if (candidates.isEmpty()) {
            return null;
        }
        if (anchor != null && anchor.entityId() != null) {
            for (TrustedEntity e : candidates) {
                if (e.id().equals(anchor.entityId())) {
                    return e;
                }
            }
        }
        return candidates.stream().filter(e -> e.status().isUsable()).findFirst().orElse(candidates.iterator().next());
    }

    private static String hostOf(String uri) {
        try {
            return URI.create(uri).getHost();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
