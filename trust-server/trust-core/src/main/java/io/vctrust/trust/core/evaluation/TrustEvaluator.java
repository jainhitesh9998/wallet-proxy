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
import io.vctrust.trust.core.policy.TrustMechanism;
import io.vctrust.trust.core.policy.TrustMechanisms;
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

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.function.Predicate;
import java.util.Comparator;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluates {@link TrustQuery}s against the registry under a {@link ClientProfile} and the operator's
 * {@link TrustMechanisms}.
 *
 * <p>Evaluation is evidence-driven: each piece of supplied subject material (identifier, client_id prefix,
 * certificate chain, DID key reference, JWK) is checked independently, and the decision combines them:
 * <ul>
 *   <li>any contradicting evidence (invalid chain, revoked entity, unauthorized credential type, key not in
 *       the DID document, x509_hash mismatch, a key the governing mechanism does not accept) →
 *       {@link Decision#NOT_TRUSTED};</li>
 *   <li>otherwise a registry entity or a validated trust anchor → {@link Decision#TRUSTED};</li>
 *   <li>otherwise → {@link Decision#UNKNOWN}.</li>
 * </ul>
 *
 * <p>The steps, in the order {@link #evaluate} takes them, are those of the client library's {@code LocalEvaluator},
 * by the same names: {@code begin} (which also selects the governing mechanism, {@code selectMechanism}), {@code claim},
 * {@code keyProof} (with {@code validateChain}), {@code acceptKey}, {@code findEntity}, {@code checkDid},
 * {@code checkStanding}, {@code checkResponseUri}, {@code matchAuthorities}, {@code decide}.
 */
public class TrustEvaluator {

    private final TrustRegistry registry;
    private final TrustSourceManager sources;
    private final DidResolver didResolver;
    private final X509PathValidator pathValidator;
    private final Clock clock;
    private final Duration decisionTtl;
    private final RevocationChecker revocation;
    private final TrustMechanisms mechanisms;

    /** An evaluator with revocation checking switched off: every certificate below an anchor has an unknown status. */
    public TrustEvaluator(TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                          X509PathValidator pathValidator, Clock clock, Duration decisionTtl) {
        this(registry, sources, didResolver, pathValidator, clock, decisionTtl,
                new RevocationChecker(RevocationChecker.CrlSource.SWITCHED_OFF, "trust-service"));
    }

    /** @param revocation certificate revocation checking for chains (see the full constructor) */
    public TrustEvaluator(TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                          X509PathValidator pathValidator, Clock clock, Duration decisionTtl, RevocationChecker revocation) {
        this(registry, sources, didResolver, pathValidator, clock, decisionTtl, revocation, TrustMechanisms.NONE);
    }

    /**
     * @param revocation certificate revocation checking for chains. Never null: with revocation checking switched off,
     *                   a checker over {@link RevocationChecker.CrlSource#SWITCHED_OFF}, which gives every certificate an
     *                   unknown status, so that a profile or mechanism that requires a known one still refuses the chain
     * @param mechanisms the operator's trust mechanisms, the same the snapshot carries to clients
     */
    public TrustEvaluator(TrustRegistry registry, TrustSourceManager sources, DidResolver didResolver,
                          X509PathValidator pathValidator, Clock clock, Duration decisionTtl, RevocationChecker revocation,
                          TrustMechanisms mechanisms) {
        this.registry = registry;
        this.sources = sources;
        this.didResolver = didResolver;
        this.pathValidator = pathValidator;
        this.clock = clock;
        this.decisionTtl = decisionTtl;
        this.revocation = Objects.requireNonNull(revocation,
                "revocation: a checker over RevocationChecker.CrlSource.SWITCHED_OFF when revocation checking is switched off");
        this.mechanisms = mechanisms == null ? TrustMechanisms.NONE : mechanisms;
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
        Evaluation ev = begin(query, profile);
        Claim claim = claim(ev);
        KeyProof key = keyProof(ev, claim);
        acceptKey(ev, key);
        Found found = findEntity(ev, claim, key);
        TrustedEntity entity = found.entity();
        DidEvidence did = checkDid(ev, key);
        AuthorizationEvidence authorization = checkStanding(ev, key, entity);
        checkResponseUri(ev, claim, entity);
        List<TrustedAuthorityMatch> authorities = matchAuthorities(ev, key, entity);
        Evidence evidence = new Evidence(key.x509(), did, authorization, authorities, found.matched(),
                clientIdEvidence(claim, key, entity), ev.mechanism() == null ? null : ev.mechanism().id());
        return decide(ev, key, entity, evidence);
    }

    /**
     * One evaluation: the query as the steps read it, the reasons they give, and the operator's mechanism that governs
     * it (null when none does: the question is then decided by the built-in rules alone).
     */
    private record Evaluation(TrustQuery query, ClientProfile profile, RegistrySnapshot snap, Instant now, EntityRole role,
                              String format, String type, Set<String> types, TrustMechanism mechanism, List<Reason> reasons) {
        TrustQuery.Subject subject() {
            return query.subject();
        }

        boolean hasDidKey() {
            return subject().kid() != null && subject().kid().startsWith("did:");
        }

        boolean hasJwk() {
            return subject().jwk() != null && !subject().jwk().isEmpty();
        }

        boolean strict() {
            return profile.strictAuthorization();
        }
    }

    /**
     * What the query claims. Its identifiers are only claimed by the identifier; those of the {@link KeyProof} are
     * proven by the presented key material (see {@link #findEntity}).
     */
    private record Claim(Set<Identifier> identifiers, ClientId clientId, String expectedDns, String expectedHash) {
    }

    /**
     * What the presented key proves.
     *
     * @param did    the DID of a DID key, else the DID the identifier names
     * @param anchor the trust anchor a valid chain leads to
     */
    private record KeyProof(Set<Identifier> identifiers, String did, List<X509Certificate> chain, PathValidationResult x509,
                            TrustAnchor anchor) {
    }

    /** Registry entries the query may be about, each with what it was found through. */
    private static final class Candidates {
        final Set<TrustedEntity> entities = new LinkedHashSet<>();
        final List<String> matched = new ArrayList<>();

        void take(TrustedEntity entity, String how) {
            if (entities.add(entity)) {
                matched.add(how);
            }
        }

        void takeAll(Map<TrustedEntity, String> found) {
            found.forEach(this::take);
        }
    }

    private record Found(TrustedEntity entity, List<String> matched) {
    }

    private Evaluation begin(TrustQuery query, ClientProfile profile) {
        Instant now = query.context().time() != null ? query.context().time() : clock.instant();
        RegistrySnapshot snap = registry.snapshot();
        // An empty format or type is no format or type: the two evaluators must not read "" differently.
        String format = CredentialFormats.canonical(blankToNull(query.context().credentialFormat()));
        String type = blankToNull(query.context().credentialType());
        // Every type the credential asserts must be authorized (a W3C VC may carry several).
        Set<String> types = new LinkedHashSet<>();
        if (type != null) {
            types.add(type);
        }
        query.context().credentialTypes().stream().filter(t -> t != null && !t.isBlank()).forEach(types::add);
        return new Evaluation(query, profile, snap, now, query.role(), format, type, types,
                selectMechanism(query.role(), format, types), new ArrayList<>());
    }

    /**
     * The operator's mechanism that governs the question: the first whose {@code for} matches its role, its format and
     * any of the types it asserts. None: the question is decided exactly as without mechanisms.
     */
    private TrustMechanism selectMechanism(EntityRole role, String format, Set<String> types) {
        return mechanisms.select(role, format, types);
    }

    /** Identifiers from the identifier string (incl. OpenID4VP client_id prefixes). */
    private static Claim claim(Evaluation ev) {
        String identifier = ev.subject().identifier();
        if (identifier == null || identifier.isBlank()) {
            return new Claim(Set.of(), null, null, null);
        }
        if (ev.role() != EntityRole.VERIFIER) {
            return new Claim(new LinkedHashSet<>(identifiersFor(identifier)), null, null, null);
        }
        return clientIdClaim(ev, ClientId.parse(identifier));
    }

    private static Claim clientIdClaim(Evaluation ev, ClientId cid) {
        Set<Identifier> identifiers = new LinkedHashSet<>();
        String expectedDns = null;
        String expectedHash = null;
        identifiers.add(Identifier.of(IdentifierType.CLIENT_ID, cid.raw()));
        switch (cid.prefix()) {
            case "x509_san_dns" -> {
                expectedDns = cid.value();
                identifiers.add(Identifier.of(IdentifierType.DNS, cid.value()));
            }
            case "x509_hash" -> {
                expectedHash = cid.value();
                identifiers.add(Identifier.of(IdentifierType.X509_SHA256, cid.value()));
            }
            case "decentralized_identifier" -> identifiers.add(Identifier.did(cid.value()));
            case "redirect_uri", "origin" -> identifiers.add(Identifier.url(cid.value()));
            case "openid_federation" -> {
                identifiers.add(Identifier.of(IdentifierType.FEDERATION_ENTITY, cid.value()));
                identifiers.add(Identifier.url(cid.value()));
            }
            case "verifier_attestation" -> ev.reasons().add(Reason.info("client_id.verifier_attestation",
                    "Verifier attestation JWT must be validated by the wallet; matching registry by client_id only"));
            default -> {
                // pre-registered: matched by CLIENT_ID only
            }
        }
        if (("x509_san_dns".equals(cid.prefix()) || "x509_hash".equals(cid.prefix())) && ev.subject().x5c().isEmpty()) {
            ev.reasons().add(Reason.error("client_id.x5c_required",
                    "Client identifier prefix " + cid.prefix() + " requires the request object's x5c chain"));
        }
        return new Claim(identifiers, cid, expectedDns, expectedHash);
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

    private KeyProof keyProof(Evaluation ev, Claim claim) {
        Set<Identifier> proven = new LinkedHashSet<>();
        String did = keyDid(ev, proven);
        keyThumbprint(ev, proven);
        List<X509Certificate> chain = parseChain(ev);
        PathValidationResult x509 = chain.isEmpty() ? null : validateChain(ev, claim, chain, proven);
        // A client identifier the presented key itself proves is one of the key's identifiers, so a verifier registered
        // by its client_id is found: x509_hash of the leaf certificate, x509_san_dns naming a dNSName of a validated
        // leaf, decentralized_identifier of the key's DID.
        if (claim.clientId() != null && provesClientId(claim.clientId(), chain, x509, ev.hasDidKey() ? did : null)) {
            proven.add(Identifier.of(IdentifierType.CLIENT_ID, claim.clientId().raw()));
        }
        return new KeyProof(proven, did, chain, x509, x509 != null && x509.valid() ? x509.anchor() : null);
    }

    /**
     * DID from kid. A query names one key: the certificate's or the DID's. With both, the evaluator cannot tell
     * which one the caller verified the signature with, and the other may be copied from anyone.
     */
    private static String keyDid(Evaluation ev, Set<Identifier> proven) {
        TrustQuery.Subject subject = ev.subject();
        if (!subject.x5c().isEmpty() && ev.hasDidKey()) {
            ev.reasons().add(Reason.error("key.ambiguous",
                    "The query presents both an x5c chain and a DID key; pass only the key the signature was verified with"));
        }
        String did = null;
        if (ev.hasDidKey()) {
            try {
                did = Did.parse(subject.kid()).did();
                proven.add(Identifier.did(did));
            } catch (IllegalArgumentException e) {
                ev.reasons().add(Reason.error("did.invalid", "kid is not a valid DID URL: " + e.getMessage()));
            }
        } else if (subject.identifier() != null && subject.identifier().startsWith("did:")) {
            did = Identifier.did(subject.identifier()).value();
        }
        return did;
    }

    private static void keyThumbprint(Evaluation ev, Set<Identifier> proven) {
        if (ev.hasJwk()) {
            try {
                proven.add(Identifier.of(IdentifierType.JWK_THUMBPRINT,
                        JWK.parse(ev.subject().jwk()).computeThumbprint().toString()));
            } catch (Exception e) {
                ev.reasons().add(Reason.warning("jwk.invalid", "Unparseable JWK: " + e.getMessage()));
            }
        }
    }

    /** Certificates read from one x5c: a real chain has a few, and each one costs parsing and path building. */
    public static final int MAX_CHAIN = 10;

    private static List<X509Certificate> parseChain(Evaluation ev) {
        if (ev.subject().x5c().isEmpty()) {
            return List.of();
        }
        if (ev.subject().x5c().size() > MAX_CHAIN) {
            ev.reasons().add(Reason.error("x509.chain_too_long", "x5c holds " + ev.subject().x5c().size()
                    + " certificates; a chain of more than " + MAX_CHAIN + " is not read"));
            return List.of();
        }
        try {
            return Certificates.fromBase64List(ev.subject().x5c());
        } catch (IllegalArgumentException e) {
            ev.reasons().add(Reason.error("x509.parse", e.getMessage()));
            return List.of();
        }
    }

    private PathValidationResult validateChain(Evaluation ev, Claim claim, List<X509Certificate> chain, Set<Identifier> proven) {
        List<Reason> reasons = ev.reasons();
        X509Certificate leaf = chain.getFirst();
        String leafHash = Certificates.sha256Thumbprint(leaf);
        // The leaf's hash is a pin (the caller verifies with the leaf's key); its other names count only once the chain validates.
        proven.add(Identifier.of(IdentifierType.X509_SHA256, leafHash));
        if (claim.expectedHash() != null && !claim.expectedHash().equals(leafHash)) {
            reasons.add(Reason.error("client_id.x509_hash_mismatch",
                    "x509_hash client_id does not match the SHA-256 hash of the leaf certificate"));
        }
        // The question's own domain, unless the governing mechanism names the domain whose anchors count instead.
        TrustDomain questionDomain = domainFor(ev.role(), ev.format());
        TrustMechanism.X509 rule = ev.mechanism() == null ? null : ev.mechanism().x509();
        TrustDomain domain = rule != null && rule.domain() != null ? TrustDomain.of(rule.domain()) : questionDomain;
        List<TrustAnchor> anchors = ev.snap().anchors(domain).stream()
                .filter(a -> ev.profile().accepts(a.frameworkId())).toList();
        // The built-in profile follows the question, also when its anchors are another domain's: a mechanism adds
        // requirements on top of it and never takes one away.
        CertificateProfile certProfile = CertificateProfiles.withRequirements(CertificateProfiles.forDomain(questionDomain),
                rule == null ? null : rule.profile());
        boolean revocationRequired = ev.profile().requireRevocationStatus() || (rule != null && rule.revocationRequired());
        String docType = CredentialFormats.MSO_MDOC.equals(ev.format()) ? ev.type() : null;
        PathValidationResult x509 = pathValidator.validate(chain, anchors, new X509PathValidator.Options(ev.now(), certProfile,
                new CertificateProfile.ProfileContext(claim.expectedDns(), docType), null)
                .withRevocation(revocation, revocationRequired));
        if (x509.valid()) {
            // The leaf's names are authenticated once the chain validates; use them to find the registered entity.
            Certificates.subjectKeyIdentifier(leaf).ifPresent(s -> proven.add(Identifier.of(IdentifierType.X509_SKI, s)));
            proven.add(Identifier.of(IdentifierType.X509_SUBJECT, Certificates.subjectName(leaf)));
            Certificates.dnsNames(leaf).forEach(n -> proven.add(Identifier.of(IdentifierType.DNS, n)));
            Certificates.uriNames(leaf).forEach(u -> proven.add(Identifier.url(u)));
            reasons.add(Reason.info("x509.valid", "Certificate chain validates to trust anchor "
                    + x509.anchor().certificate().getSubjectX500Principal().getName() + " in domain " + domain));
            x509.issues().stream().filter(i -> i.code().startsWith("x509.revocation")
                    && i.severity() == ValidationIssue.Severity.WARNING).map(Reason::of).forEach(reasons::add);
        } else if (!x509.anchorFound()) {
            reasons.add(Reason.warning("x509.no_anchor", anchors.isEmpty()
                    ? "No trust anchors configured for domain '" + domain + "' in accepted frameworks"
                    : "Certificate chain does not lead to any trust anchor in domain '" + domain + "'"));
        } else {
            x509.issues().stream().filter(i -> i.isError()).map(Reason::of).forEach(reasons::add);
        }
        String expectedDns = claim.expectedDns();
        if (expectedDns != null && !x509.anchorFound()
                && Certificates.dnsNames(leaf).stream().noneMatch(d -> d.equalsIgnoreCase(expectedDns))) {
            reasons.add(Reason.error("client_id.san_dns_mismatch",
                    "Leaf certificate has no SAN dNSName equal to the x509_san_dns client_id"));
        }
        return x509;
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

    /**
     * The proofs of key the governing mechanism accepts: a key presented another way (an {@code x5c} chain, a DID key,
     * a bare JWK) is refused, and so is a DID key of a method it does not list. A question without key material is a
     * registry lookup, and nothing here refuses it.
     */
    private static void acceptKey(Evaluation ev, KeyProof key) {
        TrustMechanism m = ev.mechanism();
        if (m == null) {
            return;
        }
        Map<String, Boolean> presented = new LinkedHashMap<>();
        presented.put("x5c", !ev.subject().x5c().isEmpty());
        presented.put("did", ev.hasDidKey());
        presented.put("jwk", ev.hasJwk());
        presented.forEach((kind, present) -> {
            if (present && !m.accepts(kind)) {
                ev.reasons().add(Reason.error("mechanism.key_not_accepted", "Trust mechanism '" + m.id() + "' does not accept a key presented as "
                        + kind + "; it accepts " + String.join(", ", m.keys())));
            }
        });
        // key.did() is the DID of a DID key only when it parsed; one that did not is refused as did.invalid already.
        if (m.did() != null && ev.hasDidKey() && key.did() != null) {
            String method = Did.parse(key.did()).method();
            if (!m.did().methods().contains(method)) {
                ev.reasons().add(Reason.error("mechanism.did_method_not_accepted", "Trust mechanism '" + m.id() + "' does not accept a key of DID method '"
                        + method + "'; it accepts " + String.join(", ", m.did().methods())));
            }
        }
    }

    private static boolean provesClientId(ClientId cid, List<X509Certificate> chain, PathValidationResult x509, String keyDid) {
        return switch (cid.prefix()) {
            case "x509_hash" -> !chain.isEmpty() && cid.value().equals(Certificates.sha256Thumbprint(chain.getFirst()));
            case "x509_san_dns" -> x509 != null && x509.valid()
                    && Certificates.dnsNames(chain.getFirst()).stream().anyMatch(d -> d.equalsIgnoreCase(cid.value()));
            case "decentralized_identifier" -> keyDid != null && keyDid.equals(Identifier.did(cid.value()).value());
            default -> false;
        };
    }

    /**
     * Registry candidates. With key material (x5c, DID kid, JWK) an entity is found only through what that key
     * proves: the key's own identifiers (a validated certificate's names, the DID of a DID key, a JWK thumbprint),
     * a pinned leaf certificate, or the entity the validated anchor belongs to. The identifier in the query is
     * then only a claim. Without key material the identifier is a registry lookup (issuer metadata, or a key the
     * caller fetched from that identifier).
     */
    private Found findEntity(Evaluation ev, Claim claim, KeyProof key) {
        boolean keyMaterial = !key.chain().isEmpty() || ev.hasDidKey() || ev.hasJwk();
        Map<TrustedEntity, String> claimed = registered(ev, claim.identifiers());
        Candidates candidates = new Candidates();
        if (!keyMaterial) {
            candidates.takeAll(claimed);
        } else {
            takeBoundToKey(ev, key, candidates);
            checkPinnedCertificate(ev, key, candidates);
            checkClaimBound(ev, key, claimed.keySet(), candidates);
        }
        if (candidates.entities.isEmpty() && sources != null) {
            // On-demand discovery follows the same rule: the key's identifiers, or the identifier without key material.
            lookUpOnDemand(ev, keyMaterial ? key.identifiers() : claim.identifiers(), candidates);
        }
        keepRole(ev, candidates);
        TrustedEntity entity = pick(candidates.entities, key.anchor(), ev.now(),
                e -> denied(e, ev.format(), ev.types(), ev.strict()) == null);
        return new Found(entity, candidates.matched);
    }

    private static Map<TrustedEntity, String> registered(Evaluation ev, Collection<Identifier> identifiers) {
        Map<TrustedEntity, String> found = new LinkedHashMap<>();
        for (Identifier id : identifiers) {
            for (TrustedEntity e : ev.snap().byIdentifier(id)) {
                if (ev.profile().accepts(e.frameworkId())) found.putIfAbsent(e, id.toString());
            }
        }
        return found;
    }

    private static void takeBoundToKey(Evaluation ev, KeyProof key, Candidates candidates) {
        candidates.takeAll(registered(ev, key.identifiers()));
        if (!key.chain().isEmpty()) {
            X509Certificate leaf = key.chain().getFirst();
            ev.snap().byCertificate(leaf).stream().filter(e -> ev.profile().accepts(e.frameworkId()))
                    .forEach(e -> candidates.take(e, "X509_CERT:" + Certificates.sha256Thumbprint(leaf)));
        }
        TrustAnchor anchor = key.anchor();
        if (anchor != null && anchor.entityId() != null) {
            ev.snap().entity(anchor.entityId()).filter(e -> ev.profile().accepts(e.frameworkId()))
                    .ifPresent(e -> candidates.take(e, "ANCHOR:" + e.id()));
        }
    }

    private static void checkPinnedCertificate(Evaluation ev, KeyProof key, Candidates candidates) {
        if (!key.chain().isEmpty() && key.anchor() == null && !candidates.entities.isEmpty()) {
            // No anchor vouches for this certificate: it stands only as a registered pin, and then only while valid.
            X509Certificate leaf = key.chain().getFirst();
            Instant now = ev.now();
            if (now.isBefore(leaf.getNotBefore().toInstant()) || now.isAfter(leaf.getNotAfter().toInstant())) {
                ev.reasons().add(Reason.error("x509.pinned_expired", "The pinned certificate is not valid at " + now));
            }
        }
    }

    private static void checkClaimBound(Evaluation ev, KeyProof key, Collection<TrustedEntity> claimed, Candidates candidates) {
        // Refused when the identifier names entities in this role and the key is bound to none of them.
        EntityRole role = ev.role();
        List<TrustedEntity> named = claimed.stream().filter(e -> role == null || e.hasRole(role)).toList();
        if (!named.isEmpty() && named.stream().noneMatch(candidates.entities::contains)) {
            ev.reasons().add(Reason.error("identifier.unbound", "The identifier names '" + named.getFirst().displayName("en")
                    + "', but the presented " + (key.chain().isEmpty() ? "key" : "certificate") + " is not bound to it"));
        }
    }

    private void lookUpOnDemand(Evaluation ev, Collection<Identifier> identifiers, Candidates candidates) {
        ClientProfile profile = ev.profile();
        for (Identifier id : identifiers) {
            Optional<TrustedEntity> od = sources.resolveOnDemand(id, profile::accepts);
            if (od.isPresent() && profile.accepts(od.get().frameworkId())) {
                candidates.take(od.get(), id + " (on-demand)");
                ev.reasons().add(Reason.info("lookup.on_demand",
                        "Not in the trust snapshot; registry entry obtained by an on-demand lookup at the trust service"));
                break;
            }
        }
    }

    private static void keepRole(Evaluation ev, Candidates candidates) {
        EntityRole role = ev.role();
        if (role != null) {
            List<TrustedEntity> withRole = candidates.entities.stream().filter(e -> e.hasRole(role)).toList();
            if (!candidates.entities.isEmpty() && withRole.isEmpty()) {
                ev.reasons().add(Reason.warning("entity.role_mismatch", "Matching entity is registered, but not as " + role));
            }
            candidates.entities.retainAll(withRole);
        }
    }

    /**
     * The entity a decision is about. When the key is bound to several registered parties, which one is meant must
     * not depend on the order a registry or a snapshot happens to list them in: the entity the anchor belongs to;
     * else, in order of entity id, the first in good standing that is authorized for what is asked; else the first
     * in good standing; else the first.
     */
    private static TrustedEntity pick(Collection<TrustedEntity> candidates, TrustAnchor anchor, Instant now, Predicate<TrustedEntity> authorized) {
        if (candidates.isEmpty()) {
            return null;
        }
        List<TrustedEntity> ordered = candidates.stream().sorted(Comparator.comparing(TrustedEntity::id)).toList();
        if (anchor != null && anchor.entityId() != null) {
            for (TrustedEntity e : ordered) {
                if (e.id().equals(anchor.entityId())) {
                    return e;
                }
            }
        }
        return ordered.stream().filter(e -> e.isUsableAt(now) && authorized.test(e)).findFirst()
                .or(() -> ordered.stream().filter(e -> e.isUsableAt(now)).findFirst())
                .orElse(ordered.getFirst());
    }

    /** The type the entity is not authorized for ("" when no type is asked and the format is refused); null when it is authorized. */
    private static String denied(TrustedEntity entity, String format, Set<String> types, boolean strict) {
        if (format == null && types.isEmpty()) {
            return null;
        }
        if (types.isEmpty()) {
            return entity.isAuthorizedFor(format, null, strict) ? null : "";
        }
        return types.stream().filter(t -> !entity.isAuthorizedFor(format, t, strict)).findFirst().orElse(null);
    }

    private DidEvidence checkDid(Evaluation ev, KeyProof key) {
        String did = key.did();
        String kid = ev.subject().kid();
        if (did == null || kid == null) {
            return null;
        }
        List<Reason> reasons = ev.reasons();
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
        String relationship = ev.role() == EntityRole.VERIFIER || ev.role() == EntityRole.WALLET_PROVIDER ? "authentication" : "assertionMethod";
        // DID Core: a relationship lists verification methods (by reference or embedded), never the DID itself.
        boolean rel = res.hasRelationship(relationship, vmRef);
        if (!rel) {
            reasons.add(Reason.error("did.relationship", "Verification method " + vmRef + " is not authorized for " + relationship));
        }
        return new DidEvidence(did, true, null, vmRef, true, relationship, rel);
    }

    private static AuthorizationEvidence checkStanding(Evaluation ev, KeyProof key, TrustedEntity entity) {
        if (entity == null) {
            return null;
        }
        Instant now = ev.now();
        if (!entity.isUsableAt(now)) {
            ev.reasons().add(Reason.error("entity.status", "Entity '" + entity.id() + "' is " + entity.status()
                    + (entity.validUntil() != null && now.isAfter(entity.validUntil()) ? " (expired)" : "")));
        }
        AuthorizationEvidence authorization = ev.format() != null || ev.type() != null ? checkAuthorization(ev, entity) : null;
        TrustAnchor anchor = key.anchor();
        if (anchor != null && anchor.frameworkId() != null && !Objects.equals(anchor.frameworkId(), entity.frameworkId())) {
            ev.reasons().add(Reason.info("framework.mixed", "Chain anchor framework '" + anchor.frameworkId()
                    + "' differs from entity framework '" + entity.frameworkId() + "'"));
        }
        return authorization;
    }

    private static AuthorizationEvidence checkAuthorization(Evaluation ev, TrustedEntity entity) {
        String format = ev.format();
        String type = ev.type();
        String denied = denied(entity, format, ev.types(), ev.strict());
        if (denied != null) {
            String what = denied.isEmpty() ? (type == null ? "" : type) : denied;
            ev.reasons().add(Reason.error("entity.not_authorized", ("Entity '" + entity.id() + "' is not authorized for "
                    + (format == null ? "" : format + " ") + what).trim()));
        }
        return new AuthorizationEvidence(format, type, denied == null, entity.authorizations().isEmpty()
                ? (ev.strict() ? "strict: no authorizations registered" : "unconstrained")
                : "registered authorizations");
    }

    /** OpenID4VP: response_uri host must match x509_san_dns (OID4VP §5.9.3), unless the RP is registered. */
    private static void checkResponseUri(Evaluation ev, Claim claim, TrustedEntity entity) {
        String expectedDns = claim.expectedDns();
        String responseUri = ev.query().context().responseUri();
        if (expectedDns == null || responseUri == null) {
            return;
        }
        // A response_uri that is not a plain https URL has no host to compare, and is refused like a mismatch.
        String host = Identifier.httpsHost(responseUri);
        if (host == null) {
            ev.reasons().add(Reason.error("client_id.response_uri_host", "response_uri is not a plain https URL"));
        } else if (!host.equals(expectedDns.toLowerCase(Locale.ROOT))) {
            ev.reasons().add(entity != null
                    ? Reason.warning("client_id.response_uri_host",
                            "response_uri host differs from x509_san_dns; accepted because the verifier is registered")
                    : Reason.error("client_id.response_uri_host",
                            "response_uri host '" + host + "' does not match x509_san_dns '" + expectedDns + "'"));
        }
    }

    /** DCQL trusted_authorities. */
    private static List<TrustedAuthorityMatch> matchAuthorities(Evaluation ev, KeyProof key, TrustedEntity entity) {
        List<TrustedAuthorityMatch> matches = new ArrayList<>();
        for (TrustQuery.TrustedAuthority ta : ev.query().context().trustedAuthorities()) {
            matches.add(matchAuthority(ta, key.chain(), key.anchor(), entity));
        }
        return matches;
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
                if (anchor != null) {
                    if (anchor.constraints().get(attr) != null) have.add(String.valueOf(anchor.constraints().get(attr)));
                    if (anchor.provenance() != null && anchor.provenance().sourceUri() != null) have.add(anchor.provenance().sourceUri());
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

    private TrustDecision decide(Evaluation ev, KeyProof key, TrustedEntity entity, Evidence evidence) {
        List<Reason> reasons = ev.reasons();
        EntityRole role = ev.role();
        TrustAnchor anchor = key.anchor();
        boolean hasError = reasons.stream().anyMatch(Reason::isError);
        Decision decision;
        String summary;
        if (hasError) {
            decision = Decision.NOT_TRUSTED;
            summary = reasons.stream().filter(Reason::isError).findFirst().map(Reason::message).orElse("Not trusted");
        } else if (entity != null || anchor != null) {
            decision = Decision.TRUSTED;
            summary = entity != null
                    ? "Trusted " + (role == null ? "entity" : role.name().toLowerCase().replace('_', ' ')) + " '" + entity.displayName("en") + "'"
                    + (entity.frameworkId() == null ? "" : " in framework '" + entity.frameworkId() + "'")
                    : "Certificate chain validates to trusted anchor in framework '" + anchor.frameworkId() + "'";
        } else {
            decision = Decision.UNKNOWN;
            summary = "No trust information found for the subject in accepted frameworks";
        }
        String frameworkId = entity != null ? entity.frameworkId() : anchor != null ? anchor.frameworkId() : null;
        TrustFramework framework = frameworkId == null ? null : ev.snap().framework(frameworkId).orElse(null);
        return new TrustDecision(decision, summary, reasons, EntityView.of(entity), framework, evidence, ev.now(),
                validUntil(ev, key, entity), "trust-service");
    }

    private Instant validUntil(Evaluation ev, KeyProof key, TrustedEntity entity) {
        Instant validUntil = ev.now().plus(decisionTtl);
        if (entity != null && entity.validUntil() != null && entity.validUntil().isBefore(validUntil)) {
            validUntil = entity.validUntil();
        }
        List<X509Certificate> chain = key.chain();
        if (!chain.isEmpty() && chain.getFirst().getNotAfter().toInstant().isBefore(validUntil)) {
            validUntil = chain.getFirst().getNotAfter().toInstant();
        }
        return validUntil;
    }

    private static Map<String, Object> clientIdEvidence(Claim claim, KeyProof key, TrustedEntity entity) {
        ClientId cid = claim.clientId();
        if (cid == null) {
            return null;
        }
        TrustAnchor anchor = key.anchor();
        List<String> provenance = new ArrayList<>();
        if (entity != null && entity.provenance() != null) {
            provenance.add(entity.provenance().sourceId());
        }
        if (anchor != null && anchor.provenance() != null && !provenance.contains(anchor.provenance().sourceId())) {
            provenance.add(anchor.provenance().sourceId());
        }
        Map<String, Object> evidence = new LinkedHashMap<>(Map.of("clientId", cid.raw(), "prefix", cid.prefix()));
        evidence.put("sources", provenance);
        return evidence;
    }

    /** A format or type that is empty or only spaces, tabs or line breaks is absent; client libraries apply the same rule. */
    private static String blankToNull(String s) {
        return s == null || s.matches("[ \\t\\r\\n]*") ? null : s;
    }
}
