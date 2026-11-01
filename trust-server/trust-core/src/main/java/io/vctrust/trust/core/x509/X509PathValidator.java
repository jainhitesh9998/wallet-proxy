package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.TrustAnchor;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * RFC 5280 path validation against a set of {@link TrustAnchor}s, followed by purpose-specific
 * {@link CertificateProfile} checks.
 *
 * <p>Accepted chain shapes (all leaf first): a full chain ending in the anchor itself, a chain ending just
 * below the anchor (the HAIP / x5c convention), or a single certificate that is itself pinned as an anchor.
 *
 * <p>With a {@link Revocation} context, every certificate below the anchor is checked for revocation once the
 * path validates (a directly pinned certificate is an anchor itself; its status comes from the trust list).
 */
public final class X509PathValidator {

    /** Revocation checking for one validation; {@code required}: an undeterminable status is an error. */
    public record Revocation(RevocationChecker checker, boolean required) {
    }

    /** Options for one validation; {@code revocation} null skips revocation checking. */
    public record Options(Instant time, CertificateProfile profile, CertificateProfile.ProfileContext profileContext,
                          Revocation revocation) {
        public Options {
            time = time == null ? Instant.now() : time;
            profile = profile == null ? CertificateProfiles.NONE : profile;
            profileContext = profileContext == null ? CertificateProfile.ProfileContext.NONE : profileContext;
        }

        public static Options at(Instant time, CertificateProfile profile) {
            return new Options(time, profile, null, null);
        }

        public Options withRevocation(RevocationChecker checker, boolean required) {
            return new Options(time, profile, profileContext, checker == null ? null : new Revocation(checker, required));
        }
    }

    public PathValidationResult validate(List<X509Certificate> chain, Collection<TrustAnchor> anchors, Options options) {
        Instant time = options.time();
        String profileName = options.profile().name();
        if (chain == null || chain.isEmpty()) {
            return new PathValidationResult(false, false, null, List.of(),
                    List.of(ValidationIssue.error("x509.empty_chain", "No certificates supplied")), profileName, time);
        }
        Map<String, TrustAnchor> anchorsByThumb = anchors.stream()
                .collect(Collectors.toMap(TrustAnchor::thumbprint, Function.identity(), (a, b) -> a));

        // Strip anchors that the sender included at the tail of the chain.
        List<X509Certificate> path = new ArrayList<>(chain);
        TrustAnchor includedAnchor = null;
        while (path.size() > 1 && anchorsByThumb.containsKey(Certificates.sha256Thumbprint(path.getLast()))) {
            includedAnchor = anchorsByThumb.get(Certificates.sha256Thumbprint(path.removeLast()));
        }

        // Direct trust: the end-entity certificate itself is pinned.
        TrustAnchor pinned = anchorsByThumb.get(Certificates.sha256Thumbprint(path.getFirst()));
        if (pinned != null && path.size() == 1) {
            return finish(List.of(), pinned, path, options, List.of(
                    ValidationIssue.info("x509.pinned", "Certificate is directly pinned as a trust anchor")));
        }

        X509Certificate top = path.getLast();
        List<TrustAnchor> candidates = new ArrayList<>();
        if (includedAnchor != null) {
            candidates.add(includedAnchor);
        }
        for (TrustAnchor a : anchors) {
            if (a != includedAnchor && a.certificate().getSubjectX500Principal().equals(top.getIssuerX500Principal())
                    && signedBy(top, a.certificate())) {
                candidates.add(a);
            }
        }
        List<CertificateSummary> summaries = path.stream().map(CertificateSummary::of).toList();
        if (candidates.isEmpty()) {
            return new PathValidationResult(false, false, null, summaries, List.of(ValidationIssue.error(
                    "x509.no_anchor", "No trust anchor found for issuer " + top.getIssuerX500Principal().getName())),
                    profileName, time);
        }

        List<ValidationIssue> lastIssues = List.of();
        TrustAnchor lastAnchor = candidates.getFirst();
        for (TrustAnchor anchor : candidates) {
            List<ValidationIssue> issues = new ArrayList<>();
            if (!anchor.status().isUsable()) {
                issues.add(ValidationIssue.error("x509.anchor_status", "Trust anchor status is " + anchor.status()));
            }
            if (time.isAfter(anchor.certificate().getNotAfter().toInstant())
                    || time.isBefore(anchor.certificate().getNotBefore().toInstant())) {
                issues.add(ValidationIssue.error("x509.anchor_expired", "Trust anchor certificate is not valid at " + time));
            }
            issues.addAll(pkix(path, anchor.certificate(), options));
            if (issues.stream().noneMatch(ValidationIssue::isError)) {
                return finish(issues, anchor, path, options, List.of());
            }
            lastIssues = issues;
            lastAnchor = anchor;
        }
        return new PathValidationResult(false, true, lastAnchor, summaries, lastIssues, profileName, time);
    }

    private PathValidationResult finish(List<ValidationIssue> pathIssues, TrustAnchor anchor, List<X509Certificate> path,
                                        Options options, List<ValidationIssue> extra) {
        List<ValidationIssue> issues = new ArrayList<>(pathIssues);
        issues.addAll(extra);
        if (!anchor.isUsableAt(options.time()) && issues.stream().noneMatch(i -> i.code().startsWith("x509.anchor"))) {
            issues.add(ValidationIssue.error("x509.anchor_unusable", "Trust anchor is not usable at " + options.time()));
        }
        List<ValidationIssue> profileIssues = options.profile().check(path, anchor.certificate(), options.profileContext());
        if (Boolean.TRUE.equals(anchor.constraints().get("relaxProfile")) && !profileIssues.isEmpty()) {
            // Operator opted this anchor out of strict profile enforcement (e.g. a sandbox issuer): keep findings visible.
            profileIssues = profileIssues.stream()
                    .map(i -> i.isError() ? ValidationIssue.warning(i.code(), i.message() + " (profile relaxed for this anchor)") : i)
                    .toList();
            issues.add(ValidationIssue.warning("x509.profile_relaxed",
                    "Certificate profile '" + options.profile().name() + "' is relaxed for this trust anchor"));
        }
        issues.addAll(profileIssues);
        if (!anchor.docTypes().isEmpty() && options.profileContext().docType() != null
                && !anchor.docTypes().contains(options.profileContext().docType())) {
            issues.add(ValidationIssue.error("x509.anchor_doctype",
                    "Trust anchor is not authorized for doctype " + options.profileContext().docType()));
        }
        List<CertificateRevocation> revocation = List.of();
        boolean pinnedItself = path.size() == 1 && Certificates.sha256Thumbprint(path.getFirst()).equals(anchor.thumbprint());
        if (options.revocation() != null && !pinnedItself) {
            RevocationChecker.Result r = options.revocation().checker().check(path, anchor.certificate(), options.time(),
                    options.revocation().required());
            issues.addAll(r.issues());
            revocation = r.statuses();
        }
        boolean valid = issues.stream().noneMatch(ValidationIssue::isError);
        return new PathValidationResult(valid, true, anchor, path.stream().map(CertificateSummary::of).toList(),
                issues, options.profile().name(), options.time(), revocation);
    }

    private static List<ValidationIssue> pkix(List<X509Certificate> path, X509Certificate anchorCert, Options options) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(path);
            PKIXParameters params = new PKIXParameters(Set.of(new java.security.cert.TrustAnchor(anchorCert, null)));
            params.setDate(Date.from(options.time()));
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            // Revocation is checked by RevocationChecker afterwards (CRLs from the trust list / distribution points).
            params.setRevocationEnabled(false);
            validator.validate(certPath, params);
            return List.of();
        } catch (CertPathValidatorException e) {
            String reason = e.getReason() == null ? "UNSPECIFIED" : e.getReason().toString();
            return List.of(ValidationIssue.error("x509.path." + reason.toLowerCase(),
                    "Path validation failed" + (e.getIndex() >= 0 ? " at certificate " + e.getIndex() : "")
                            + ": " + e.getMessage()));
        } catch (CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            return List.of(ValidationIssue.error("x509.path.error", "Path validation error: " + e.getMessage()));
        }
    }

    private static boolean signedBy(X509Certificate cert, X509Certificate issuer) {
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Distinct anchors by thumbprint, preserving order. */
    public static List<TrustAnchor> distinct(Collection<TrustAnchor> anchors) {
        Set<String> seen = new HashSet<>();
        return anchors.stream().filter(a -> seen.add(a.thumbprint())).toList();
    }
}
