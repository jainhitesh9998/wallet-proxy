package io.vctrust.trust.core.x509;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * What an operator requires of a certificate chain on top of RFC 5280 and the built-in profile of the question: the
 * {@code x509.profile} of a trust mechanism. Each member is one check, reported with a code of its own when it fails.
 *
 * <p>Only what this parser and the client library's ({@code x509/certificate.ts}) read alike is a member, because the
 * device applies the same requirements to the same chain and must reach the same decision: the basic constraints'
 * CA flag, the first seven key usage bits, the extended key usages as dotted OIDs, the subject's first text country,
 * the two validity dates, the URIs of the CRL distribution points, and the length of the path.
 *
 * @param leafNotCa            the signing certificate is not a CA ({@code profile.leaf_is_ca})
 * @param keyUsage             the key usage extension is present and asserts each of these bits ({@code profile.key_usage})
 * @param extendedKeyUsage     each of these OIDs is among the extended key usages ({@code profile.extended_key_usage})
 * @param sameCountryAsAnchor  the leaf and the anchor both name a country, and the same one ({@code profile.country})
 * @param maxValidityDays      the leaf's notAfter is at most this many days after its notBefore ({@code profile.validity}); null: no limit
 * @param crlDistributionPoint the leaf names an http(s) CRL distribution point ({@code profile.crl_distribution_point})
 * @param maxIntermediates     at most this many CA certificates between the leaf and the anchor ({@code profile.path_length}); null: no limit
 */
public record CertificateRequirements(boolean leafNotCa, List<String> keyUsage, List<String> extendedKeyUsage,
                                      boolean sameCountryAsAnchor, Integer maxValidityDays, boolean crlDistributionPoint,
                                      Integer maxIntermediates) {

    /** The key usage bits by their RFC 5280 names, in bit order: the ones the client library's parser reads. */
    public static final List<String> KEY_USAGE_BITS = List.of("digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign");

    private static final long DAY_MILLIS = 86_400_000L;
    /** ASCII only, as the client library reads it: a CRL location is an IA5String. */
    private static final Pattern HTTP_URL = Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);

    public CertificateRequirements {
        keyUsage = keyUsage == null ? List.of() : List.copyOf(keyUsage);
        extendedKeyUsage = extendedKeyUsage == null ? List.of() : List.copyOf(extendedKeyUsage);
    }

    /**
     * @param path   the validated path, leaf first, without the anchor
     * @param anchor the trust anchor's certificate
     */
    public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor) {
        List<ValidationIssue> issues = new ArrayList<>();
        X509Certificate leaf = path.getFirst();
        if (leafNotCa && Certificates.isCa(leaf)) {
            issues.add(ValidationIssue.error("profile.leaf_is_ca", "The signing certificate is a CA certificate"));
        }
        if (!keyUsage.isEmpty()) {
            boolean[] bits = leaf.getKeyUsage();
            List<String> missing = keyUsage.stream().filter(name -> bits == null || !bits[KEY_USAGE_BITS.indexOf(name)]).toList();
            if (!missing.isEmpty()) {
                issues.add(ValidationIssue.error("profile.key_usage", bits == null
                        ? "The signing certificate has no key usage extension; required: " + String.join(", ", keyUsage)
                        : "The signing certificate's key usage does not assert " + String.join(", ", missing)));
            }
        }
        if (!extendedKeyUsage.isEmpty()) {
            List<String> have = Certificates.extendedKeyUsage(leaf);
            List<String> missing = extendedKeyUsage.stream().filter(oid -> !have.contains(oid)).toList();
            if (!missing.isEmpty()) {
                issues.add(ValidationIssue.error("profile.extended_key_usage",
                        "The signing certificate lacks extended key usage " + String.join(", ", missing)));
            }
        }
        if (sameCountryAsAnchor) {
            Optional<String> leafCountry = Certificates.subjectCountry(leaf);
            Optional<String> anchorCountry = Certificates.subjectCountry(anchor);
            // Compared exactly: a case-insensitive comparison is not the same thing on every platform.
            if (leafCountry.isEmpty() || anchorCountry.isEmpty() || !leafCountry.get().equals(anchorCountry.get())) {
                issues.add(ValidationIssue.error("profile.country", "The signing certificate's country ("
                        + leafCountry.orElse("none") + ") is not the trust anchor's (" + anchorCountry.orElse("none") + ")"));
            }
        }
        if (maxValidityDays != null) {
            long millis = leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime();
            if (millis > maxValidityDays * DAY_MILLIS) {
                issues.add(ValidationIssue.error("profile.validity", "The signing certificate is valid for more than "
                        + maxValidityDays + " days"));
            }
        }
        if (crlDistributionPoint && Certificates.crlDistributionPoints(leaf).stream().noneMatch(u -> HTTP_URL.matcher(u).find())) {
            issues.add(ValidationIssue.error("profile.crl_distribution_point",
                    "The signing certificate names no http(s) CRL distribution point"));
        }
        if (maxIntermediates != null && path.size() - 1 > maxIntermediates) {
            issues.add(ValidationIssue.error("profile.path_length", "The chain has " + (path.size() - 1)
                    + " CA certificates between the signing certificate and the trust anchor; at most " + maxIntermediates + " are allowed"));
        }
        return issues;
    }
}
