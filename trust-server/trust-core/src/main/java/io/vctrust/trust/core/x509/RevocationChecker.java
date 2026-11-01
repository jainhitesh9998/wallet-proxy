package io.vctrust.trust.core.x509;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Revocation checking for a validated certificate path (RFC 5280 §6.3): every certificate below the trust anchor
 * is looked up in a CRL issued by its issuer — CRLs held for that issuer (trust anchor CRLs) first, then the CRLs
 * at the certificate's own distribution points. OCSP is used only when an {@link OcspSource} is configured
 * (server side; devices never send OCSP requests, which would name the certificate being checked).
 *
 * <p>Devices apply the same rules to the CRLs in the trust snapshot, so the service and the device agree.
 */
public final class RevocationChecker {

    /** Tolerated clock skew for a CRL's thisUpdate. */
    public static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    static final String DELTA_CRL_INDICATOR = "2.5.29.27";
    static final String CERTIFICATE_ISSUER = "2.5.29.29";
    static final Set<String> KNOWN_CRITICAL = Set.of("2.5.29.20", "2.5.29.35", "2.5.29.28", "2.5.29.46");

    /** A parsed CRL and where it came from ({@code url} is null for a CRL pushed with the trust list). */
    public static final class Crl {
        private static final Pattern PEM = Pattern.compile("-----BEGIN X509 CRL-----([A-Za-z0-9+/=\\s]+?)-----END X509 CRL-----");

        private final X509CRL crl;
        private final byte[] der;
        private final String url;
        private final Instant fetchedAt;
        private final boolean indirectEntries;

        private Crl(X509CRL crl, byte[] der, String url, Instant fetchedAt) {
            this.crl = crl;
            this.der = der;
            this.url = url;
            this.fetchedAt = fetchedAt;
            boolean indirect = false;
            if (crl.getRevokedCertificates() != null) {
                for (X509CRLEntry e : crl.getRevokedCertificates()) {
                    Set<String> crit = e.getCriticalExtensionOIDs();
                    if (crit != null && crit.contains(CERTIFICATE_ISSUER)) {
                        indirect = true;
                        break;
                    }
                }
            }
            this.indirectEntries = indirect;
        }

        /** Parses a DER, PEM or base64 CRL. */
        public static Crl parse(byte[] data, String url, Instant fetchedAt) {
            byte[] der = data;
            if (data.length > 0 && data[0] != 0x30) {
                String text = new String(data, StandardCharsets.US_ASCII);
                Matcher m = PEM.matcher(text);
                der = Base64.getMimeDecoder().decode(m.find() ? m.group(1) : text.strip());
            }
            try {
                X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
                return new Crl(crl, der, url, fetchedAt);
            } catch (CRLException | CertificateException | ClassCastException e) {
                throw new IllegalArgumentException("Not an X.509 CRL: " + e.getMessage(), e);
            }
        }

        public X509CRL crl() {
            return crl;
        }

        public byte[] der() {
            return der.clone();
        }

        public int size() {
            return der.length;
        }

        public String url() {
            return url;
        }

        public Instant fetchedAt() {
            return fetchedAt;
        }

        public Instant thisUpdate() {
            return crl.getThisUpdate().toInstant();
        }

        public Instant nextUpdate() {
            return crl.getNextUpdate() == null ? null : crl.getNextUpdate().toInstant();
        }

        public Optional<BigInteger> crlNumber() {
            byte[] ext = crl.getExtensionValue("2.5.29.20");
            if (ext == null) {
                return Optional.empty();
            }
            try {
                return Optional.of(org.bouncycastle.asn1.ASN1Integer.getInstance(
                        ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets())).getValue());
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        public int revokedCount() {
            return crl.getRevokedCertificates() == null ? 0 : crl.getRevokedCertificates().size();
        }

        /** Signature and issuer name check against the certificate expected to have issued this CRL. */
        public boolean issuedBy(X509Certificate issuer) {
            if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            try {
                crl.verify(issuer.getPublicKey());
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    /** Where CRLs come from. */
    public interface CrlSource {
        /** CRLs held for certificates issued by {@code issuer} (e.g. the CRLs of a trust anchor). */
        List<Crl> heldFor(X509Certificate issuer);

        /** The CRL published at a distribution point; throws when it cannot be obtained. */
        Crl fetch(String url) throws IOException;
    }

    /** Server-side OCSP (RFC 6960). */
    public interface OcspSource {
        OcspResult check(X509Certificate cert, X509Certificate issuer, String url, Instant time);
    }

    /** An OCSP answer; {@code reason} is the revocation reason, or why the status is unknown. */
    public record OcspResult(CertificateRevocation.Status status, String reason, Instant revokedAt,
                             Instant thisUpdate, Instant nextUpdate) {
    }

    /** Issues to add to the path validation result, and the per-certificate statuses. */
    public record Result(List<ValidationIssue> issues, List<CertificateRevocation> statuses) {
    }

    private final CrlSource crls;
    private final OcspSource ocsp;
    private final String source;

    /**
     * @param ocsp   null disables OCSP
     * @param source reported as {@link CertificateRevocation#source()}
     */
    public RevocationChecker(CrlSource crls, OcspSource ocsp, String source) {
        this.crls = crls;
        this.ocsp = ocsp;
        this.source = source;
    }

    /**
     * @param path     the validated path, leaf first, without the anchor
     * @param required when true an undeterminable status is an error, otherwise a warning
     */
    public Result check(List<X509Certificate> path, X509Certificate anchor, Instant time, boolean required) {
        List<ValidationIssue> issues = new ArrayList<>();
        List<CertificateRevocation> statuses = new ArrayList<>();
        for (int j = 0; j < path.size(); j++) {
            X509Certificate c = path.get(j);
            X509Certificate issuer = j + 1 < path.size() ? path.get(j + 1) : anchor;
            CertificateRevocation r = checkOne(j, c, issuer, time);
            statuses.add(r);
            String who = "Certificate " + j + " (" + c.getSubjectX500Principal().getName() + ")";
            switch (r.status()) {
                case GOOD -> issues.add(ValidationIssue.info("x509.not_revoked", who + " is not revoked ("
                        + ("ocsp".equals(r.method()) ? "OCSP " + r.crlUrl() : "CRL " + (r.crlUrl() == null ? "from the trust list" : r.crlUrl()))
                        + ", next update " + (r.nextUpdate() == null ? "none" : r.nextUpdate()) + ")"));
                case REVOKED -> issues.add(ValidationIssue.error("x509.revoked", who + " was revoked on " + r.revokedAt()
                        + " (" + r.reason() + ")"));
                case ON_HOLD -> issues.add(ValidationIssue.error("x509.on_hold", who + " is on hold (suspended) since " + r.revokedAt()));
                case UNKNOWN -> {
                    String msg = "Revocation status of certificate " + j + " (" + c.getSubjectX500Principal().getName()
                            + ") is unknown: " + r.reason();
                    issues.add(required ? ValidationIssue.error("x509.revocation_unknown", msg)
                            : ValidationIssue.warning("x509.revocation_unknown", msg));
                }
            }
        }
        return new Result(issues, statuses);
    }

    private CertificateRevocation checkOne(int index, X509Certificate c, X509Certificate issuer, Instant time) {
        String why = null;
        Set<String> tried = new HashSet<>();
        for (Crl crl : crls.heldFor(issuer)) {
            if (crl.url() != null) {
                tried.add(crl.url());
            }
            Verdict v = evaluate(index, crl, c, issuer, time);
            if (v.decided() != null) {
                return v.decided();
            }
            why = why == null ? v.why() : why;
        }
        for (String url : Certificates.crlDistributionPoints(c)) {
            if (!isHttp(url) || !tried.add(url)) {
                continue;
            }
            Crl crl;
            try {
                crl = crls.fetch(url);
            } catch (Exception e) {
                why = why == null ? "CRL unavailable: " + e.getMessage() : why;
                continue;
            }
            Verdict v = evaluate(index, crl, c, issuer, time);
            if (v.decided() != null) {
                return v.decided();
            }
            why = why == null ? v.why() : why;
        }
        List<String> ocspUrls = Certificates.ocspUrls(c).stream().filter(RevocationChecker::isHttp).toList();
        if (!ocspUrls.isEmpty()) {
            if (ocsp != null) {
                OcspResult r = ocsp.check(c, issuer, ocspUrls.getFirst(), time);
                if (r.status() != CertificateRevocation.Status.UNKNOWN) {
                    return status(index, c, r.status(), r.reason(), r.revokedAt(), "ocsp", ocspUrls.getFirst(),
                            r.thisUpdate(), r.nextUpdate());
                }
                why = why == null ? "OCSP: " + r.reason() : why;
            } else if (why == null) {
                why = "the issuer publishes only OCSP, which is disabled";
            }
        }
        return status(index, c, CertificateRevocation.Status.UNKNOWN, why == null ? "no CRL is published for it" : why,
                null, null, null, null, null);
    }

    private record Verdict(CertificateRevocation decided, String why) {
        static Verdict skip(String why) {
            return new Verdict(null, why);
        }
    }

    private Verdict evaluate(int index, Crl held, X509Certificate c, X509Certificate issuer, Instant time) {
        X509CRL crl = held.crl();
        if (!crl.getIssuerX500Principal().equals(c.getIssuerX500Principal())) {
            return Verdict.skip("the CRL issuer does not match the certificate issuer");
        }
        boolean[] ku = issuer.getKeyUsage();
        if (ku != null && (ku.length < 7 || !ku[6])) {
            return Verdict.skip("the issuer certificate may not sign CRLs");
        }
        try {
            crl.verify(issuer.getPublicKey());
        } catch (Exception e) {
            return Verdict.skip("CRL signature does not verify");
        }
        if (held.thisUpdate().isAfter(time.plus(CLOCK_SKEW))) {
            return Verdict.skip("CRL is not yet valid (thisUpdate " + held.thisUpdate() + ")");
        }
        if (held.nextUpdate() != null && held.nextUpdate().isBefore(time)) {
            return Verdict.skip("CRL expired at " + held.nextUpdate());
        }
        Set<String> critical = crl.getCriticalExtensionOIDs() == null ? Set.of() : crl.getCriticalExtensionOIDs();
        Set<String> nonCritical = crl.getNonCriticalExtensionOIDs() == null ? Set.of() : crl.getNonCriticalExtensionOIDs();
        if (critical.contains(DELTA_CRL_INDICATOR) || nonCritical.contains(DELTA_CRL_INDICATOR)) {
            return Verdict.skip("delta CRLs are not supported");
        }
        for (String oid : critical) {
            if (!KNOWN_CRITICAL.contains(oid)) {
                return Verdict.skip("the CRL has an unsupported critical extension " + oid);
            }
        }
        String scope = scope(crl, c);
        if (scope != null) {
            return Verdict.skip(scope);
        }
        if (held.indirectEntries) {
            return Verdict.skip("indirect CRL entries are not supported");
        }
        X509CRLEntry entry = crl.getRevokedCertificate(c.getSerialNumber());
        CRLReason reason = entry == null ? null : entry.getRevocationReason();
        if (entry == null || reason == CRLReason.REMOVE_FROM_CRL) {
            return new Verdict(status(index, c, CertificateRevocation.Status.GOOD, null, null, "crl", held.url(),
                    held.thisUpdate(), held.nextUpdate()), null);
        }
        CertificateRevocation.Status s = reason == CRLReason.CERTIFICATE_HOLD
                ? CertificateRevocation.Status.ON_HOLD : CertificateRevocation.Status.REVOKED;
        return new Verdict(status(index, c, s, reasonName(reason), entry.getRevocationDate().toInstant(), "crl",
                held.url(), held.thisUpdate(), held.nextUpdate()), null);
    }

    /** Null when the CRL's Issuing Distribution Point scope covers {@code c}; otherwise why not. */
    private static String scope(X509CRL crl, X509Certificate c) {
        byte[] ext = crl.getExtensionValue("2.5.29.28");
        if (ext == null) {
            return null;
        }
        IssuingDistributionPoint idp;
        try {
            idp = IssuingDistributionPoint.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets()));
        } catch (Exception e) {
            return "the CRL's issuing distribution point is malformed";
        }
        if (idp.isIndirectCRL()) {
            return "indirect CRLs are not supported";
        }
        if (idp.getOnlySomeReasons() != null) {
            return "the CRL is partitioned by reason";
        }
        if (idp.onlyContainsAttributeCerts()) {
            return "the CRL covers only attribute certificates";
        }
        boolean ca = Certificates.isCa(c);
        if (idp.onlyContainsUserCerts() && ca) {
            return "the CRL covers only end-entity certificates";
        }
        if (idp.onlyContainsCACerts() && !ca) {
            return "the CRL covers only CA certificates";
        }
        List<String> names = Certificates.fullNameUris(idp.getDistributionPoint());
        if (!names.isEmpty() && Certificates.crlDistributionPoints(c).stream().noneMatch(names::contains)) {
            return "the CRL's distribution point does not match the certificate";
        }
        return null;
    }

    private CertificateRevocation status(int index, X509Certificate c, CertificateRevocation.Status s, String reason,
                                         Instant revokedAt, String method, String url, Instant thisUpdate, Instant nextUpdate) {
        return new CertificateRevocation(index, c.getSerialNumber().toString(16), c.getSubjectX500Principal().getName(), s,
                reason, revokedAt, method, url, source, thisUpdate, nextUpdate);
    }

    private static boolean isHttp(String url) {
        String u = url.toLowerCase(Locale.ROOT);
        return u.startsWith("https://") || u.startsWith("http://");
    }

    /** RFC 5280 CRLReason names. */
    public static String reasonName(CRLReason r) {
        if (r == null) {
            return "unspecified";
        }
        return switch (r) {
            case KEY_COMPROMISE -> "keyCompromise";
            case CA_COMPROMISE -> "cACompromise";
            case AFFILIATION_CHANGED -> "affiliationChanged";
            case SUPERSEDED -> "superseded";
            case CESSATION_OF_OPERATION -> "cessationOfOperation";
            case CERTIFICATE_HOLD -> "certificateHold";
            case REMOVE_FROM_CRL -> "removeFromCRL";
            case PRIVILEGE_WITHDRAWN -> "privilegeWithdrawn";
            case AA_COMPROMISE -> "aACompromise";
            default -> "unspecified";
        };
    }

    /** RFC 5280 CRLReason code → name (for OCSP revocation reasons). */
    public static String reasonName(int code) {
        CRLReason[] all = CRLReason.values();
        return code >= 0 && code < all.length ? reasonName(all[code]) : "unspecified";
    }
}
