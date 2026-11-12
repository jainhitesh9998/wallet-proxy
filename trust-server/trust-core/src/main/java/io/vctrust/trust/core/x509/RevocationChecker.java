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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Revocation checking for a validated certificate path (RFC 5280 §6.3): every certificate below the trust anchor
 * is looked up in the CRLs issued by its issuer — CRLs held for that issuer (trust anchor CRLs) first, then, when
 * none of those can be used, the CRLs at the certificate's own distribution points. When several CRLs can be used,
 * a revocation in any of them stands and otherwise the newest decides. OCSP is never used: a request names the
 * certificate being checked, and the profiles this service serves (ISO 18013-5, HAIP) publish CRLs.
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
        /**
         * The source of a service with revocation checking switched off: it knows no CRL and fetches none. Chains are
         * still checked against it rather than not at all: every certificate below the anchor has the status UNKNOWN,
         * for this reason, so a client profile or a mechanism that requires a known status refuses the chain, as a
         * device does that can get no CRL.
         */
        CrlSource SWITCHED_OFF = new CrlSource() {
            @Override
            public List<Crl> heldFor(X509Certificate issuer) {
                return List.of();
            }

            @Override
            public Crl fetch(String url) throws IOException {
                throw new IOException(unavailable());
            }

            @Override
            public String unavailable() {
                return "revocation checking is switched off on this service";
            }
        };

        /** CRLs held for certificates issued by {@code issuer} (e.g. the CRLs of a trust anchor), in every framework. */
        List<Crl> heldFor(X509Certificate issuer);

        /**
         * CRLs held for certificates issued by {@code issuer} in the frameworks {@code frameworks} accepts: where a CA
         * publishes is configured per framework, and a client is decided for by the CRLs of the frameworks it sees,
         * as its snapshot carries them. A source that does not hold CRLs per framework holds the same for all.
         */
        default List<Crl> heldFor(X509Certificate issuer, Predicate<String> frameworks) {
            return heldFor(issuer);
        }

        /** The CRL published at a distribution point; throws when it cannot be obtained. */
        Crl fetch(String url) throws IOException;

        /** Null when this source can be asked; otherwise why no certificate's status can be had from it. */
        default String unavailable() {
            return null;
        }
    }

    /** Issues to add to the path validation result, and the per-certificate statuses. */
    public record Result(List<ValidationIssue> issues, List<CertificateRevocation> statuses) {
    }

    private final CrlSource crls;
    private final String source;
    /** The frameworks whose CRLs count; null: those of every framework. */
    private final Predicate<String> frameworks;

    /**
     * @param crls   where CRLs come from; {@link CrlSource#SWITCHED_OFF} when revocation checking is switched off
     * @param source reported as {@link CertificateRevocation#source()}
     */
    public RevocationChecker(CrlSource crls, String source) {
        this(crls, source, null);
    }

    private RevocationChecker(CrlSource crls, String source, Predicate<String> frameworks) {
        this.crls = Objects.requireNonNull(crls, "crls: CrlSource.SWITCHED_OFF when revocation checking is switched off");
        this.source = source;
        this.frameworks = frameworks;
    }

    /**
     * The same checker for one client: of the CRLs held for an issuer, only those of the frameworks
     * {@code frameworks} accepts count ({@link CrlSource#heldFor(X509Certificate, Predicate)}), which are the CRLs
     * that client's snapshot carries. CRLs fetched from a certificate's own distribution points count as before.
     */
    public RevocationChecker forFrameworks(Predicate<String> frameworks) {
        return new RevocationChecker(crls, source, Objects.requireNonNull(frameworks, "frameworks"));
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
                        + "CRL " + (r.crlUrl() == null ? "from the trust list" : r.crlUrl())
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
        String unavailable = crls.unavailable();
        if (unavailable != null) {
            return status(index, c, CertificateRevocation.Status.UNKNOWN, unavailable, null, null, null, null, null);
        }
        String why = null;
        Set<String> tried = new HashSet<>();
        // What each usable CRL says. The CRLs held come first; the certificate's own distribution points are fetched
        // only when none of those can be used, as on the device.
        List<Verdict> said = new ArrayList<>();
        for (Crl crl : frameworks == null ? crls.heldFor(issuer) : crls.heldFor(issuer, frameworks)) {
            if (crl.url() != null) {
                tried.add(crl.url());
            }
            Verdict v = evaluate(index, crl, c, issuer, time);
            if (v.decided() != null) {
                said.add(v);
            } else {
                why = why == null ? v.why() : why;
            }
        }
        for (String url : said.isEmpty() ? Certificates.crlDistributionPoints(c) : List.<String>of()) {
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
                said.add(v);
            } else {
                why = why == null ? v.why() : why;
            }
        }
        // A revocation in any usable CRL stands: a stale CRL from before it, served again or named by someone else,
        // does not take it back. A hold can be lifted, so like a "not revoked" it holds only when the newest CRL says
        // it. The same rule as the device's (checkRevocation in trust-client).
        Verdict revoked = newest(said.stream().filter(v -> v.decided().status() == CertificateRevocation.Status.REVOKED).toList());
        Verdict decisive = revoked != null ? revoked : newest(said);
        if (decisive != null) {
            return decisive.decided();
        }
        if (why == null && Certificates.ocspUrls(c).stream().anyMatch(RevocationChecker::isHttp)) {
            why = "the issuer publishes only OCSP, which is not used";
        }
        return status(index, c, CertificateRevocation.Status.UNKNOWN, why == null ? "no CRL is published for it" : why,
                null, null, null, null, null);
    }

    /** What one CRL says about a certificate ({@code decided}), or why it says nothing ({@code why}). */
    private record Verdict(CertificateRevocation decided, String why, Crl crl) {
        static Verdict skip(String why) {
            return new Verdict(null, why, null);
        }
    }

    /** The verdict of the most recently issued CRL: by thisUpdate, then CRL number; on a tie, the first. */
    private static Verdict newest(List<Verdict> verdicts) {
        Verdict best = null;
        for (Verdict v : verdicts) {
            if (best == null || newer(v.crl(), best.crl())) {
                best = v;
            }
        }
        return best;
    }

    private static boolean newer(Crl a, Crl b) {
        int t = a.thisUpdate().compareTo(b.thisUpdate());
        return t > 0 || (t == 0 && a.crlNumber().isPresent() && b.crlNumber().isPresent()
                && a.crlNumber().get().compareTo(b.crlNumber().get()) > 0);
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
                    held.thisUpdate(), held.nextUpdate()), null, held);
        }
        CertificateRevocation.Status s = reason == CRLReason.CERTIFICATE_HOLD
                ? CertificateRevocation.Status.ON_HOLD : CertificateRevocation.Status.REVOKED;
        return new Verdict(status(index, c, s, reasonName(reason), entry.getRevocationDate().toInstant(), "crl",
                held.url(), held.thisUpdate(), held.nextUpdate()), null, held);
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

}
