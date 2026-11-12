package io.vctrust.trust.core.x509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertList;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Revocation checking for a validated certificate path (RFC 5280 §6.3): every certificate below the trust anchor
 * is looked up in the CRLs issued by its issuer — CRLs held for that issuer (trust anchor CRLs) first, then, when
 * those leave its status unknown, the CRLs at the certificate's own distribution points as well. OCSP is never used: a
 * request names the certificate being checked, and the profiles this service serves (ISO 18013-5, HAIP) publish CRLs.
 *
 * <p>A CRL is read as the device reads it ({@code checkRevocation} in trust-client's {@code x509/revocation.ts}, the
 * reference; {@code conformance/revocation/crl-cases.json} holds both sides to it), so that a verifier backend that
 * asks the service gets no laxer answer than a device:
 * <ul>
 *   <li>A certificate is good only when a complete, current CRL whose scope can be evaluated does not list it. A delta
 *   CRL can show a revocation or a hold, never that a certificate is not revoked; a CRL that lists a serial number more
 *   than once proves nothing about the certificates it does not list; a serial listed more than once counts with its
 *   gravest entry (a revocation over a hold, either over removeFromCRL).</li>
 *   <li>removeFromCRL lifts a hold in a delta CRL read together with its base. Deltas are not combined here, and a
 *   complete CRL should not use it at all: an entry with that reason proves nothing.</li>
 *   <li>A CRL is not used when it is not current (issued beyond the clock skew, past its next update, or, stating no
 *   next update, issued more than {@link #MAX_AGE_WITHOUT_NEXT_UPDATE} ago), carries a critical extension this code
 *   does not know (on the CRL or on any entry), is indirect (also when only an entry names another certificate issuer),
 *   or is partitioned by reason. A CRL scoped to a distribution point covers a certificate only when the certificate
 *   names that point by URI, in a point that covers every reason and names no other CRL issuer.</li>
 *   <li>Of the CRLs that can be used, a revocation (other than a hold, which can be lifted) in any of them stands, and
 *   otherwise the most recent decides: by thisUpdate, then CRL number; on a tie, the first held.</li>
 * </ul>
 * Part of this is hidden by the JDK's {@link X509CRL} (it keeps the last of a serial's entries, and says nothing of an
 * entry's non-critical extensions), so the entries are read from the encoded CRL.
 */
public final class RevocationChecker {

    /** Tolerated clock skew for a CRL's thisUpdate. */
    public static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    /**
     * How long a CRL that states no nextUpdate is used after its thisUpdate. RFC 5280 requires nextUpdate; without it
     * nothing says when the CRL was superseded, so it must not stand in for the current one indefinitely.
     */
    public static final Duration MAX_AGE_WITHOUT_NEXT_UPDATE = Duration.ofDays(7);
    static final String DELTA_CRL_INDICATOR = "2.5.29.27";
    static final String CERTIFICATE_ISSUER = "2.5.29.29";
    static final String REASON_CODE = "2.5.29.21";
    /** CRL extensions this code knows: crlNumber, authorityKeyIdentifier, issuingDistributionPoint, freshestCRL, deltaCRLIndicator. */
    static final Set<String> KNOWN_CRITICAL = Set.of("2.5.29.20", "2.5.29.35", "2.5.29.28", "2.5.29.46", DELTA_CRL_INDICATOR);
    /** CRL entry extensions this code knows: reasonCode, invalidityDate, certificateIssuer. */
    static final Set<String> KNOWN_ENTRY_EXTENSIONS = Set.of(REASON_CODE, "2.5.29.24", CERTIFICATE_ISSUER);
    static final int CERTIFICATE_HOLD = 6;
    static final int REMOVE_FROM_CRL = 8;
    private static final String DELTA = "delta CRLs are not supported";

    /** A parsed CRL and where it came from ({@code url} is null for a CRL pushed with the trust list). */
    public static final class Crl {
        private static final Pattern PEM = Pattern.compile("-----BEGIN X509 CRL-----([A-Za-z0-9+/=\\s]+?)-----END X509 CRL-----");

        private final X509CRL crl;
        private final byte[] der;
        private final String url;
        private final Instant fetchedAt;
        /** By serial number, the gravest entry of each serial listed. */
        private final Map<BigInteger, Entry> entries;
        private final boolean duplicateSerials;
        private final boolean certificateIssuerEntries;
        private final boolean delta;
        /** Critical CRL extensions and critical entry extensions this code does not know. */
        private final List<String> unsupportedCritical;

        /** An entry of the CRL: when the certificate was revoked, and the CRLReason code (null: none, read as unspecified). */
        record Entry(Instant revokedAt, Integer reason) {
            /** removeFromCRL < certificateHold < any revocation. */
            int gravity() {
                return reason != null && reason == REMOVE_FROM_CRL ? 0 : reason != null && reason == CERTIFICATE_HOLD ? 1 : 2;
            }
        }

        private Crl(X509CRL crl, byte[] der, String url, Instant fetchedAt) {
            this.crl = crl;
            this.der = der;
            this.url = url;
            this.fetchedAt = fetchedAt;
            TBSCertList tbs = CertificateList.getInstance(der).getTBSCertList();
            Map<BigInteger, Entry> bySerial = new HashMap<>();
            List<String> unsupported = new ArrayList<>();
            boolean duplicates = false;
            boolean otherIssuer = false;
            for (TBSCertList.CRLEntry e : tbs.getRevokedCertificates()) {
                Extensions ext = e.getExtensions();
                Integer reason = null;
                if (ext != null) {
                    Extension rc = ext.getExtension(Extension.reasonCode);
                    if (rc != null) {
                        reason = org.bouncycastle.asn1.x509.CRLReason.getInstance(rc.getParsedValue()).getValue().intValue();
                    }
                    otherIssuer |= ext.getExtension(Extension.certificateIssuer) != null;
                    for (ASN1ObjectIdentifier oid : ext.getCriticalExtensionOIDs()) {
                        if (!KNOWN_ENTRY_EXTENSIONS.contains(oid.getId()) && !unsupported.contains(oid.getId())) {
                            unsupported.add(oid.getId());
                        }
                    }
                }
                Entry entry = new Entry(e.getRevocationDate().getDate().toInstant(), reason);
                Entry listed = bySerial.get(e.getUserCertificate().getValue());
                duplicates |= listed != null;
                if (listed == null || entry.gravity() > listed.gravity()) {
                    bySerial.put(e.getUserCertificate().getValue(), entry);
                }
            }
            Extensions ext = tbs.getExtensions();
            if (ext != null) {
                for (ASN1ObjectIdentifier oid : ext.getCriticalExtensionOIDs()) {
                    if (!KNOWN_CRITICAL.contains(oid.getId()) && !unsupported.contains(oid.getId())) {
                        unsupported.add(oid.getId());
                    }
                }
            }
            this.entries = Map.copyOf(bySerial);
            this.duplicateSerials = duplicates;
            this.certificateIssuerEntries = otherIssuer;
            this.delta = ext != null && ext.getExtension(Extension.deltaCRLIndicator) != null;
            this.unsupportedCritical = List.copyOf(unsupported);
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
            } catch (RuntimeException e) {
                // What the JDK read but the entries do not (a malformed reason code, say): not a CRL to rely on.
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

        /** The entry of {@code serial}, the gravest when it is listed more than once; null when it is not listed. */
        Entry entry(BigInteger serial) {
            return entries.get(serial);
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
        Reading reading = new Reading(c, issuer, time);
        Set<String> tried = new HashSet<>();
        for (Crl crl : frameworks == null ? crls.heldFor(issuer) : crls.heldFor(issuer, frameworks)) {
            if (crl.url() != null) {
                tried.add(crl.url());
            }
            reading.add(crl);
        }
        CertificateRevocation decided = reading.decide(index);
        if (decided.status() != CertificateRevocation.Status.UNKNOWN) {
            return decided;
        }
        // As on the device (validateChainOnDevice): for a certificate the CRLs held leave unknown, the CRLs at its own
        // distribution points, read together with those held.
        boolean more = false;
        for (String url : Certificates.crlDistributionPoints(c)) {
            if (!isHttp(url) || !tried.add(url)) {
                continue;
            }
            more = true;
            try {
                reading.add(crls.fetch(url));
            } catch (Exception e) {
                reading.because("CRL unavailable: " + e.getMessage());
            }
        }
        return more ? reading.decide(index) : decided;
    }

    /** What one usable CRL says about the certificate: its entry, or null when the (complete) CRL does not list it. */
    private record Statement(Crl crl, Crl.Entry entry) {
    }

    /** The CRLs read for one certificate, in the order they were held, and why the first that could not be used was not. */
    private final class Reading {
        private final X509Certificate cert;
        private final X509Certificate issuer;
        private final Instant time;
        private final List<Statement> statements = new ArrayList<>();
        private String why;

        Reading(X509Certificate cert, X509Certificate issuer, Instant time) {
            this.cert = cert;
            this.issuer = issuer;
            this.time = time;
        }

        void because(String reason) {
            why = why == null ? reason : why;
        }

        void add(Crl held) {
            if (!held.crl().getIssuerX500Principal().equals(cert.getIssuerX500Principal())) {
                because("the CRL issuer does not match the certificate issuer");
                return;
            }
            String problem = unusable(held, cert, issuer, time);
            if (problem != null) {
                because(problem);
                return;
            }
            Crl.Entry entry = held.entry(cert.getSerialNumber());
            // A delta CRL is not a complete list: it can show that a certificate was revoked, never that it was not.
            if (held.delta && entry == null) {
                because(DELTA);
                return;
            }
            // Nor is a list that names a certificate twice a sound one: its entries stand, its silence is not relied on.
            if (held.duplicateSerials && entry == null) {
                because("the CRL lists a serial number more than once");
                return;
            }
            statements.add(new Statement(held, entry));
        }

        CertificateRevocation decide(int index) {
            // A revocation (other than a hold, which can be lifted) in any usable CRL stands: a stale CRL from before it,
            // served again or named by someone else, does not take it back. Otherwise the newest decides.
            Statement decisive = newest(statements.stream().filter(s -> s.entry() != null && s.entry().gravity() == 2).toList());
            if (decisive == null) {
                decisive = newest(statements);
            }
            String reason = why;
            if (decisive != null) {
                Crl held = decisive.crl();
                Crl.Entry e = decisive.entry();
                if (e == null) {
                    return status(index, cert, CertificateRevocation.Status.GOOD, null, null, "crl", held.url(), held.thisUpdate(), held.nextUpdate());
                }
                if (e.reason() != null && e.reason() == CERTIFICATE_HOLD) {
                    return status(index, cert, CertificateRevocation.Status.ON_HOLD, reasonName(CERTIFICATE_HOLD), e.revokedAt(), "crl", held.url(),
                            held.thisUpdate(), held.nextUpdate());
                }
                if (e.reason() == null || e.reason() != REMOVE_FROM_CRL) {
                    return status(index, cert, CertificateRevocation.Status.REVOKED, reasonName(e.reason() == null ? 0 : e.reason()), e.revokedAt(), "crl",
                            held.url(), held.thisUpdate(), held.nextUpdate());
                }
                // removeFromCRL lifts a hold in a delta CRL, read together with its base. Alone it proves nothing: not in
                // a delta (deltas are not combined here), and in a complete CRL it should not appear at all.
                reason = held.delta ? DELTA : "the CRL lists the certificate with reason removeFromCRL, which only a delta CRL may use";
            }
            if (reason == null && Certificates.ocspUrls(cert).stream().anyMatch(RevocationChecker::isHttp)) {
                reason = "the issuer publishes only OCSP, which is not used";
            }
            return status(index, cert, CertificateRevocation.Status.UNKNOWN, reason == null ? "no CRL is published for it" : reason,
                    null, null, null, null, null);
        }
    }

    /** The most recently issued: by thisUpdate, then CRL number; on a tie, the first. */
    private static Statement newest(List<Statement> statements) {
        Statement best = null;
        for (Statement s : statements) {
            if (best == null || newer(s.crl(), best.crl())) {
                best = s;
            }
        }
        return best;
    }

    private static boolean newer(Crl a, Crl b) {
        int t = a.thisUpdate().compareTo(b.thisUpdate());
        return t > 0 || (t == 0 && a.crlNumber().isPresent() && b.crlNumber().isPresent()
                && a.crlNumber().get().compareTo(b.crlNumber().get()) > 0);
    }

    /** Why {@code held} cannot say anything about {@code c}; null when it can. */
    private static String unusable(Crl held, X509Certificate c, X509Certificate issuer, Instant time) {
        try {
            held.crl().verify(issuer.getPublicKey());
        } catch (Exception e) {
            return "CRL signature does not verify";
        }
        boolean[] ku = issuer.getKeyUsage();
        if (ku != null && (ku.length < 7 || !ku[6])) {
            return "the issuer certificate may not sign CRLs";
        }
        if (held.thisUpdate().isAfter(time.plus(CLOCK_SKEW))) {
            return "CRL is not yet valid (thisUpdate " + held.thisUpdate() + ")";
        }
        if (held.nextUpdate() != null) {
            if (held.nextUpdate().isBefore(time)) {
                return "CRL expired at " + held.nextUpdate();
            }
        } else if (Duration.between(held.thisUpdate(), time).compareTo(MAX_AGE_WITHOUT_NEXT_UPDATE) > 0) {
            return "CRL states no next update and was issued more than " + MAX_AGE_WITHOUT_NEXT_UPDATE.toDays() + " days ago (" + held.thisUpdate() + ")";
        }
        if (!held.unsupportedCritical.isEmpty()) {
            return "the CRL has an unsupported critical extension " + held.unsupportedCritical.getFirst();
        }
        return scope(held, c);
    }

    /** Null when the CRL's scope (RFC 5280 §5.2.5, Issuing Distribution Point) covers {@code c}; otherwise why not. */
    private static String scope(Crl held, X509Certificate c) {
        byte[] ext = held.crl().getExtensionValue(Extension.issuingDistributionPoint.getId());
        IssuingDistributionPoint idp = null;
        if (ext != null) {
            try {
                idp = IssuingDistributionPoint.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets()));
            } catch (Exception e) {
                return "the CRL's issuing distribution point is malformed";
            }
        }
        if ((idp != null && idp.isIndirectCRL()) || held.certificateIssuerEntries) {
            return "indirect CRLs are not supported";
        }
        if (idp == null) {
            return null;
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
        // A CRL for one distribution point covers a certificate only when the certificate names that point (by URI, in
        // a distribution point that is not limited to some reasons or to another CRL issuer). A point named any other
        // way (a directoryName, a name relative to the issuer) is a partition this code cannot match: not covering.
        DistributionPointName point = idp.getDistributionPoint();
        List<String> uris = Certificates.fullNameUris(point);
        boolean otherNames = point != null && (point.getType() != DistributionPointName.FULL_NAME
                || GeneralNames.getInstance(point.getName()).getNames().length > uris.size());
        if ((!uris.isEmpty() || otherNames) && fullScopeUris(c).stream().noneMatch(uris::contains)) {
            return "the CRL's distribution point does not match the certificate";
        }
        return null;
    }

    /** The URIs of the certificate's CRL distribution points that cover every reason and name no other CRL issuer. */
    private static List<String> fullScopeUris(X509Certificate c) {
        byte[] ext = c.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return List.of();
        }
        try {
            List<String> out = new ArrayList<>();
            for (DistributionPoint p : CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(ext).getOctets()))
                    .getDistributionPoints()) {
                if (p.getReasons() == null && p.getCRLIssuer() == null) {
                    out.addAll(Certificates.fullNameUris(p.getDistributionPoint()));
                }
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
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
        return r == null ? "unspecified" : reasonName(r.ordinal());
    }

    /** The RFC 5280 name of a CRLReason code, as the device names it; a code without a name as {@code reason <code>}. */
    static String reasonName(int code) {
        return switch (code) {
            case 0 -> "unspecified";
            case 1 -> "keyCompromise";
            case 2 -> "cACompromise";
            case 3 -> "affiliationChanged";
            case 4 -> "superseded";
            case 5 -> "cessationOfOperation";
            case 6 -> "certificateHold";
            case 8 -> "removeFromCRL";
            case 9 -> "privilegeWithdrawn";
            case 10 -> "aACompromise";
            default -> "reason " + code;
        };
    }
}
