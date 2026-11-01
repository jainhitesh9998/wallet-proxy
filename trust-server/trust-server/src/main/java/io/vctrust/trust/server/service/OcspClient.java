package io.vctrust.trust.server.service;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.x509.CertificateRevocation.Status;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OCSP (RFC 6960) for server-side decisions only, off by default ({@code trust.revocation.ocsp}). An OCSP request
 * names the exact certificate being checked, so devices never send one; verifier backends asking this service in
 * 'service' mode may. Responses must be signed by the issuer or by a delegated responder certificate it issued
 * (id-kp-OCSPSigning), and are cached until their nextUpdate (5 minutes when absent).
 */
public class OcspClient implements RevocationChecker.OcspSource {

    private static final String OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    private record Cached(RevocationChecker.OcspResult result, Instant until) {
    }

    private final HttpFetcher http;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public OcspClient(HttpFetcher http, Clock clock) {
        this.http = http;
        this.clock = clock;
    }

    @Override
    public RevocationChecker.OcspResult check(X509Certificate cert, X509Certificate issuer, String url, Instant time) {
        String key = Certificates.sha256Thumbprint(issuer) + "|" + cert.getSerialNumber().toString(16);
        Instant now = clock.instant();
        Cached c = cache.get(key);
        if (c != null && c.until().isAfter(now)) {
            return c.result();
        }
        RevocationChecker.OcspResult r;
        try {
            r = query(cert, issuer, url, time);
        } catch (Exception e) {
            return unknown("OCSP responder unavailable: " + e.getMessage());
        }
        if (r.status() != Status.UNKNOWN || r.thisUpdate() != null) {
            Instant until = r.nextUpdate() != null && r.nextUpdate().isAfter(now) ? r.nextUpdate() : now.plus(DEFAULT_TTL);
            cache.put(key, new Cached(r, until));
        }
        return r;
    }

    private RevocationChecker.OcspResult query(X509Certificate cert, X509Certificate issuer, String url, Instant time) throws Exception {
        CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer), cert.getSerialNumber());
        byte[] req = new OCSPReqBuilder().addRequest(id).build().getEncoded();
        HttpFetcher.Response http = this.http.execute(HttpFetcher.Request.post(URI.create(url), "application/ocsp-request", req,
                "application/ocsp-response"));
        if (!http.isSuccess()) {
            return unknown("OCSP responder returned HTTP " + http.status());
        }
        OCSPResp resp = new OCSPResp(http.body());
        if (resp.getStatus() != OCSPResp.SUCCESSFUL) {
            return unknown("OCSP responder status " + resp.getStatus());
        }
        if (!(resp.getResponseObject() instanceof BasicOCSPResp basic)) {
            return unknown("unsupported OCSP response type");
        }
        if (!signedByIssuerOrDelegate(basic, issuer, time)) {
            return unknown("OCSP response signature does not verify");
        }
        for (SingleResp s : basic.getResponses()) {
            if (!s.getCertID().equals(id)) {
                continue;
            }
            Instant thisUpdate = s.getThisUpdate().toInstant();
            Instant nextUpdate = s.getNextUpdate() == null ? null : s.getNextUpdate().toInstant();
            if (thisUpdate.isAfter(time.plus(RevocationChecker.CLOCK_SKEW)) || (nextUpdate != null && nextUpdate.isBefore(time))) {
                return unknown("OCSP response is not current");
            }
            CertificateStatus cs = s.getCertStatus();
            if (cs == CertificateStatus.GOOD) {
                return new RevocationChecker.OcspResult(Status.GOOD, null, null, thisUpdate, nextUpdate);
            }
            if (cs instanceof RevokedStatus rs) {
                int code = rs.hasRevocationReason() ? rs.getRevocationReason() : 0;
                return new RevocationChecker.OcspResult(code == 6 ? Status.ON_HOLD : Status.REVOKED,
                        RevocationChecker.reasonName(code), rs.getRevocationTime().toInstant(), thisUpdate, nextUpdate);
            }
            return new RevocationChecker.OcspResult(Status.UNKNOWN, "the OCSP responder does not know the certificate", null,
                    thisUpdate, nextUpdate);
        }
        return unknown("the OCSP response does not cover the certificate");
    }

    private static boolean signedByIssuerOrDelegate(BasicOCSPResp basic, X509Certificate issuer, Instant time) {
        if (verifies(basic, issuer.getPublicKey())) {
            return true;
        }
        for (X509CertificateHolder h : basic.getCerts()) {
            try {
                X509Certificate d = new JcaX509CertificateConverter().getCertificate(h);
                d.verify(issuer.getPublicKey());
                if (d.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                        && Certificates.extendedKeyUsage(d).contains(OCSP_SIGNING)
                        && !time.isBefore(d.getNotBefore().toInstant()) && !time.isAfter(d.getNotAfter().toInstant())
                        && verifies(basic, d.getPublicKey())) {
                    return true;
                }
            } catch (Exception e) {
                // not a delegate of this issuer
            }
        }
        return false;
    }

    private static boolean verifies(BasicOCSPResp basic, PublicKey key) {
        try {
            return basic.isSignatureValid(new JcaContentVerifierProviderBuilder().build(key));
        } catch (Exception e) {
            return false;
        }
    }

    private static RevocationChecker.OcspResult unknown(String why) {
        return new RevocationChecker.OcspResult(Status.UNKNOWN, why, null, null, null);
    }
}
