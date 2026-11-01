package io.vctrust.trust.server.service;

import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.CertificateRevocation.Status;
import io.vctrust.trust.core.x509.RevocationChecker;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

class OcspClientTest {

    static final TestPki.Issued ROOT = TestPki.rootCa("CN=OCSP Test Root,C=UT");
    static final TestPki.Issued GOOD = TestPki.withRevocationUrls("CN=Good leaf,C=UT", ROOT, false, List.of(), List.of("http://ocsp"), null);
    static final TestPki.Issued REVOKED = TestPki.withRevocationUrls("CN=Revoked leaf,C=UT", ROOT, false, List.of(), List.of("http://ocsp"), null);
    /** Delegated responder: issued by the root with id-kp-OCSPSigning. */
    static final TestPki.Issued RESPONDER = TestPki.leaf("CN=OCSP responder,C=UT", ROOT, List.of(), "1.3.6.1.5.5.7.3.9");
    static final TestPki.Issued STRANGER = TestPki.rootCa("CN=Stranger,C=UT");

    final HttpServer server;
    final String url;
    /** Who signs responses: the issuer, the delegated responder, or a stranger. */
    volatile TestPki.Issued signer = ROOT;
    /** Unlisted serials are good ({@link CertificateStatus#GOOD} is null). */
    final Map<BigInteger, CertificateStatus> statuses = new ConcurrentHashMap<>();

    OcspClientTest() throws Exception {
        statuses.put(REVOKED.certificate().getSerialNumber(), new RevokedStatus(Date.from(Instant.now().minus(Duration.ofDays(2))), 1));
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        url = "http://localhost:" + server.getAddress().getPort() + "/ocsp";
        server.createContext("/ocsp", ex -> {
            try {
                OCSPReq req = new OCSPReq(ex.getRequestBody().readAllBytes());
                KeyPair keys = signer.keys();
                var b = new JcaBasicOCSPRespBuilder(keys.getPublic(), new JcaDigestCalculatorProviderBuilder().build()
                        .get(org.bouncycastle.cert.ocsp.CertificateID.HASH_SHA1));
                for (Req r : req.getRequestList()) {
                    b.addResponse(r.getCertID(), statuses.getOrDefault(r.getCertID().getSerialNumber(), CertificateStatus.GOOD),
                            new Date(), Date.from(Instant.now().plus(Duration.ofHours(1))), null);
                }
                X509CertificateHolder[] chain = signer == RESPONDER
                        ? new X509CertificateHolder[]{new JcaX509CertificateHolder(RESPONDER.certificate())} : null;
                BasicOCSPResp basic = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate()), chain, new Date());
                byte[] body = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
                ex.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                ex.sendResponseHeaders(200, body.length);
                ex.getResponseBody().write(body);
            } catch (Exception e) {
                ex.sendResponseHeaders(500, -1);
            } finally {
                ex.close();
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void goodAndRevokedFromTheIssuerOrADelegatedResponder() {
        OcspClient ocsp = new OcspClient(CrlServiceTest.fetcher(), Clock.systemUTC());
        RevocationChecker.OcspResult good = ocsp.check(GOOD.certificate(), ROOT.certificate(), url, Instant.now());
        assertThat(good.status()).isEqualTo(Status.GOOD);
        assertThat(good.nextUpdate()).isAfter(Instant.now());

        signer = RESPONDER;
        RevocationChecker.OcspResult revoked = ocsp.check(REVOKED.certificate(), ROOT.certificate(), url, Instant.now());
        assertThat(revoked.status()).isEqualTo(Status.REVOKED);
        assertThat(revoked.reason()).isEqualTo("keyCompromise");
    }

    @Test
    void rejectsResponsesSignedByAnyoneElse() {
        signer = STRANGER;
        OcspClient ocsp = new OcspClient(CrlServiceTest.fetcher(), Clock.systemUTC());
        RevocationChecker.OcspResult r = ocsp.check(GOOD.certificate(), ROOT.certificate(), url, Instant.now());
        assertThat(r.status()).isEqualTo(Status.UNKNOWN);
        assertThat(r.reason()).isEqualTo("OCSP response signature does not verify");
    }
}
