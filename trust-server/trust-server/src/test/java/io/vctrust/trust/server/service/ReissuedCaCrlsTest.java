package io.vctrust.trust.server.service;

import com.nimbusds.jwt.SignedJWT;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.FakeHttp;
import io.vctrust.trust.core.x509.CertificateRevocation;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustJacksonModule;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A CRL the service holds for an anchor is a CRL of the issuer, matched to a chain by the issuer's name and key, as
 * the device matches it: not by the anchor certificate it was configured with.
 *
 * <p>The fixture ({@code conformance/pki/generate-reissued.sh}): a CA with two certificates, the same name and key.
 * Framework {@code other} lists the first, whose distribution point serves the CA's current CRL, which revokes the
 * signer. Framework {@code partner} lists the second, with {@code crlUrls} naming an earlier CRL of the CA that revokes
 * nothing. A chain validates to whichever of the two the registry lists first. {@code reissued-ca.test.ts} decides the
 * same on the device, from the CRLs each client's snapshot carries.
 */
class ReissuedCaCrlsTest {

    static final String CURRENT = "http://crl.registry.example/current.crl";
    static final String LAST_WEEK = "http://crl.registry.example/last-week.crl";

    static final ClientProfile OTHER = new ClientProfile("other-wallet", "Other", Set.of("other"), false, false, false, false, false);
    static final ClientProfile PARTNER = new ClientProfile("partner-wallet", "Partner", Set.of("partner"), false, false, false, false, false);
    static final ClientProfile BOTH = new ClientProfile("both-wallet", "Both", Set.of("other", "partner"), false, false, false, false, false);

    @TempDir
    Path dir;

    final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void stop() throws Exception {
        for (AutoCloseable c : closing) {
            c.close();
        }
    }

    static Path pki(String file) {
        Path p = Path.of("").toAbsolutePath();
        while (!Files.exists(p.resolve("conformance/pki"))) {
            p = p.getParent();
        }
        return p.resolve("conformance/pki").resolve(file);
    }

    static X509Certificate certificate(String name) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(pki(name + ".pem"))));
    }

    static TrustAnchor official() throws Exception {
        return new TrustAnchor("official-iaca", TrustDomain.MDOC_IACA, certificate("reissued-ca"), "other", null, null, Map.of(), null);
    }

    static TrustAnchor partner() throws Exception {
        return new TrustAnchor("partner-iaca", TrustDomain.MDOC_IACA, certificate("reissued-ca-2"), "partner", null, null,
                Map.of("crlUrls", List.of(LAST_WEEK)), null);
    }

    /** The service around one registry, with the CA's CRLs at their locations. */
    final class Service {
        final TrustRegistry registry = new TrustRegistry();
        final CrlService crls;
        final TrustEvaluator evaluator;
        final SnapshotService snapshots;

        Service(List<TrustAnchor> anchors) throws Exception {
            registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("other", "Other", null, null, null),
                    new TrustFramework("partner", "Partner", null, null, null)), List.of(), anchors));
            FakeHttp http = new FakeHttp()
                    .respond(CURRENT, 200, "application/pkix-crl", Files.readAllBytes(pki("reissued-ca.crl")))
                    .respond(LAST_WEEK, 200, "application/pkix-crl", Files.readAllBytes(pki("reissued-ca-old.crl")));
            TrustProperties.Revocation cfg = new TrustProperties.Revocation();
            cfg.setEnabled(false); // no refresh thread: the test loads the CRLs itself
            crls = new CrlService(registry, http, cfg, new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false),
                    Clock.systemUTC());
            closing.add(crls);
            crls.refresh();
            evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(),
                    Duration.ofHours(1), new RevocationChecker(crls, "trust-service"));
            snapshots = new SnapshotService(registry, new ServiceKeyManager(dir.resolve("key.jwk").toString(), "https://trust.test"),
                    JsonMapper.builder().addModule(new TrustJacksonModule()).build(), null, crls, null,
                    new SnapshotService.Options(Duration.ofHours(1), false, 0, Duration.ofSeconds(1), 262144, 262144, Duration.ZERO),
                    Clock.systemUTC(), TrustMechanisms.NONE);
        }

        CertificateRevocation signerStatus(ClientProfile client, Decision expected, String order) throws Exception {
            TrustDecision d = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                    new TrustQuery.Subject(null, List.of(Certificates.toBase64(certificate("reissued-ds"))), null, null),
                    new TrustQuery.Context("oid4vci", "mso_mdoc", "org.iso.18013.5.1.mDL", null, null, List.of())), client);
            assertThat(d.decision()).as(order + ", " + client.clientId() + ": " + d.reasons()).isEqualTo(expected);
            return d.evidence().x509().revocation().getFirst();
        }

        /** The CRLs in the snapshot {@code client} is given: location and the anchor certificate it was configured for. */
        @SuppressWarnings("unchecked")
        List<List<String>> crlsIn(ClientProfile client) throws Exception {
            List<Object> claim = SignedJWT.parse(snapshots.snapshot(client).jwt()).getJWTClaimsSet().getListClaim("crls");
            return claim.stream().map(c -> (Map<String, Object>) c).map(c -> List.of((String) c.get("url"), (String) c.get("issuer"),
                    Base64.getEncoder().encodeToString(Base64.getDecoder().decode((String) c.get("crl"))))).toList();
        }
    }

    @Test
    void aCrlOfTheCaCountsWhicheverOfItsCertificatesTheChainValidatesTo() throws Exception {
        String officialThumb = Certificates.sha256Thumbprint(certificate("reissued-ca"));
        String partnerThumb = Certificates.sha256Thumbprint(certificate("reissued-ca-2"));
        String current = Base64.getEncoder().encodeToString(Files.readAllBytes(pki("reissued-ca.crl")));
        String lastWeek = Base64.getEncoder().encodeToString(Files.readAllBytes(pki("reissued-ca-old.crl")));
        for (List<TrustAnchor> anchors : List.of(List.of(partner(), official()), List.of(official(), partner()))) {
            String order = anchors.getFirst().id() + " first";
            Service service = new Service(anchors);

            // A client that sees both frameworks holds both CRLs of the CA: the revocation in the current one stands,
            // also when the chain validates to partner's certificate, for which only last week's CRL was configured.
            assertThat(service.signerStatus(BOTH, Decision.NOT_TRUSTED, order)).as(order).satisfies(s -> {
                assertThat(s.status()).isEqualTo(CertificateRevocation.Status.REVOKED);
                assertThat(s.crlUrl()).isEqualTo(CURRENT);
            });
            assertThat(service.crlsIn(BOTH)).as(order).containsExactlyInAnyOrder(
                    List.of(CURRENT, officialThumb, current), List.of(LAST_WEEK, partnerThumb, lastWeek));

            // A client of one framework is decided by that framework's CRL, as before.
            assertThat(service.signerStatus(OTHER, Decision.NOT_TRUSTED, order).status()).as(order).isEqualTo(CertificateRevocation.Status.REVOKED);
            assertThat(service.crlsIn(OTHER)).as(order).containsExactly(List.of(CURRENT, officialThumb, current));
            assertThat(service.signerStatus(PARTNER, Decision.TRUSTED, order)).as(order).satisfies(s -> {
                assertThat(s.status()).isEqualTo(CertificateRevocation.Status.GOOD);
                assertThat(s.crlUrl()).isEqualTo(LAST_WEEK);
            });
            assertThat(service.crlsIn(PARTNER)).as(order).containsExactly(List.of(LAST_WEEK, partnerThumb, lastWeek));
        }
    }
}
