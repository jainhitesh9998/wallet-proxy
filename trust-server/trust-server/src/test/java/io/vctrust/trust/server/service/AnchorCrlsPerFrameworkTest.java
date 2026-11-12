package io.vctrust.trust.server.service;

import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.testing.TestPki.Revoked;
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

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The CRL configuration of an anchor is its framework's: an anchor record of one framework (its {@code crlUrls}, a
 * pushed {@code crl}) does not decide which CRL the anchor of another framework gets for the same certificate. A client
 * is told, and decided for, by the CRLs of the frameworks it sees.
 *
 * <p>The scenario: the CA of framework {@code other} publishes its CRL at the distribution point in its own
 * certificate, and that CRL revokes a signer. Framework {@code partner} lists the same certificate with {@code crlUrls}
 * naming last week's CRL of the same CA: genuine, still within its validity, from before the revocation.
 */
class AnchorCrlsPerFrameworkTest {

    static final ClientProfile OTHER = new ClientProfile("other-wallet", "Other", Set.of("other"), false, false, false, false, false);
    static final ClientProfile PARTNER = new ClientProfile("partner-wallet", "Partner", Set.of("partner"), false, false, false, false, false);
    static final ClientProfile BOTH = new ClientProfile("both-wallet", "Both", Set.of("other", "partner"), false, false, false, false, false);
    static final ClientProfile OPERATOR = new ClientProfile("ops", "ops", Set.of(ClientProfile.ALL_FRAMEWORKS), false, false, true);

    @TempDir
    Path dir;

    final HttpServer server;
    final String base;
    final String current;
    final String lastWeek;
    final TestPki.Issued ca;
    final TestPki.Issued signer;
    /** Last week's CRL of the CA: genuine, still within its validity, from before the signer was revoked. */
    final byte[] lastWeekCrl;
    final List<AutoCloseable> closing = new ArrayList<>();

    AnchorCrlsPerFrameworkTest() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        base = "http://localhost:" + server.getAddress().getPort();
        current = base + "/current.crl";
        lastWeek = base + "/last-week.crl";
        ca = TestPki.rootCa("CN=Official IACA,C=UT", List.of(current));
        signer = TestPki.documentSigner("CN=Official DS,C=UT", ca);
        Instant now = Instant.now();
        serve("/current.crl", TestPki.crl(ca, now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(7)),
                List.of(Revoked.of(signer, 1)), BigInteger.TWO).getEncoded());
        lastWeekCrl = TestPki.crl(ca, now.minus(Duration.ofDays(7)), now.plus(Duration.ofDays(7)), List.of(), BigInteger.ONE).getEncoded();
        serve("/last-week.crl", lastWeekCrl);
        server.start();
    }

    void serve(String path, byte[] body) {
        server.createContext(path, ex -> {
            ex.getResponseHeaders().add("Content-Type", "application/pkix-crl");
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
    }

    @AfterEach
    void stop() throws Exception {
        server.stop(0);
        for (AutoCloseable c : closing) {
            c.close();
        }
    }

    TrustAnchor official() {
        return new TrustAnchor("official-iaca", TrustDomain.MDOC_IACA, ca.certificate(), "other", null, null, Map.of(),
                Provenance.of("official", "static", "other", null, Instant.now()));
    }

    TrustAnchor partner() {
        return new TrustAnchor("partner-iaca", TrustDomain.MDOC_IACA, ca.certificate(), "partner", null, null,
                Map.of("crlUrls", List.of(lastWeek)), Provenance.of("partner", "static", "partner", null, Instant.now()));
    }

    /** The service around one registry: the CRLs it holds, its evaluator, and the snapshot each client is given. */
    final class Service {
        final TrustRegistry registry = new TrustRegistry();
        final CrlService crls;
        final TrustEvaluator evaluator;
        final SnapshotService snapshots;

        Service(List<TrustAnchor> anchors) {
            registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("other", "Other", null, null, null),
                    new TrustFramework("partner", "Partner", null, null, null)), List.of(), anchors));
            TrustProperties.Revocation cfg = new TrustProperties.Revocation();
            cfg.setEnabled(false); // no refresh thread: the test loads the CRLs itself
            crls = new CrlService(registry, CrlServiceTest.fetcher(), cfg,
                    new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false), Clock.systemUTC());
            closing.add(crls);
            crls.refresh();
            // As TrustCoreConfiguration wires them.
            evaluator = new TrustEvaluator(registry, null, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(),
                    Duration.ofHours(1), new RevocationChecker(crls, "trust-service"));
            snapshots = new SnapshotService(registry, new ServiceKeyManager(dir.resolve("key.jwk").toString(), "https://trust.test"),
                    JsonMapper.builder().addModule(new TrustJacksonModule()).build(), null, crls, null,
                    new SnapshotService.Options(Duration.ofHours(1), false, 0, Duration.ofSeconds(1), 262144, 262144, Duration.ZERO),
                    Clock.systemUTC(), TrustMechanisms.NONE);
        }

        /** The signer's status, as the service decides it for {@code client}. */
        CertificateRevocation signerStatus(ClientProfile client, Decision expected) {
            TrustDecision d = evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                    new TrustQuery.Subject(null, List.of(Certificates.toBase64(signer.certificate())), null, null),
                    new TrustQuery.Context("oid4vci", "mso_mdoc", "org.iso.18013.5.1.mDL", null, null, List.of())), client);
            assertThat(d.decision()).as(client.clientId() + ": " + d.reasons()).isEqualTo(expected);
            return d.evidence().x509().revocation().getFirst();
        }

        /** The CRL locations in the snapshot {@code client} is given. */
        @SuppressWarnings("unchecked")
        List<String> crlsIn(ClientProfile client) throws Exception {
            List<Object> claim = SignedJWT.parse(snapshots.snapshot(client).jwt()).getJWTClaimsSet().getListClaim("crls");
            String issuer = Certificates.sha256Thumbprint(ca.certificate());
            assertThat(claim).allSatisfy(c -> assertThat(((Map<String, Object>) c).get("issuer")).isEqualTo(issuer));
            return claim.stream().map(c -> (String) ((Map<String, Object>) c).get("url")).toList();
        }
    }

    @Test
    void theCaAloneRevokesTheSigner() throws Exception {
        Service service = new Service(List.of(official()));
        assertThat(service.signerStatus(OTHER, Decision.NOT_TRUSTED)).satisfies(s -> {
            assertThat(s.status()).isEqualTo(CertificateRevocation.Status.REVOKED);
            assertThat(s.crlUrl()).isEqualTo(current);
        });
        assertThat(service.crlsIn(OTHER)).containsExactly(current);
    }

    @Test
    void anotherFrameworksAnchorRecordDoesNotChooseTheCrlOfThisFramework() throws Exception {
        // Whichever framework's anchor the registry lists first.
        for (List<TrustAnchor> anchors : List.of(List.of(official(), partner()), List.of(partner(), official()))) {
            String order = anchors.getFirst().id() + " first";
            Service service = new Service(anchors);

            // A client of "other" is told, and decided for, by the CA's own CRL: the signer stays revoked.
            assertThat(service.signerStatus(OTHER, Decision.NOT_TRUSTED)).as(order).satisfies(s -> {
                assertThat(s.status()).isEqualTo(CertificateRevocation.Status.REVOKED);
                assertThat(s.crlUrl()).isEqualTo(current);
            });
            assertThat(service.crlsIn(OTHER)).as(order).containsExactly(current);

            // A client that sees both frameworks holds both CRLs: the revocation in the current one stands.
            assertThat(service.signerStatus(BOTH, Decision.NOT_TRUSTED)).as(order).satisfies(s -> {
                assertThat(s.status()).isEqualTo(CertificateRevocation.Status.REVOKED);
                assertThat(s.crlUrl()).isEqualTo(current);
            });
            assertThat(service.crlsIn(BOTH)).as(order).containsExactlyInAnyOrder(current, lastWeek);

            // A client of "partner" alone is told what its own framework says, and nothing of the other's.
            assertThat(service.signerStatus(PARTNER, Decision.TRUSTED)).as(order).satisfies(s -> {
                assertThat(s.status()).isEqualTo(CertificateRevocation.Status.GOOD);
                assertThat(s.crlUrl()).isEqualTo(lastWeek);
            });
            assertThat(service.crlsIn(PARTNER)).as(order).containsExactly(lastWeek);

            // The operator sees which framework each CRL is for.
            List<Map<String, Object>> listing = new AdministrationService(null, service.registry, List::of, null, null, null, null,
                    service.crls, 262144).anchorCrls(OPERATOR);
            assertThat(listing).as(order).extracting(m -> m.get("url"), m -> m.get("frameworks"), m -> m.get("anchorIds"))
                    .containsExactlyInAnyOrder(
                            org.assertj.core.groups.Tuple.tuple(current, List.of("other"), List.of("official-iaca")),
                            org.assertj.core.groups.Tuple.tuple(lastWeek, List.of("partner"), List.of("partner-iaca")));
        }
    }

    @Test
    void aCrlPushedByAnotherFrameworkIsThatFrameworksOnly() throws Exception {
        // The partner pushes last week's CRL with its anchor record instead of naming where it is.
        TrustAnchor pushed = new TrustAnchor("partner-iaca", TrustDomain.MDOC_IACA, ca.certificate(), "partner", null, null,
                Map.of("crl", java.util.Base64.getEncoder().encodeToString(lastWeekCrl)), null);
        Service service = new Service(List.of(pushed, official()));
        assertThat(service.signerStatus(OTHER, Decision.NOT_TRUSTED).crlUrl()).isEqualTo(current);
        assertThat(service.crlsIn(OTHER)).containsExactly(current);
        assertThat(service.signerStatus(BOTH, Decision.NOT_TRUSTED).status()).isEqualTo(CertificateRevocation.Status.REVOKED);
        assertThat(service.crlsIn(BOTH)).containsExactlyInAnyOrder(current, null);
        assertThat(service.crlsIn(PARTNER)).containsExactly((String) null);
    }
}
