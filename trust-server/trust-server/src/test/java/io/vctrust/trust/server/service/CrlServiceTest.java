package io.vctrust.trust.server.service;

import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.testing.TestPki.Revoked;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.http.SafeHttpFetcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509CRL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CrlServiceTest {

    /** A clock tests can move forward. */
    static final class MutableClock extends Clock {
        Instant now = Instant.now();

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    final HttpServer server;
    final String base;
    final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    final MutableClock clock = new MutableClock();
    CrlService service;

    CrlServiceTest() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        base = "http://localhost:" + server.getAddress().getPort();
        server.start();
    }

    void serve(String path, byte[] body, String type) {
        server.createContext(path, ex -> {
            hits.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
            ex.getResponseHeaders().add("Content-Type", type);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
    }

    static byte[] der(X509CRL crl) {
        try {
            return crl.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static SafeHttpFetcher fetcher() {
        TrustProperties.Http http = new TrustProperties.Http();
        http.setAllowPrivateNetworks(true);
        http.setHttpAllowedHosts(List.of("localhost"));
        return new SafeHttpFetcher(http);
    }

    static TrustAnchor anchor(String id, TestPki.Issued ca, String framework, Map<String, Object> constraints) {
        return new TrustAnchor(id, TrustDomain.MDOC_IACA, ca.certificate(), framework, null, null, constraints, null);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        if (service != null) {
            service.close();
        }
    }

    @Test
    void loadsVerifiesAndRefreshesAnchorCrls() throws Exception {
        var configured = TestPki.rootCa("CN=Configured CRL,C=UT");
        var ds = TestPki.documentSigner("CN=Configured DS,C=UT", configured);
        var selfIssued = TestPki.rootCa("CN=Self CRL,C=UT", List.of(base + "/self.crl"));
        var pushed = TestPki.rootCa("CN=Pushed CRL,C=UT");
        var wrong = TestPki.rootCa("CN=Wrong CRL,C=UT");
        serve("/configured.crl", der(TestPki.crl(configured, Revoked.of(ds, 1))), "application/pkix-crl");
        serve("/self.crl", der(TestPki.crl(selfIssued)), "application/pkix-crl");
        serve("/wrong.crl", der(TestPki.crl(configured)), "application/pkix-crl");
        String pem = "-----BEGIN X509 CRL-----\n" + Base64.getMimeEncoder().encodeToString(der(TestPki.crl(pushed))) + "\n-----END X509 CRL-----\n";

        TrustRegistry registry = new TrustRegistry();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(), List.of(), List.of(
                anchor("configured", configured, "fw-a", Map.of("crlUrls", List.of(base + "/configured.crl"))),
                anchor("self", selfIssued, "fw-a", Map.of()),
                anchor("pushed", pushed, "fw-b", Map.of("crl", pem)),
                anchor("wrong", wrong, "fw-a", Map.of("crlUrls", base + "/wrong.crl")))));
        TrustProperties.Revocation cfg = new TrustProperties.Revocation();
        cfg.setEnabled(false); // no background thread: the test drives refresh()
        service = new CrlService(registry, fetcher(), cfg, new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false), clock);
        AtomicInteger changes = new AtomicInteger();
        service.onChange(changes::incrementAndGet);
        service.refresh();

        assertThat(service.heldFor(configured.certificate())).singleElement().satisfies(c -> {
            assertThat(c.url()).isEqualTo(base + "/configured.crl");
            assertThat(c.revokedCount()).isEqualTo(1);
        });
        assertThat(service.heldFor(selfIssued.certificate())).hasSize(1);
        assertThat(service.heldFor(pushed.certificate())).singleElement().satisfies(c -> assertThat(c.url()).isNull());
        assertThat(service.heldFor(wrong.certificate())).isEmpty();
        assertThat(changes.get()).isEqualTo(1);

        List<Map<String, Object>> listing = service.listing(a -> true);
        assertThat(listing).hasSize(4);
        assertThat(listing).filteredOn(m -> m.get("anchorIds").equals(List.of("wrong")))
                .singleElement().satisfies(m -> assertThat((String) m.get("error")).contains("not issued and signed by the anchor"));

        // Snapshot claims: visible, verified anchors only; pushed CRLs carry no url.
        List<Map<String, Object>> claims = service.snapshotClaims(a -> "fw-a".equals(a.frameworkId()), 256 * 1024);
        assertThat(claims).extracting(m -> m.get("issuer")).containsExactlyInAnyOrder(
                Certificates.sha256Thumbprint(configured.certificate()), Certificates.sha256Thumbprint(selfIssued.certificate()));
        assertThat(claims.getFirst()).containsKeys("crl", "thisUpdate", "nextUpdate", "crlNumber", "url");
        assertThat(service.snapshotClaims(a -> true, 10)).isEmpty();

        // Not due yet: no refetch. After the refresh interval: refetched, unchanged CRLs → no change event.
        service.refresh();
        assertThat(hits.get("/configured.crl").get()).isEqualTo(1);
        clock.now = clock.now.plus(Duration.ofHours(2));
        service.refresh();
        assertThat(hits.get("/configured.crl").get()).isEqualTo(2);
        assertThat(changes.get()).isEqualTo(1);
    }

    @Test
    void anOlderCrlDoesNotReplaceTheOneHeld() throws Exception {
        var ca = TestPki.rootCa("CN=Replayed CRL,C=UT");
        var ds = TestPki.documentSigner("CN=Revoked DS,C=UT", ca);
        Instant now = clock.instant();
        // Issued yesterday, before the revocation; and today's, which revokes the document signer. Both are genuine.
        byte[] before = der(TestPki.crl(ca, now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(6)), List.of(), null, null));
        byte[] current = der(TestPki.crl(ca, now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(7)), List.of(Revoked.of(ds, 1)), null, null));
        var served = new java.util.concurrent.atomic.AtomicReference<>(current);
        server.createContext("/replayed.crl", ex -> {
            ex.getResponseHeaders().add("Content-Type", "application/pkix-crl");
            ex.sendResponseHeaders(200, served.get().length);
            ex.getResponseBody().write(served.get());
            ex.close();
        });
        TrustRegistry registry = new TrustRegistry();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(), List.of(), List.of(
                anchor("replayed", ca, "fw-a", Map.of("crlUrls", List.of(base + "/replayed.crl"))))));
        TrustProperties.Revocation cfg = new TrustProperties.Revocation();
        cfg.setEnabled(false);
        service = new CrlService(registry, fetcher(), cfg, new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false), clock);
        service.refresh();
        assertThat(service.heldFor(ca.certificate())).singleElement().satisfies(c -> assertThat(c.revokedCount()).isEqualTo(1));

        // Whoever answers at the distribution point (plain http) now serves the CRL from before the revocation.
        served.set(before);
        clock.now = clock.now.plus(Duration.ofHours(2));
        service.refresh();
        assertThat(service.heldFor(ca.certificate())).singleElement().satisfies(c -> assertThat(c.revokedCount()).isEqualTo(1));
        assertThat(service.listing(a -> true)).singleElement()
                .satisfies(m -> assertThat((String) m.get("error")).contains("older than the one held"));
    }

    @Test
    void fetchesDistributionPointsOnDemandAndRelays() throws Exception {
        var inter = TestPki.rootCa("CN=Intermediate CRL,C=UT");
        serve("/inter.crl", der(TestPki.crl(inter)), "application/pkix-crl");
        serve("/page", "<html>no</html>".getBytes(StandardCharsets.UTF_8), "text/html");
        TrustProperties.Revocation cfg = new TrustProperties.Revocation();
        cfg.setEnabled(false);
        service = new CrlService(new TrustRegistry(), fetcher(), cfg, new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false), clock);
        assertThat(service.fetch(base + "/inter.crl").issuedBy(inter.certificate())).isTrue();
        service.fetch(base + "/inter.crl");
        assertThat(hits.get("/inter.crl").get()).isEqualTo(1);
        CrlService.Relayed relayed = service.relay(base + "/inter.crl");
        assertThat(relayed.expiresAt()).isAfter(clock.instant());
        assertThatThrownBy(() -> service.relay(base + "/page")).isInstanceOf(IOException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class);

        cfg.setFetchOnDemand(false);
        assertThatThrownBy(() -> service.fetch(base + "/inter.crl")).hasMessageContaining("disabled");
    }
}
