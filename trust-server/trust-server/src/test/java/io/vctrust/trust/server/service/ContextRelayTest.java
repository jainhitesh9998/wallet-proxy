package io.vctrust.trust.server.service;

import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.http.SafeHttpFetcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** The JSON-LD context relay through the guarded outbound client, as it runs in the service. */
class ContextRelayTest {

    static final byte[] CONTEXT = "{ \"@context\": {\"name\": \"https://schema.org/name\"} }\n".getBytes(StandardCharsets.UTF_8);

    final HttpServer server;
    final int port;
    final String base;
    final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    final Clock clock = Clock.fixed(Instant.parse("2026-11-12T10:00:00Z"), ZoneOffset.UTC);
    final List<SafeHttpFetcher> fetchers = new ArrayList<>();

    ContextRelayTest() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        port = server.getAddress().getPort();
        base = "http://localhost:" + port;
        serve("/ctx", "application/ld+json", CONTEXT);
        serve("/not-a-context", "application/ld+json", "{\"internal\":\"what an admin console might say\"}".getBytes(StandardCharsets.UTF_8));
        serve("/array", "application/ld+json", "[{\"@context\":{}}]".getBytes(StandardCharsets.UTF_8));
        serve("/page", "text/html", "<html>what an admin console might say</html>".getBytes(StandardCharsets.UTF_8));
        serve("/large", "application/ld+json", ("{\"@context\":{},\"pad\":\"" + "x".repeat(200) + "\"}").getBytes(StandardCharsets.UTF_8));
        server.createContext("/to-internal", ex -> {
            hits.computeIfAbsent("/to-internal", k -> new AtomicInteger()).incrementAndGet();
            ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + port + "/ctx");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.start();
    }

    void serve(String path, String type, byte[] body) {
        server.createContext(path, ex -> {
            hits.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
            ex.getResponseHeaders().add("Content-Type", type);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
    }

    @AfterEach
    void stop() throws IOException {
        server.stop(0);
        for (SafeHttpFetcher f : fetchers) {
            f.close();
        }
    }

    int hits(String path) {
        return hits.getOrDefault(path, new AtomicInteger()).get();
    }

    /** A relay whose outbound client may reach {@code privateHosts} on loopback (this test's upstream), and nothing else internal. */
    ContextRelay relay(TrustProperties.Cache cache, String... privateHosts) {
        TrustProperties.Http http = new TrustProperties.Http();
        http.setHttpAllowedHosts(List.of("localhost", "127.0.0.1"));
        http.setAllowedPrivateHosts(List.of(privateHosts));
        SafeHttpFetcher fetcher = new SafeHttpFetcher(http);
        fetchers.add(fetcher);
        return new ContextRelay(new ContextService(fetcher, cache, clock), cache, clock);
    }

    static ServiceException refusal(Runnable call) {
        try {
            call.run();
        } catch (ServiceException e) {
            return e;
        }
        throw new AssertionError("expected a refusal");
    }

    @Test
    void passesOnTheBytesTheHostServedAndHoldsThem() {
        ContextRelay relay = relay(new TrustProperties.Cache(), "localhost");
        ContextRelay.Relayed r = relay.relay(base + "/ctx");
        assertThat(r.body()).isEqualTo(CONTEXT);
        assertThat(r.maxAge()).isEqualTo(Duration.ofHours(24)); // trust.cache.context-ttl
        assertThat(relay.relay(base + "/ctx").body()).isEqualTo(CONTEXT);
        assertThat(hits("/ctx")).isEqualTo(1);
    }

    @Test
    void passesOnNothingButAJsonLdContextWithinTheDocumentLimit() {
        TrustProperties.Cache cache = new TrustProperties.Cache();
        cache.setMaxDocumentBytes(100);
        ContextRelay relay = relay(cache, "localhost");
        for (String path : List.of("/not-a-context", "/array", "/page", "/large")) {
            ServiceException e = refusal(() -> relay.relay(base + path));
            assertThat(e.kind()).as(path).isEqualTo(ServiceException.Kind.UPSTREAM_FAILED);
            assertThat(e.code()).as(path).isEqualTo("invalid_context");
            assertThat(e.getMessage()).as(path).doesNotContain("admin console");
        }
        ServiceException missing = refusal(() -> relay.relay(base + "/nowhere"));
        assertThat(missing.code()).isEqualTo("upstream_unavailable");
    }

    @Test
    void reachesNoInternalAddress() {
        ContextRelay relay = relay(new TrustProperties.Cache());
        // The cloud metadata address, loopback by name, loopback by number: refused before any connection is made.
        for (String url : List.of("https://169.254.169.254/latest/meta-data/", "https://localhost:" + port + "/ctx", base + "/ctx",
                "http://127.0.0.1:" + port + "/ctx", "https://[::1]:" + port + "/ctx")) {
            ServiceException e = refusal(() -> relay.relay(url));
            assertThat(e.kind()).as(url).isEqualTo(ServiceException.Kind.INVALID_REQUEST);
            assertThat(e.code()).as(url).isEqualTo("invalid_request");
        }
        // Which address a name resolved to stays in the log: told to the caller, it would map the network for them.
        assertThat(refusal(() -> relay.relay("https://localhost:" + port + "/ctx")).getMessage())
                .contains("non-public address").doesNotContain("127.0.0.1").doesNotContain("::1");
        assertThat(hits("/ctx")).isZero();

        // A redirect is checked again: a host the relay may ask cannot send it on to one it may not.
        ContextRelay redirected = relay(new TrustProperties.Cache(), "localhost");
        ServiceException e = refusal(() -> redirected.relay(base + "/to-internal"));
        assertThat(e.code()).isEqualTo("invalid_request");
        assertThat(hits("/to-internal")).isEqualTo(1);
        assertThat(hits("/ctx")).isZero();
    }

    @Test
    void onlyHttpsUnlessTheOperatorAllowsTheHostAndOnlyHttpUrls() {
        ContextRelay relay = relay(new TrustProperties.Cache());
        ServiceException plain = refusal(() -> relay.relay("http://contexts.example/v1"));
        assertThat(plain.code()).isEqualTo("invalid_request");
        assertThat(plain.getMessage()).contains("Only https");
        for (String url : List.of("ftp://contexts.example/v1", "file:///etc/passwd", "classpath:application.yml", "/etc/passwd", "not a url")) {
            assertThat(refusal(() -> relay.relay(url)).code()).as(url).isEqualTo("invalid_request");
        }
    }

    @Test
    void switchedOffItAnswersNothingAndFetchesNothing() {
        TrustProperties.Cache cache = new TrustProperties.Cache();
        cache.setRelayContexts(false);
        ServiceException e = refusal(() -> relay(cache, "localhost").relay(base + "/ctx"));
        assertThat(e.kind()).isEqualTo(ServiceException.Kind.NOT_FOUND);
        assertThat(hits("/ctx")).isZero();
    }
}
