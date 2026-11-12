package io.vctrust.trust.server.http;

import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafeHttpFetcherTest {

    /** A fetch that is cut off returns in well under this, on any machine; one that reads on takes the 40 s the body lasts. */
    static final java.time.Duration LONG_BEFORE_THE_BODY_ENDS = java.time.Duration.ofSeconds(15);

    static HttpServer server;
    static int port;
    static final AtomicInteger hits = new AtomicInteger();

    /** Every test host answers with the loopback address of the local server, like a rebinding DNS would. */
    static final DnsResolver LOOPBACK_DNS = new DnsResolver() {
        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            if (Character.isDigit(host.charAt(0))) {
                return new InetAddress[] {InetAddress.getByName(host)}; // IP literals reach the resolver too
            }
            if (!host.endsWith(".test")) {
                throw new UnknownHostException(host);
            }
            return new InetAddress[] {InetAddress.getLoopbackAddress()};
        }

        @Override
        public String resolveCanonicalHostname(String host) {
            return host;
        }
    };

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/ok", ex -> {
            hits.incrementAndGet();
            byte[] b = "hello".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "text/plain");
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.createContext("/to-internal", ex -> {
            hits.incrementAndGet();
            ex.getResponseHeaders().add("Location", "http://internal.test:" + port + "/ok");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.createContext("/big", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(200, 0);
            ex.getResponseBody().write(new byte[4096]);
            ex.close();
        });
        // A body that never ends: a chunk every 50 ms until the client goes away (or, as a backstop, for 40 s).
        server.createContext("/endless", ex -> {
            hits.incrementAndGet();
            endless(ex, 200);
        });
        // What arrived: the headers a test sent, as "name=value" lines (absent ones as "name=").
        server.createContext("/echo-headers", ex -> {
            hits.incrementAndGet();
            StringBuilder sb = new StringBuilder();
            for (String name : List.of("Authorization", "X-Api-Key", "Accept")) {
                String v = ex.getRequestHeaders().getFirst(name);
                sb.append(name).append('=').append(v == null ? "" : v).append('\n');
            }
            byte[] b = sb.toString().getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.createContext("/to-same-origin", ex -> redirect(ex, "http://public.test:" + port + "/echo-headers"));
        server.createContext("/to-other-origin", ex -> redirect(ex, "http://other.test:" + port + "/echo-headers"));
        // Away to another origin, which sends the request back to the first one.
        server.createContext("/away-and-back", ex -> redirect(ex, "http://other.test:" + port + "/back"));
        server.createContext("/back", ex -> redirect(ex, "http://public.test:" + port + "/echo-headers"));
        server.createContext("/endless-redirect", ex -> {
            hits.incrementAndGet();
            ex.getResponseHeaders().add("Location", "http://public.test:" + port + "/ok");
            endless(ex, 302);
        });
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "test-upstream");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    static void redirect(com.sun.net.httpserver.HttpExchange ex, String location) throws IOException {
        hits.incrementAndGet();
        ex.getResponseHeaders().add("Location", location);
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    static void endless(com.sun.net.httpserver.HttpExchange ex, int status) throws IOException {
        ex.sendResponseHeaders(status, 0);
        try (var out = ex.getResponseBody()) {
            long end = System.nanoTime() + java.time.Duration.ofSeconds(40).toNanos();
            while (System.nanoTime() < end) {
                out.write(new byte[256]);
                out.flush();
                Thread.sleep(50);
            }
        } catch (IOException | InterruptedException gone) {
            // the client dropped the connection
        }
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    @BeforeEach
    void reset() {
        hits.set(0);
    }

    static TrustProperties.Http config(List<String> privateHosts) {
        TrustProperties.Http http = new TrustProperties.Http();
        http.setHttpAllowedHosts(List.of("rebind.test", "public.test", "internal.test", "127.0.0.1"));
        http.setAllowedPrivateHosts(privateHosts);
        http.setMaxResponseBytes(1024);
        return http;
    }

    static URI url(String host, String path) {
        return URI.create("http://" + host + ":" + port + path);
    }

    @Test
    void hostResolvingToAnInternalAddressIsRefusedBeforeConnecting() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of()), LOOPBACK_DNS)) {
            assertThatThrownBy(() -> fetcher.get(url("rebind.test", "/ok"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    // which address it is stays in the log: the answer must not map the network for the caller
                    .hasMessageContaining("non-public address").hasMessageNotContaining("127.0.0.1");
            assertThatThrownBy(() -> fetcher.get(url("127.0.0.1", "/ok"), null))
                    .isInstanceOf(HttpFetcher.BlockedException.class);
        }
        assertThat(hits).hasValue(0);
    }

    @Test
    void allowedPrivateHostsMayResolveInternally() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of("rebind.test")), LOOPBACK_DNS)) {
            HttpFetcher.Response r = fetcher.get(url("rebind.test", "/ok"), "text/plain");
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.bodyAsString()).isEqualTo("hello");
            assertThat(r.contentType()).isEqualTo("text/plain");
        }
        assertThat(hits).hasValue(1);
    }

    @Test
    void redirectToAnInternalAddressIsRefused() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of("public.test")), LOOPBACK_DNS)) {
            assertThatThrownBy(() -> fetcher.get(url("public.test", "/to-internal"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("internal.test");
        }
        assertThat(hits).hasValue(1); // the redirect only; /ok was never reached
    }

    @Test
    void onlyAcceptFollowsARedirectToAnotherOrigin() throws IOException {
        TrustProperties.Http cfg = config(List.of("public.test", "other.test"));
        cfg.setHttpAllowedHosts(List.of("public.test", "other.test"));
        Map<String, String> headers = Map.of("Authorization", "Bearer secret-token", "X-Api-Key", "secret-key",
                "Accept", "application/json");
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(cfg, LOOPBACK_DNS)) {
            // Asked directly, and redirected within the origin: every header arrives.
            String all = "Authorization=Bearer secret-token\nX-Api-Key=secret-key\nAccept=application/json\n";
            assertThat(fetcher.execute(new HttpFetcher.Request("GET", url("public.test", "/echo-headers"), headers, null, null))
                    .bodyAsString()).isEqualTo(all);
            assertThat(fetcher.execute(new HttpFetcher.Request("GET", url("public.test", "/to-same-origin"), headers, null, null))
                    .bodyAsString()).isEqualTo(all);
            // Redirected to another host: only Accept goes on.
            String acceptOnly = "Authorization=\nX-Api-Key=\nAccept=application/json\n";
            assertThat(fetcher.execute(new HttpFetcher.Request("GET", url("public.test", "/to-other-origin"), headers, null, null))
                    .bodyAsString()).isEqualTo(acceptOnly);
            // Sent back to the first origin by the other one: the credentials stay dropped.
            assertThat(fetcher.execute(new HttpFetcher.Request("GET", url("public.test", "/away-and-back"), headers, null, null))
                    .bodyAsString()).isEqualTo(acceptOnly);
        }
        // Another port, or another scheme, is another origin.
        assertThat(SafeHttpFetcher.sameOrigin(URI.create("https://a.test/x"), URI.create("https://A.test:443/y?z"))).isTrue();
        assertThat(SafeHttpFetcher.sameOrigin(URI.create("https://a.test/x"), URI.create("https://a.test:8443/x"))).isFalse();
        assertThat(SafeHttpFetcher.sameOrigin(URI.create("https://a.test/x"), URI.create("http://a.test/x"))).isFalse();
        assertThat(SafeHttpFetcher.sameOrigin(URI.create("https://a.test/x"), URI.create("https://b.a.test/x"))).isFalse();
    }

    @Test
    void plainHttpOnlyThroughTheCrlView() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of("crl.test")), LOOPBACK_DNS)) {
            assertThatThrownBy(() -> fetcher.get(url("crl.test", "/ok"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("Only https");
            HttpFetcher crls = fetcher.allowingPlainHttp();
            assertThat(crls.get(url("crl.test", "/ok"), null).bodyAsString()).isEqualTo("hello");
            // Every other rule still applies: internal addresses, redirects to them, other schemes.
            assertThatThrownBy(() -> crls.get(url("other.test", "/ok"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class);
            assertThatThrownBy(() -> crls.get(URI.create("http://other.test/ok"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("non-public address");
            assertThatThrownBy(() -> crls.get(url("crl.test", "/to-internal"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("internal.test");
            assertThatThrownBy(() -> crls.get(URI.create("ftp://crl.test/x.crl"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class);
            // Plain http only on port 80 for public hosts, so the open relays cannot probe other ports.
            assertThatThrownBy(() -> crls.get(URI.create("http://crl.public.example:8081/x.crl"), null))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("port 80");
        }
        assertThat(hits).hasValue(2); // /ok and the redirect; the internal target was never reached
    }

    @Test
    void oversizeBodyIsRefused() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of("public.test")), LOOPBACK_DNS)) {
            assertThatThrownBy(() -> fetcher.get(url("public.test", "/big"), null))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("exceeds 1024 bytes");
        }
    }

    @Test
    void theCapsEndTheFetchInsteadOfReadingOn() throws IOException {
        TrustProperties.Http cfg = config(List.of("public.test"));
        cfg.setTotalTimeout(java.time.Duration.ofMillis(700));
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(cfg, LOOPBACK_DNS)) {
            // Too large: refused at the limit, without reading the rest of a body that never ends.
            long start = System.nanoTime();
            assertThatThrownBy(() -> fetcher.get(url("public.test", "/endless"), null))
                    .isInstanceOf(IOException.class).hasMessageContaining("exceeds 1024 bytes");
            assertThat(java.time.Duration.ofNanos(System.nanoTime() - start)).isLessThan(LONG_BEFORE_THE_BODY_ENDS);

            // Too slow: the total time holds although every single read succeeds.
            cfg.setMaxResponseBytes(8 * 1024 * 1024);
            start = System.nanoTime();
            assertThatThrownBy(() -> fetcher.get(url("public.test", "/endless"), null))
                    .isInstanceOf(IOException.class).hasMessageContaining("took longer than");
            assertThat(java.time.Duration.ofNanos(System.nanoTime() - start)).isLessThan(LONG_BEFORE_THE_BODY_ENDS);

            // A redirect with a body that never ends is followed without reading that body.
            start = System.nanoTime();
            assertThat(fetcher.get(url("public.test", "/endless-redirect"), null).bodyAsString()).isEqualTo("hello");
            assertThat(java.time.Duration.ofNanos(System.nanoTime() - start)).isLessThan(LONG_BEFORE_THE_BODY_ENDS);

            // The fetcher still works afterwards: no connection is left occupied.
            assertThat(fetcher.get(url("public.test", "/ok"), null).bodyAsString()).isEqualTo("hello");
        }
    }

    @Test
    void onlyHttpsUnlessTheHostIsAllowedPlainHttp() throws IOException {
        try (SafeHttpFetcher fetcher = new SafeHttpFetcher(config(List.of("other.test")), LOOPBACK_DNS)) {
            assertThatThrownBy(() -> fetcher.execute(new HttpFetcher.Request("GET", url("other.test", "/ok"), Map.of(), null, null)))
                    .isInstanceOf(SafeHttpFetcher.BlockedRequestException.class)
                    .hasMessageContaining("Only https");
        }
        assertThat(hits).hasValue(0);
    }

    @Test
    void embeddedAndSpecialAddressesAreInternal() throws UnknownHostException {
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("10.1.2.3"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("100.64.0.1"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("169.254.169.254"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("fd00::1"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("64:ff9b::7f00:1"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("2002:a00:1::1"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("::ffff:192.168.1.1"))).isTrue();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("93.184.215.14"))).isFalse();
        assertThat(SafeHttpFetcher.isInternal(InetAddress.getByName("2606:4700::6810:84e5"))).isFalse();
    }
}
