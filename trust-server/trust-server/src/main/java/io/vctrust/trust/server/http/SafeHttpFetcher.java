package io.vctrust.trust.server.http;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Outbound HTTP for everything the service fetches on behalf of clients. Defends against SSRF: only https
 * (http for explicitly allowed development hosts, and for CRLs through {@link #allowingPlainHttp()}), no private /
 * loopback / link-local / CGNAT targets unless allowed, redirects re-validated hop by hop, response size and total
 * time capped.
 * <p>
 * Host names are resolved exactly once per connection, by a {@link DnsResolver} that drops the request when any
 * address is internal. The socket then connects to the addresses that were checked, so a DNS answer that changes
 * between the check and the connect (DNS rebinding) cannot reach an internal address. TLS SNI and hostname
 * verification still use the host name. System proxy settings are ignored, since a proxy would resolve the name
 * itself.
 */
public class SafeHttpFetcher implements HttpFetcher, Closeable {

    private static final Logger log = LoggerFactory.getLogger(SafeHttpFetcher.class);

    private final CloseableHttpClient client;
    private final TrustProperties.Http cfg;
    private final Set<String> httpHosts;
    private final Set<String> privateHosts;

    public SafeHttpFetcher(TrustProperties.Http cfg) {
        this(cfg, SystemDefaultDnsResolver.INSTANCE);
    }

    /** {@code dns} answers the raw lookups (tests substitute it); the internal-address check is always applied. */
    SafeHttpFetcher(TrustProperties.Http cfg, DnsResolver dns) {
        this.cfg = cfg;
        this.httpHosts = lower(cfg.getHttpAllowedHosts());
        this.privateHosts = lower(cfg.getAllowedPrivateHosts());
        this.client = HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setDnsResolver(new GuardedDnsResolver(dns))
                        .setDefaultConnectionConfig(ConnectionConfig.custom()
                                .setConnectTimeout(Timeout.of(cfg.getConnectTimeout()))
                                .setSocketTimeout(Timeout.of(cfg.getReadTimeout()))
                                .build())
                        .setMaxConnPerRoute(10)
                        .setMaxConnTotal(100)
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableContentCompression() // bodies are passed on byte for byte; no decompression bombs
                .setUserAgent(cfg.getUserAgent())
                .build();
    }

    private static Set<String> lower(List<String> l) {
        return l.stream().map(s -> s.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public Response execute(Request request) throws IOException {
        return execute(request, false);
    }

    /**
     * This fetcher, also for plain http URLs; every other check (addresses, redirects, size, time) is unchanged. Only
     * for signed objects whose integrity does not rest on TLS: CRLs, whose distribution points are mostly http
     * (RFC 5280 §4.2.1.13; a CRL is verified against its issuer).
     */
    public HttpFetcher allowingPlainHttp() {
        return request -> execute(request, true);
    }

    private Response execute(Request request, boolean plainHttp) throws IOException {
        URI uri = request.uri();
        String method = request.method();
        Duration timeout = request.timeout() != null ? request.timeout() : cfg.getReadTimeout();
        long deadline = System.nanoTime() + cfg.getTotalTimeout().toNanos();
        for (int hop = 0; hop <= cfg.getMaxRedirects(); hop++) {
            check(uri, plainHttp);
            HttpUriRequestBase req = "POST".equals(method) ? new HttpPost(uri) : new HttpGet(uri);
            request.headers().forEach(req::setHeader);
            if ("POST".equals(method) && request.body() != null) {
                req.setEntity(new ByteArrayEntity(request.body(), null));
            }
            HttpClientContext context = HttpClientContext.create();
            context.setRequestConfig(RequestConfig.custom().setResponseTimeout(Timeout.of(timeout)).setRedirectsEnabled(false).build());
            try (ClassicHttpResponse r = client.executeOpen(null, req, context)) {
                int status = r.getCode();
                Header location = r.getFirstHeader("Location");
                if (status >= 300 && status < 400 && location != null) {
                    uri = uri.resolve(location.getValue());
                    if (status == 303) {
                        method = "GET";
                    }
                    continue;
                }
                byte[] body = read(r.getEntity(), uri, deadline);
                log.debug("{} {} -> {} ({} bytes)", method, uri, status, body.length);
                return new Response(status, headers(r), body, uri);
            } catch (InternalAddressException e) {
                throw new BlockedRequestException("Refusing to fetch " + uri + ": " + e.getMessage());
            }
        }
        throw new IOException("Too many redirects fetching " + request.uri());
    }

    private byte[] read(HttpEntity entity, URI uri, long deadline) throws IOException {
        if (entity == null) {
            return new byte[0];
        }
        int max = cfg.getMaxResponseBytes();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = entity.getContent()) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) {
                if (out.size() + n > max) {
                    throw new IOException("Response from " + uri + " exceeds " + max + " bytes");
                }
                out.write(buf, 0, n);
                if (System.nanoTime() > deadline) {
                    throw new IOException("Response from " + uri + " took longer than " + cfg.getTotalTimeout());
                }
            }
        }
        return out.toByteArray();
    }

    private static Map<String, List<String>> headers(ClassicHttpResponse r) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        for (Header header : r.getHeaders()) {
            h.computeIfAbsent(header.getName(), k -> new ArrayList<>()).add(header.getValue());
        }
        return h;
    }

    /** Scheme and host rules; the address check happens at connect time, in {@link GuardedDnsResolver}. */
    void check(URI uri, boolean plainHttp) throws IOException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            throw new BlockedRequestException("URL has no host: " + uri);
        }
        if (!"https".equals(scheme) && !("http".equals(scheme) && (plainHttp || httpHosts.contains(host)))) {
            throw new BlockedRequestException("Only https URLs may be fetched (got " + uri + ")");
        }
        // Plain http for signed objects stays on the standard port, so the relays cannot be used to probe other services.
        if ("http".equals(scheme) && !httpHosts.contains(host) && uri.getPort() != -1 && uri.getPort() != 80 && !privateAllowed(host)) {
            throw new BlockedRequestException("Plain http is fetched only on port 80 (got " + uri + ")");
        }
    }

    private boolean privateAllowed(String host) {
        return cfg.isAllowPrivateNetworks() || privateHosts.contains(host.toLowerCase(Locale.ROOT));
    }

    static boolean isInternal(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress()
                || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            int b0 = b[0] & 0xff;
            int b1 = b[1] & 0xff;
            return b0 == 0 || (b0 == 100 && b1 >= 64 && b1 < 128) || (b0 == 192 && b1 == 0 && (b[2] & 0xff) == 0)
                    || (b0 == 198 && (b1 == 18 || b1 == 19)) || b0 >= 240;
        }
        if (a instanceof Inet6Address) {
            if ((b[0] & 0xfe) == 0xfc) {
                return true; // unique local fc00::/7
            }
            // IPv4 embedded by NAT64 (64:ff9b::/96) or 6to4 (2002::/16): judge the IPv4 address
            boolean nat64 = b[0] == 0 && b[1] == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b
                    && java.util.Arrays.equals(b, 4, 12, new byte[8], 0, 8);
            if (nat64) {
                return isInternal(ipv4(b, 12));
            }
            if (b[0] == 0x20 && b[1] == 0x02) {
                return isInternal(ipv4(b, 2));
            }
        }
        return false;
    }

    private static InetAddress ipv4(byte[] b, int offset) {
        try {
            return InetAddress.getByAddress(java.util.Arrays.copyOfRange(b, offset, offset + 4));
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() throws IOException {
        client.close();
    }

    /** Resolves once and refuses (as a failed lookup) a host with any internal address, unless it is allowed. */
    private final class GuardedDnsResolver implements DnsResolver {
        private final DnsResolver delegate;

        GuardedDnsResolver(DnsResolver delegate) {
            this.delegate = delegate;
        }

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            InetAddress[] addresses = delegate.resolve(host);
            if (!privateAllowed(host)) {
                for (InetAddress a : addresses) {
                    if (isInternal(a)) {
                        throw new InternalAddressException(host + " resolves to non-public address " + a.getHostAddress());
                    }
                }
            }
            return addresses;
        }

        @Override
        public List<InetSocketAddress> resolve(String host, int port) throws UnknownHostException {
            List<InetSocketAddress> out = new ArrayList<>();
            for (InetAddress a : resolve(host)) {
                out.add(new InetSocketAddress(a, port));
            }
            return out;
        }

        @Override
        public String resolveCanonicalHostname(String host) throws UnknownHostException {
            return delegate.resolveCanonicalHostname(host);
        }
    }

    /** A lookup refused by the guard; surfaces as {@link BlockedRequestException}. */
    static final class InternalAddressException extends UnknownHostException {
        InternalAddressException(String message) {
            super(message);
        }
    }

    /** Raised when a URL is refused by policy (maps to HTTP 400/403 at the API). */
    public static class BlockedRequestException extends HttpFetcher.BlockedException {
        public BlockedRequestException(String message) {
            super(message);
        }
    }
}
