package io.vctrust.trust.server.http;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Outbound HTTP for everything the service fetches on behalf of clients. Defends against SSRF: only https
 * (http for explicitly allowed development hosts), no private / loopback / link-local / CGNAT targets unless
 * allowed, redirects re-validated hop by hop, response size capped.
 */
public class SafeHttpFetcher implements HttpFetcher {

    private static final Logger log = LoggerFactory.getLogger(SafeHttpFetcher.class);

    private final HttpClient client;
    private final TrustProperties.Http cfg;
    private final Set<String> httpHosts;
    private final Set<String> privateHosts;

    public SafeHttpFetcher(TrustProperties.Http cfg) {
        this.cfg = cfg;
        this.httpHosts = lower(cfg.getHttpAllowedHosts());
        this.privateHosts = lower(cfg.getAllowedPrivateHosts());
        this.client = HttpClient.newBuilder()
                .connectTimeout(cfg.getConnectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static Set<String> lower(List<String> l) {
        return l.stream().map(s -> s.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public Response execute(Request request) throws IOException {
        URI uri = request.uri();
        String method = request.method();
        for (int hop = 0; hop <= cfg.getMaxRedirects(); hop++) {
            check(uri);
            HttpRequest.Builder b = HttpRequest.newBuilder(uri)
                    .timeout(request.timeout() != null ? request.timeout() : cfg.getReadTimeout())
                    .header("User-Agent", cfg.getUserAgent());
            request.headers().forEach(b::header);
            if ("POST".equals(method)) {
                b.POST(request.body() == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(request.body()));
            } else {
                b.GET();
            }
            HttpResponse<InputStream> r;
            try {
                r = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted", e);
            }
            int status = r.statusCode();
            if (status >= 300 && status < 400 && r.headers().firstValue("Location").isPresent()) {
                r.body().close();
                uri = uri.resolve(r.headers().firstValue("Location").get());
                if (status == 303) {
                    method = "GET";
                }
                continue;
            }
            byte[] body;
            try (InputStream in = r.body()) {
                body = in.readNBytes(cfg.getMaxResponseBytes() + 1);
            }
            if (body.length > cfg.getMaxResponseBytes()) {
                throw new IOException("Response from " + uri + " exceeds " + cfg.getMaxResponseBytes() + " bytes");
            }
            log.debug("{} {} -> {} ({} bytes)", method, uri, status, body.length);
            return new Response(status, Map.copyOf(r.headers().map()), body, uri);
        }
        throw new IOException("Too many redirects fetching " + request.uri());
    }

    void check(URI uri) throws IOException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            throw new BlockedRequestException("URL has no host: " + uri);
        }
        if (!"https".equals(scheme) && !("http".equals(scheme) && httpHosts.contains(host))) {
            throw new BlockedRequestException("Only https URLs may be fetched (got " + uri + ")");
        }
        if (cfg.isAllowPrivateNetworks() || privateHosts.contains(host)) {
            return;
        }
        for (InetAddress a : InetAddress.getAllByName(host)) {
            if (isInternal(a)) {
                throw new BlockedRequestException("Refusing to fetch " + uri + ": resolves to non-public address " + a.getHostAddress());
            }
        }
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
            return (b[0] & 0xfe) == 0xfc;
        }
        return false;
    }

    /** Raised when a URL is refused by policy (maps to HTTP 400/403 at the API). */
    public static class BlockedRequestException extends HttpFetcher.BlockedException {
        public BlockedRequestException(String message) {
            super(message);
        }
    }
}
