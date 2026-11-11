package io.vctrust.trust.core.did;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.spi.HttpFetcher;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * did:web (W3C CCG did:web). {@code did:web:host%3Aport:a:b} resolves to {@code https://host:port/a/b/did.json};
 * a bare host resolves to {@code /.well-known/did.json}. Plain http is used only for hosts explicitly
 * allowed (local development).
 */
public final class DidWebDriver implements DidMethodDriver {

    private final HttpFetcher http;
    private final Set<String> httpAllowedHosts;

    public DidWebDriver(HttpFetcher http, Set<String> httpAllowedHosts) {
        this.http = http;
        this.httpAllowedHosts = httpAllowedHosts == null ? Set.of() : httpAllowedHosts;
    }

    @Override
    public Set<String> methods() {
        return Set.of("web");
    }

    /**
     * The URL of the DID document (did:web, "Read"): a host with an optional port, then path segments. The first
     * part of the identifier may decode to nothing else: a path, a query or userinfo there would let the DID name
     * any resource of any host as its document. Client libraries apply the same rule.
     */
    public URI documentUrl(Did did) {
        String[] parts = did.methodSpecificId().split(":", -1);
        String hostPort = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
        if (!HOST_PORT.matcher(hostPort).matches()) {
            throw new IllegalArgumentException("did:web host is not a host name with an optional port");
        }
        String host = hostPort.contains(":") ? hostPort.substring(0, hostPort.indexOf(':')) : hostPort;
        String scheme = httpAllowedHosts.contains(host) ? "http" : "https";
        StringBuilder path = new StringBuilder();
        if (parts.length == 1) {
            path.append("/.well-known/did.json");
        } else {
            for (int i = 1; i < parts.length; i++) {
                String segment = URLDecoder.decode(parts[i], StandardCharsets.UTF_8);
                if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || NOT_IN_A_SEGMENT.matcher(segment).find()) {
                    throw new IllegalArgumentException("did:web path segment is not a plain segment");
                }
                path.append('/').append(URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20"));
            }
            path.append("/did.json");
        }
        return URI.create(scheme + "://" + hostPort + path);
    }

    private static final Pattern HOST_PORT = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?");
    private static final Pattern NOT_IN_A_SEGMENT = Pattern.compile("[/?#\\\\\\s]");

    @Override
    public DidResolutionResult resolve(Did did) {
        URI url;
        try {
            url = documentUrl(did);
        } catch (IllegalArgumentException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        }
        HttpFetcher.Response r;
        try {
            r = http.get(url, "application/did+json, application/did+ld+json, application/json");
        } catch (java.net.UnknownHostException e) {
            // A name that does not resolve right now is an outage until proven otherwise: only the host itself,
            // answering 404 or 410, says that the document is gone.
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, "Host of " + url + " does not resolve");
        } catch (HttpFetcher.BlockedException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        } catch (IOException e) {
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, "Fetching " + url + " failed: " + e.getMessage());
        }
        if (r.status() == 404 || r.status() == 410) {
            return DidResolutionResult.error(DidResolutionResult.NOT_FOUND, "HTTP " + r.status() + " from " + url);
        }
        if (!r.isSuccess()) {
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, "HTTP " + r.status() + " from " + url);
        }
        Map<String, Object> doc;
        try {
            doc = Json.parseObject(r.body());
        } catch (RuntimeException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID_DOCUMENT, "did.json is not a JSON object");
        }
        if (!did.did().equals(doc.get("id"))) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID_DOCUMENT,
                    "DID document id '" + doc.get("id") + "' does not match " + did.did());
        }
        Map<String, Object> rm = new LinkedHashMap<>();
        rm.put("retrieved", Instant.now().toString());
        rm.put("documentUrl", url.toString());
        r.maxAge().ifPresent(d -> rm.put("maxAgeSeconds", d.toSeconds()));
        return DidResolutionResult.success(doc, rm, Map.of());
    }
}
