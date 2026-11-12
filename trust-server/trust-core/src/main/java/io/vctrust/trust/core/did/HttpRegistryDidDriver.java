package io.vctrust.trust.core.did;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.spi.HttpFetcher;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Resolves a DID method through its registry's HTTP API, given a URL template with a {@code {did}} placeholder,
 * e.g. EBSI: {@code https://api-pilot.ebsi.eu/did-registry/v5/identifiers/{did}}. Accepts either a bare DID
 * document or a DID resolution result in the response.
 */
public final class HttpRegistryDidDriver implements DidMethodDriver {

    private final HttpFetcher http;
    private final String method;
    private final String template;

    public HttpRegistryDidDriver(HttpFetcher http, String method, String template) {
        this.http = http;
        this.method = method;
        this.template = template;
    }

    @Override
    public Set<String> methods() {
        return Set.of(method);
    }

    @Override
    @SuppressWarnings("unchecked")
    public DidResolutionResult resolve(Did did) {
        URI url = URI.create(template.replace("{did}", URLEncoder.encode(did.did(), StandardCharsets.UTF_8)));
        HttpFetcher.Response r;
        try {
            r = http.get(url, "application/did+ld+json, application/did-resolution, application/json");
        } catch (IOException e) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "Registry unreachable: " + e.getMessage());
        }
        if (r.status() == 404 || r.status() == 400) {
            return DidResolutionResult.error(DidResolutionResult.NOT_FOUND, "Registry returned HTTP " + r.status());
        }
        if (!r.isSuccess()) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "Registry returned HTTP " + r.status());
        }
        Map<String, Object> body;
        try {
            body = Json.parseObject(r.body());
        } catch (RuntimeException e) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INVALID_DID_DOCUMENT, "Registry response is not JSON");
        }
        Map<String, Object> doc = body.get("didDocument") instanceof Map<?, ?> m ? (Map<String, Object>) m : body;
        if (!did.did().equals(doc.get("id"))) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INVALID_DID_DOCUMENT, "Registry document id does not match DID");
        }
        Map<String, Object> rm = new LinkedHashMap<>();
        rm.put("registry", url.getHost());
        r.maxAge().ifPresent(d -> rm.put("maxAgeSeconds", d.toSeconds()));
        return DidResolutionResult.success(doc, rm, Map.of());
    }
}
