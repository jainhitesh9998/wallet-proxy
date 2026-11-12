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
 * Delegates resolution to an upstream DIF Universal Resolver ({@code GET /1.0/identifiers/{did}}), for
 * methods without a native driver. The upstream is treated as untrusted transport: results are tagged with
 * {@code resolver} metadata so clients can see that resolution was delegated.
 */
public final class UniversalResolverDriver implements DidMethodDriver {

    private final HttpFetcher http;
    private final URI baseUrl;
    private final Set<String> methods;

    /** @param methods methods to delegate, or {@code ["*"]} for all methods without a native driver */
    public UniversalResolverDriver(HttpFetcher http, URI baseUrl, Set<String> methods) {
        this.http = http;
        this.baseUrl = baseUrl;
        this.methods = methods == null || methods.isEmpty() ? Set.of("*") : Set.copyOf(methods);
    }

    @Override
    public Set<String> methods() {
        return methods;
    }

    @Override
    @SuppressWarnings("unchecked")
    public DidResolutionResult resolve(Did did) {
        String base = baseUrl.toString().replaceAll("/+$", "");
        URI url = URI.create(base + "/1.0/identifiers/" + URLEncoder.encode(did.did(), StandardCharsets.UTF_8));
        HttpFetcher.Response r;
        try {
            r = http.get(url, "application/did-resolution, application/ld+json;profile=\"https://w3id.org/did-resolution\";q=0.9, application/json;q=0.5");
        } catch (IOException e) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "Universal resolver unreachable: " + e.getMessage());
        }
        Map<String, Object> body;
        try {
            body = Json.parseObject(r.body());
        } catch (RuntimeException e) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "Universal resolver returned HTTP " + r.status());
        }
        Map<String, Object> doc;
        Map<String, Object> rm;
        Map<String, Object> dm;
        if (body.containsKey("didDocument") || body.containsKey("didResolutionMetadata")) {
            doc = body.get("didDocument") instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
            rm = new LinkedHashMap<>(body.get("didResolutionMetadata") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of());
            dm = body.get("didDocumentMetadata") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        } else if (r.isSuccess() && body.get("id") instanceof String) {
            doc = body;
            rm = new LinkedHashMap<>();
            dm = Map.of();
        } else {
            String message = "Upstream resolver returned HTTP " + r.status() + (body.get("message") instanceof String m ? ": " + m : "");
            return (r.status() == 404 ? DidResolutionResult.error(DidResolutionResult.NOT_FOUND, message)
                    : DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, message)).withResolutionMetadata("resolver", base);
        }
        if (doc == null || rm.containsKey("error")) {
            String code = DidResolutionResult.normalizeError(rm.get("error"));
            if (code == null) {
                code = r.status() == 404 ? DidResolutionResult.NOT_FOUND : DidResolutionResult.INTERNAL_ERROR;
            }
            // What the resolver says about the DID (not found, invalid, method not supported) is passed on as its answer.
            // An error the DID Resolution binding answers with 500 (the resolver's internal error, an invalid document, a
            // code this service does not know) is a failure of the resolver or of where the DID lives: a 500 from this
            // service's relay means a failure of the service itself, and nothing else.
            String message = "Upstream resolver " + base + " reported " + code;
            return (DidResolutionResult.httpStatus(code) == 500 ? DidResolutionResult.upstreamError(code, message)
                    : DidResolutionResult.error(code, message)).withResolutionMetadata("resolver", base);
        }
        rm.put("resolver", base);
        if (!did.did().equals(doc.get("id"))) {
            return DidResolutionResult.upstreamError(DidResolutionResult.INVALID_DID_DOCUMENT, "Resolved document id does not match DID");
        }
        return DidResolutionResult.success(doc, rm, dm);
    }
}
