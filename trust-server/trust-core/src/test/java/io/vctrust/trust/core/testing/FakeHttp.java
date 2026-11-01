package io.vctrust.trust.core.testing;

import io.vctrust.trust.core.spi.HttpFetcher;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link HttpFetcher}: register canned responses by URL, record requests. */
public final class FakeHttp implements HttpFetcher {

    private final Map<String, Response> routes = new LinkedHashMap<>();
    private final Map<String, Response> jsonOnly = new LinkedHashMap<>();
    public final List<Request> requests = new ArrayList<>();

    /** A response served only to requests that accept nothing but application/json (content negotiation). */
    public FakeHttp jsonForPlainAccept(String url, String body) {
        jsonOnly.put(url, new Response(200, Map.of("Content-Type", List.of("application/json")), body.getBytes(StandardCharsets.UTF_8), URI.create(url)));
        return this;
    }

    public FakeHttp json(String url, String body) {
        return respond(url, 200, "application/json", body.getBytes(StandardCharsets.UTF_8));
    }

    public FakeHttp respond(String url, int status, String contentType, byte[] body) {
        routes.put(url, new Response(status, Map.of("Content-Type", List.of(contentType)), body, URI.create(url)));
        return this;
    }

    @Override
    public Response execute(Request request) throws IOException {
        requests.add(request);
        Response r = "application/json".equals(request.headers().get("Accept")) && jsonOnly.containsKey(request.uri().toString())
                ? jsonOnly.get(request.uri().toString()) : routes.get(request.uri().toString());
        if (r == null) {
            return new Response(404, Map.of("Content-Type", List.of("text/plain")), "not found".getBytes(), request.uri());
        }
        return r;
    }
}
