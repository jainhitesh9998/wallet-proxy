package io.vctrust.trust.core.spi;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Outbound HTTP abstraction. The server implementation enforces SSRF protection, size limits and timeouts;
 * adapters and resolvers never open sockets themselves.
 */
public interface HttpFetcher {

    Response execute(Request request) throws IOException;

    default Response get(URI uri, String accept) throws IOException {
        return execute(Request.get(uri, accept));
    }

    record Request(String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout) {
        public Request {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
        }

        public static Request get(URI uri, String accept) {
            return new Request("GET", uri, accept == null ? Map.of() : Map.of("Accept", accept), null, null);
        }

        public static Request post(URI uri, String contentType, byte[] body, String accept) {
            return new Request("POST", uri, accept == null ? Map.of("Content-Type", contentType)
                    : Map.of("Content-Type", contentType, "Accept", accept), body, null);
        }

        public Request withHeader(String name, String value) {
            var h = new java.util.LinkedHashMap<>(headers);
            h.put(name, value);
            return new Request(method, uri, h, body, timeout);
        }
    }

    record Response(int status, Map<String, List<String>> headers, byte[] body, URI finalUri) {

        public Optional<String> header(String name) {
            return headers.entrySet().stream()
                    .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
                    .flatMap(e -> e.getValue().stream())
                    .findFirst();
        }

        public String contentType() {
            return header("Content-Type").map(v -> v.split(";")[0].trim().toLowerCase(Locale.ROOT)).orElse("");
        }

        public boolean isSuccess() {
            return status >= 200 && status < 300;
        }

        public String bodyAsString() {
            return body == null ? "" : new String(body, StandardCharsets.UTF_8);
        }

        /** {@code max-age} from Cache-Control, if present. */
        public Optional<Duration> maxAge() {
            return header("Cache-Control").flatMap(cc -> {
                for (String part : cc.split(",")) {
                    String p = part.trim().toLowerCase(Locale.ROOT);
                    if (p.startsWith("max-age=")) {
                        try {
                            return Optional.of(Duration.ofSeconds(Long.parseLong(p.substring(8))));
                        } catch (NumberFormatException ignored) {
                            return Optional.empty();
                        }
                    }
                    if (p.equals("no-store") || p.equals("no-cache")) {
                        return Optional.of(Duration.ZERO);
                    }
                }
                return Optional.empty();
            });
        }
    }

    /** Thrown for non-2xx responses where a caller requires success. */
    final class HttpStatusException extends IOException {
        private final int status;

        public HttpStatusException(URI uri, int status) {
            super("HTTP " + status + " from " + uri);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    /** Thrown when a URL is refused by the fetcher's security policy (SSRF guard, scheme rules). */
    class BlockedException extends IOException {
        public BlockedException(String message) {
            super(message);
        }
    }

    /** Executes and throws {@link HttpStatusException} unless the response is 2xx. */
    default Response fetchOk(Request request) throws IOException {
        Response r = execute(request);
        if (!r.isSuccess()) {
            throw new HttpStatusException(request.uri(), r.status());
        }
        return r;
    }
}
