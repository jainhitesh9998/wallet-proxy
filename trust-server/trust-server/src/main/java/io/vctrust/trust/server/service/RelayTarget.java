package io.vctrust.trust.server.service;

import java.net.URI;
import java.util.Locale;

/** Which URLs a client may ask a relay for. */
final class RelayTarget {

    private RelayTarget() {
    }

    /** @throws ServiceException {@code invalid_request} unless {@code url} is an absolute http(s) URL */
    static void check(String url) {
        try {
            URI u = URI.create(url);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!("https".equals(scheme) || "http".equals(scheme)) || u.getHost() == null) {
                throw ServiceException.invalidRequest("invalid_request", "An absolute http(s) URL is required");
            }
        } catch (IllegalArgumentException e) {
            throw ServiceException.invalidRequest("invalid_request", "Malformed URL: " + e.getMessage());
        }
    }
}
