package io.vctrust.trust.server.http;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

/** Loads {@code classpath:}, {@code file:} (or plain paths) and {@code http(s):} locations. */
public class TrustResourceLoader implements ResourceLoader {

    private final HttpFetcher http;

    public TrustResourceLoader(HttpFetcher http) {
        this.http = http;
    }

    @Override
    public byte[] load(String location) throws IOException {
        if (location.startsWith("classpath:")) {
            String path = location.substring("classpath:".length()).replaceFirst("^/", "");
            try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path)) {
                if (in == null) {
                    throw new IOException("Classpath resource not found: " + path);
                }
                return in.readAllBytes();
            }
        }
        if (location.startsWith("https://") || location.startsWith("http://")) {
            return http.fetchOk(HttpFetcher.Request.get(URI.create(location), null)).body();
        }
        return Files.readAllBytes(location.startsWith("file:") ? Path.of(URI.create(location)) : Path.of(location));
    }
}
