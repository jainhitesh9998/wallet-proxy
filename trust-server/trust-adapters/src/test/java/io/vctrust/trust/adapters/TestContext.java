package io.vctrust.trust.adapters;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.testing.FakeHttp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/** SourceContext backed by in-memory resources, the classpath and a {@link FakeHttp}. */
final class TestContext implements SourceContext {
    final FakeHttp http = new FakeHttp();
    final Map<String, byte[]> resources = new HashMap<>();

    TestContext put(String location, String content) {
        resources.put(location, content.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    TestContext put(String location, byte[] content) {
        resources.put(location, content);
        return this;
    }

    @Override
    public HttpFetcher http() {
        return http;
    }

    @Override
    public ResourceLoader resources() {
        return location -> {
            if (resources.containsKey(location)) {
                return resources.get(location);
            }
            if (location.startsWith("classpath:")) {
                try (InputStream in = TestContext.class.getResourceAsStream("/" + location.substring(10))) {
                    if (in == null) throw new IOException("No resource " + location);
                    return in.readAllBytes();
                }
            }
            HttpFetcher.Response r = http.execute(HttpFetcher.Request.get(URI.create(location), null));
            if (!r.isSuccess()) throw new IOException("HTTP " + r.status() + " for " + location);
            return r.body();
        };
    }

    @Override
    public Clock clock() {
        return Clock.systemUTC();
    }
}
