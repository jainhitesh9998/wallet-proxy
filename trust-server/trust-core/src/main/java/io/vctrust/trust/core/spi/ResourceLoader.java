package io.vctrust.trust.core.spi;

import java.io.IOException;

/** Loads configuration resources ({@code classpath:}, {@code file:} or {@code https:} locations). */
@FunctionalInterface
public interface ResourceLoader {
    byte[] load(String location) throws IOException;

    /**
     * The loader for locations that a document from elsewhere names (a list fetched over the network, an entry sent
     * to the admin API): web locations only. Such a document must not be able to make the service read its own
     * files or classpath; where it may fetch from is then decided by the outbound HTTP policy.
     */
    static ResourceLoader remoteOnly(ResourceLoader loader) {
        return location -> {
            if (location == null || !(location.startsWith("https://") || location.startsWith("http://"))) {
                throw new IOException("Only an http(s) location may be named here, not " + location);
            }
            return loader.load(location);
        };
    }

    /** Whether a location is fetched over the network (as opposed to a file or classpath resource of this host). */
    static boolean isRemote(String location) {
        return location != null && (location.startsWith("https://") || location.startsWith("http://"));
    }
}
