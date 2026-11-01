package io.vctrust.trust.core.spi;

import java.io.IOException;

/** Loads configuration resources ({@code classpath:}, {@code file:} or {@code https:} locations). */
@FunctionalInterface
public interface ResourceLoader {
    byte[] load(String location) throws IOException;
}
