package io.vctrust.trust.core.spi;

/**
 * A provider of trust information in some external format (ETSI trusted list, VICAL, OpenID Federation,
 * EBSI TIR, a YAML file, ...), normalized into entities and anchors.
 *
 * <p>Implementations must be thread-safe; {@link #load()} may be called concurrently with lookups on a
 * previous result but never concurrently with itself.
 */
public interface TrustSource {

    SourceDefinition definition();

    default String id() {
        return definition().id();
    }

    default String type() {
        return definition().type();
    }

    SourceLoadResult load() throws TrustSourceException;
}
