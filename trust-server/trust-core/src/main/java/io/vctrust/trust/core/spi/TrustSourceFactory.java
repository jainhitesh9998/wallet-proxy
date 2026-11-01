package io.vctrust.trust.core.spi;

/**
 * Creates {@link TrustSource}s of one {@link #type()}. Factories are discovered with
 * {@link java.util.ServiceLoader} (and, in the server, as Spring beans), which is the extension point for
 * new list formats.
 */
public interface TrustSourceFactory {

    String type();

    TrustSource create(SourceDefinition definition, SourceContext context);
}
