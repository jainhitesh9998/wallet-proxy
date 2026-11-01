package io.vctrust.trust.core.spi;

import java.time.Clock;

/** Services made available to trust sources by the host application. */
public interface SourceContext {

    HttpFetcher http();

    ResourceLoader resources();

    Clock clock();
}
