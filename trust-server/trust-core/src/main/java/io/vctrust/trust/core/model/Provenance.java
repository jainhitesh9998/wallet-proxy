package io.vctrust.trust.core.model;

import java.time.Instant;
import java.util.Map;

/** Where a piece of trust information came from. Carried into every decision as evidence. */
public record Provenance(String sourceId, String sourceType, String frameworkId, String sourceUri,
                         Instant retrievedAt, Map<String, Object> details) {

    public Provenance {
        details = details == null ? Map.of() : Map.copyOf(details);
    }

    public static Provenance of(String sourceId, String sourceType, String frameworkId, String sourceUri,
                                Instant retrievedAt) {
        return new Provenance(sourceId, sourceType, frameworkId, sourceUri, retrievedAt, Map.of());
    }
}
