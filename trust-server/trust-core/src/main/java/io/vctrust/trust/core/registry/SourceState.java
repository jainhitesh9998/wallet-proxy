package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.spi.ListInfo;

import java.time.Instant;
import java.util.List;

/** Health of one trust source: last attempt, last success, error and counts. Serialized for the admin API. */
public record SourceState(String id, String type, String frameworkId, boolean enabled, Instant lastAttempt,
                          Instant lastSuccess, String lastError, int entityCount, int anchorCount,
                          ListInfo listInfo, List<String> warnings, Instant nextRefresh) {

    public boolean healthy() {
        return lastSuccess != null && lastError == null;
    }
}
