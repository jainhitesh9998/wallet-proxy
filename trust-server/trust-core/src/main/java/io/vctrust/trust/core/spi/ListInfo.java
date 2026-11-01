package io.vctrust.trust.core.spi;

import java.time.Instant;
import java.util.Map;

/**
 * Metadata about a loaded list: its own sequence number, issue / next-update times and whether its
 * signature was verified. {@code nextUpdate} lets the source manager schedule refreshes.
 */
public record ListInfo(String issuer, String sequence, Instant issuedAt, Instant nextUpdate,
                       SignatureStatus signature, Map<String, Object> details) {

    public enum SignatureStatus { VERIFIED, NOT_SIGNED, NOT_CHECKED, INVALID }

    public ListInfo {
        signature = signature == null ? SignatureStatus.NOT_CHECKED : signature;
        details = details == null ? Map.of() : Map.copyOf(details);
    }

    public static ListInfo unsigned() {
        return new ListInfo(null, null, null, null, SignatureStatus.NOT_SIGNED, Map.of());
    }
}
