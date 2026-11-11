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

    /**
     * Whether this list is older than {@code held}: issued earlier, or numbered lower. A list that is older than
     * the one already loaded is a replay (of a state before a withdrawal, say) and is not to replace it.
     */
    public boolean olderThan(ListInfo held) {
        if (held == null) {
            return false;
        }
        if (issuedAt != null && held.issuedAt() != null && issuedAt.isBefore(held.issuedAt())) {
            return true;
        }
        Long mine = number(sequence);
        Long theirs = number(held.sequence());
        return mine != null && theirs != null && mine < theirs;
    }

    private static Long number(String sequence) {
        if (sequence == null || !sequence.matches("[0-9]{1,18}")) {
            return null;
        }
        return Long.valueOf(sequence);
    }
}
