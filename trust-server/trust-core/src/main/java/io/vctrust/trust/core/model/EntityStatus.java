package io.vctrust.trust.core.model;

/** Lifecycle status of an entity or trust anchor as asserted by its source list. */
public enum EntityStatus {
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
    UNKNOWN;

    public boolean isUsable() {
        return this == ACTIVE;
    }
}
