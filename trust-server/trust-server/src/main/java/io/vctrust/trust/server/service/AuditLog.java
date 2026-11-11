package io.vctrust.trust.server.service;

import io.vctrust.trust.core.policy.ClientProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Who changed what the service trusts: one line per change, on its own logger so it can be routed and kept. */
final class AuditLog {

    private static final Logger audit = LoggerFactory.getLogger("io.vctrust.trust.audit");

    private AuditLog() {
    }

    static void sourceRefresh(ClientProfile admin, String sourceId) {
        audit.info("client={} action=refresh-source source={}", admin.clientId(), sourceId);
    }

    /** @param kind {@code entity} or {@code anchor} */
    static void managedPut(ClientProfile admin, String kind, String id, Object framework) {
        audit.info("client={} action=put-{} id={} framework={}", admin.clientId(), kind, id, framework);
    }

    /** @param kind {@code entity} or {@code anchor} */
    static void managedDelete(ClientProfile admin, String kind, String id) {
        audit.info("client={} action=delete-{} id={}", admin.clientId(), kind, id);
    }

    static void cachesCleared(ClientProfile admin) {
        audit.info("client={} action=clear-caches", admin.clientId());
    }
}
