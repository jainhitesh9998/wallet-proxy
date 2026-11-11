package io.vctrust.trust.server.service;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.policy.ClientProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Who changed what the service trusts: one line per change, and per refused attempt, on its own logger so it can be
 * routed and kept. Values that a caller chose (ids, framework names) are written as JSON strings: quoted, with
 * quotes, backslashes and control characters escaped, so that no value can pass for a field or for a line of its own.
 */
final class AuditLog {

    private static final Logger audit = LoggerFactory.getLogger("io.vctrust.trust.audit");

    private AuditLog() {
    }

    static void sourceRefresh(ClientProfile admin, String sourceId) {
        audit.info("client={} action=refresh-source source={}", admin.clientId(), quoted(sourceId));
    }

    /** @param kind {@code entity} or {@code anchor} */
    static void managedPut(ClientProfile admin, String kind, String id, Object framework) {
        audit.info("client={} action=put-{} id={} framework={}", admin.clientId(), kind, quoted(id), quoted(framework));
    }

    /** @param kind {@code entity} or {@code anchor} */
    static void managedDelete(ClientProfile admin, String kind, String id) {
        audit.info("client={} action=delete-{} id={}", admin.clientId(), kind, quoted(id));
    }

    static void cachesCleared(ClientProfile admin) {
        audit.info("client={} action=clear-caches", admin.clientId());
    }

    /** An operator action asked for by a client that is not an operator. */
    static void refused(ClientProfile client, String action) {
        audit.warn("client={} action={} refused=not-an-admin", client == null ? "none" : quoted(client.clientId()), action);
    }

    static String quoted(Object value) {
        return value == null ? "null" : Json.write(String.valueOf(value));
    }
}
