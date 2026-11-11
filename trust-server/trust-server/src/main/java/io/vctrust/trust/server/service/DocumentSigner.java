package io.vctrust.trust.server.service;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Signs an answer for the client that asked: the document becomes the {@code data} claim of a JWT signed by the
 * service key, audience-bound to that client, so a client verifies it like a snapshot.
 */
public class DocumentSigner {

    private final ServiceKeyManager keys;
    private final JsonMapper mapper;
    private final Duration ttl;

    /** @param ttl how long a signed answer is valid */
    public DocumentSigner(ServiceKeyManager keys, JsonMapper mapper, Duration ttl) {
        this.keys = keys;
        this.mapper = mapper;
        this.ttl = ttl;
    }

    /** @param typ the JWT's {@code typ}, which names the kind of answer */
    public String sign(String typ, Object document, ClientProfile client) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("data", mapper.convertValue(document, Object.class));
        return keys.sign(typ, claims, ttl, client.clientId());
    }
}
