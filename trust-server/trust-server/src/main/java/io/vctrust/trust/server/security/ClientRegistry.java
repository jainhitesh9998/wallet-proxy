package io.vctrust.trust.server.security;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.config.TrustProperties;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Configured clients (wallets, verifiers, admins) keyed by the SHA-256 of their API key. */
public class ClientRegistry {

    private final Map<String, ClientProfile> byKeyHash = new LinkedHashMap<>();
    private final Map<String, ClientProfile> byId = new LinkedHashMap<>();
    private final ClientProfile anonymous;

    public ClientRegistry(TrustProperties props) {
        for (TrustProperties.Client c : props.getClients()) {
            if (c.getApiKey() == null || c.getApiKey().isBlank()) {
                throw new IllegalArgumentException("Client " + c.getId() + " has no api-key");
            }
            ClientProfile p = new ClientProfile(c.getId(), c.getName() == null ? c.getId() : c.getName(),
                    Set.copyOf(c.getFrameworks()), c.isStrictAuthorization(), c.isAllowUnregisteredMetadata(), c.isAdmin());
            byKeyHash.put(hash(c.getApiKey()), p);
            byId.put(c.getId(), p);
        }
        TrustProperties.Anonymous a = props.getAnonymous();
        anonymous = a.isEnabled()
                ? new ClientProfile("anonymous", "Anonymous", Set.copyOf(a.getFrameworks()), false, a.isAllowUnregisteredMetadata(), false)
                : null;
    }

    public Optional<ClientProfile> byApiKey(String apiKey) {
        return Optional.ofNullable(byKeyHash.get(hash(apiKey)));
    }

    public Optional<ClientProfile> anonymous() {
        return Optional.ofNullable(anonymous);
    }

    public Collection<ClientProfile> all() {
        return byId.values();
    }

    private static String hash(String s) {
        return HexFormat.of().formatHex(Hashes.sha256(s.getBytes(StandardCharsets.UTF_8)));
    }
}
