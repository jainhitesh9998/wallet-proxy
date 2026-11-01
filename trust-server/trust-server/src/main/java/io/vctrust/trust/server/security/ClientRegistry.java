package io.vctrust.trust.server.security;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.config.TrustProperties;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Configured clients (wallets, verifiers, admins) and the credentials that identify them: API keys (held as
 * SHA-256), authorization-server client ids, and TLS client certificate thumbprints.
 */
public class ClientRegistry {

    private final Map<String, ClientProfile> byKeyHash = new LinkedHashMap<>();
    private final Map<String, ClientProfile> byOauthClientId = new LinkedHashMap<>();
    private final Map<String, ClientProfile> byCertificate = new LinkedHashMap<>();
    private final Map<String, ClientProfile> byId = new LinkedHashMap<>();
    private final Map<String, Integer> requestsPerMinute = new LinkedHashMap<>();
    private final ClientProfile anonymous;

    public ClientRegistry(TrustProperties props) {
        boolean oauth = props.getAuth().getOauth().isEnabled();
        boolean apiKeys = props.getAuth().isApiKeys();
        for (TrustProperties.Client c : props.getClients()) {
            if (c.getId() == null || c.getId().isBlank()) {
                throw new IllegalArgumentException("A client has no id");
            }
            if (byId.containsKey(c.getId())) {
                throw new IllegalArgumentException("Duplicate client id " + c.getId());
            }
            ClientProfile p = new ClientProfile(c.getId(), c.getName() == null ? c.getId() : c.getName(),
                    Set.copyOf(c.getFrameworks()), c.isStrictAuthorization(), c.isAllowUnregisteredMetadata(), c.isAdmin(),
                    c.isRequireRevocationStatus(), c.isRequireSignedIssuerMetadata(), c.isAllowRelaxedProfiles());
            boolean credential = false;
            if (apiKeys && c.getApiKey() != null && !c.getApiKey().isBlank()) {
                put(byKeyHash, hash(c.getApiKey()), p, "API key");
                credential = true;
            }
            if (apiKeys && c.getApiKeySha256() != null && !c.getApiKeySha256().isBlank()) {
                String h = c.getApiKeySha256().trim().toLowerCase(Locale.ROOT);
                if (!h.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Client " + c.getId() + ": api-key-sha256 must be 64 hex digits");
                }
                put(byKeyHash, h, p, "API key");
                credential = true;
            }
            if (oauth) {
                put(byOauthClientId, c.getOauthClientId() == null || c.getOauthClientId().isBlank() ? c.getId() : c.getOauthClientId(), p,
                        "oauth-client-id");
                credential = true;
            }
            for (String t : c.getCertificateSha256()) {
                put(byCertificate, normalizeThumbprint(t, c.getId()), p, "certificate");
                credential = true;
            }
            if (!credential) {
                throw new IllegalArgumentException("Client " + c.getId() + " has no usable credential: configure api-key, "
                        + "api-key-sha256 or certificate-sha256, or enable trust.auth.oauth");
            }
            byId.put(c.getId(), p);
            if (c.getRequestsPerMinute() != null) {
                requestsPerMinute.put(c.getId(), c.getRequestsPerMinute());
            }
        }
        TrustProperties.Anonymous a = props.getAnonymous();
        anonymous = a.isEnabled()
                ? new ClientProfile("anonymous", "Anonymous", Set.copyOf(a.getFrameworks()), false, a.isAllowUnregisteredMetadata(), false)
                : null;
    }

    private static void put(Map<String, ClientProfile> index, String key, ClientProfile p, String what) {
        ClientProfile previous = index.putIfAbsent(key, p);
        if (previous != null) {
            throw new IllegalArgumentException("Clients " + previous.clientId() + " and " + p.clientId() + " share the same " + what);
        }
    }

    public Optional<ClientProfile> byApiKey(String apiKey) {
        return Optional.ofNullable(byKeyHash.get(hash(apiKey)));
    }

    public Optional<ClientProfile> byOauthClientId(String clientId) {
        return Optional.ofNullable(byOauthClientId.get(clientId));
    }

    /** @param sha256Hex SHA-256 of the certificate's DER encoding, lowercase hex */
    public Optional<ClientProfile> byCertificate(String sha256Hex) {
        return Optional.ofNullable(byCertificate.get(sha256Hex));
    }

    public Optional<ClientProfile> anonymous() {
        return Optional.ofNullable(anonymous);
    }

    /** The client's own rate, if it overrides the default. */
    public Optional<Integer> requestsPerMinute(String clientId) {
        return Optional.ofNullable(requestsPerMinute.get(clientId));
    }

    public Collection<ClientProfile> all() {
        return byId.values();
    }

    /** Hex (optionally colon-separated) or base64url SHA-256 thumbprint → lowercase hex. */
    static String normalizeThumbprint(String t, String clientId) {
        String s = t.trim().replace(":", "").toLowerCase(Locale.ROOT);
        if (s.matches("[0-9a-f]{64}")) {
            return s;
        }
        try {
            byte[] b = Base64.getUrlDecoder().decode(t.trim().replace("=", ""));
            if (b.length == 32) {
                return HexFormat.of().formatHex(b);
            }
        } catch (IllegalArgumentException ignored) {
            // fall through
        }
        throw new IllegalArgumentException("Client " + clientId + ": certificate-sha256 '" + t + "' is not a SHA-256 thumbprint");
    }

    private static String hash(String s) {
        return HexFormat.of().formatHex(Hashes.sha256(s.getBytes(StandardCharsets.UTF_8)));
    }
}
