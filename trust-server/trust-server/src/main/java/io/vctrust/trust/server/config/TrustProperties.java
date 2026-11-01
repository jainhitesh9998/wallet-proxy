package io.vctrust.trust.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** All {@code trust.*} configuration. See {@code application.yml} for a documented example. */
@ConfigurationProperties("trust")
public class TrustProperties {

    private Service service = new Service();
    private Http http = new Http();
    private Cache cache = new Cache();
    private Did did = new Did();
    private Anonymous anonymous = new Anonymous();
    private List<Framework> frameworks = new ArrayList<>();
    private List<Source> sources = new ArrayList<>();
    private List<Client> clients = new ArrayList<>();
    private List<String> corsOrigins = new ArrayList<>(List.of("*"));

    public static class Service {
        /** Identifier of this service; {@code iss} of signed responses and snapshots. */
        private String issuer = "http://localhost:8090";
        /** JWK file holding the EC P-256 signing key; generated on first start if missing. */
        private String signingKeyFile = "./data/signing-key.jwk";
        private Duration decisionTtl = Duration.ofHours(1);
        private Duration snapshotTtl = Duration.ofHours(24);
        private Duration signedResponseTtl = Duration.ofMinutes(10);

        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getSigningKeyFile() { return signingKeyFile; }
        public void setSigningKeyFile(String signingKeyFile) { this.signingKeyFile = signingKeyFile; }
        public Duration getDecisionTtl() { return decisionTtl; }
        public void setDecisionTtl(Duration decisionTtl) { this.decisionTtl = decisionTtl; }
        public Duration getSnapshotTtl() { return snapshotTtl; }
        public void setSnapshotTtl(Duration snapshotTtl) { this.snapshotTtl = snapshotTtl; }
        public Duration getSignedResponseTtl() { return signedResponseTtl; }
        public void setSignedResponseTtl(Duration signedResponseTtl) { this.signedResponseTtl = signedResponseTtl; }
    }

    public static class Http {
        private Duration connectTimeout = Duration.ofSeconds(3);
        private Duration readTimeout = Duration.ofSeconds(10);
        private int maxResponseBytes = 8 * 1024 * 1024;
        private int maxRedirects = 3;
        /** Allow outbound requests to private, loopback and link-local addresses (development only). */
        private boolean allowPrivateNetworks = false;
        /** Hosts exempt from the private-network check. */
        private List<String> allowedPrivateHosts = new ArrayList<>();
        /** Hosts that may be fetched over plain http (development only). */
        private List<String> httpAllowedHosts = new ArrayList<>();
        private String userAgent = "vc-trust-service/0.1";

        public Duration getConnectTimeout() { return connectTimeout; }
        public void setConnectTimeout(Duration v) { this.connectTimeout = v; }
        public Duration getReadTimeout() { return readTimeout; }
        public void setReadTimeout(Duration v) { this.readTimeout = v; }
        public int getMaxResponseBytes() { return maxResponseBytes; }
        public void setMaxResponseBytes(int v) { this.maxResponseBytes = v; }
        public int getMaxRedirects() { return maxRedirects; }
        public void setMaxRedirects(int v) { this.maxRedirects = v; }
        public boolean isAllowPrivateNetworks() { return allowPrivateNetworks; }
        public void setAllowPrivateNetworks(boolean v) { this.allowPrivateNetworks = v; }
        public List<String> getAllowedPrivateHosts() { return allowedPrivateHosts; }
        public void setAllowedPrivateHosts(List<String> v) { this.allowedPrivateHosts = v; }
        public List<String> getHttpAllowedHosts() { return httpAllowedHosts; }
        public void setHttpAllowedHosts(List<String> v) { this.httpAllowedHosts = v; }
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String v) { this.userAgent = v; }
    }

    public static class Cache {
        private Duration metadataMinTtl = Duration.ofMinutes(1);
        private Duration metadataMaxTtl = Duration.ofHours(1);
        private Duration didTtl = Duration.ofMinutes(15);
        private Duration negativeTtl = Duration.ofMinutes(1);
        /** How long a stale entry may be served when the upstream is unavailable. */
        private Duration staleIfError = Duration.ofHours(24);
        private long maxEntries = 10_000;

        public Duration getMetadataMinTtl() { return metadataMinTtl; }
        public void setMetadataMinTtl(Duration v) { this.metadataMinTtl = v; }
        public Duration getMetadataMaxTtl() { return metadataMaxTtl; }
        public void setMetadataMaxTtl(Duration v) { this.metadataMaxTtl = v; }
        public Duration getDidTtl() { return didTtl; }
        public void setDidTtl(Duration v) { this.didTtl = v; }
        public Duration getNegativeTtl() { return negativeTtl; }
        public void setNegativeTtl(Duration v) { this.negativeTtl = v; }
        public Duration getStaleIfError() { return staleIfError; }
        public void setStaleIfError(Duration v) { this.staleIfError = v; }
        public long getMaxEntries() { return maxEntries; }
        public void setMaxEntries(long v) { this.maxEntries = v; }
    }

    public static class Did {
        /** Optional DIF Universal Resolver for methods without a native driver. */
        private String universalResolverUrl;
        private List<String> universalResolverMethods = new ArrayList<>(List.of("*"));
        /** Per-method registry URL templates with a {did} placeholder, e.g. ebsi. */
        private Map<String, String> registries = new LinkedHashMap<>();

        public Map<String, String> getRegistries() { return registries; }
        public void setRegistries(Map<String, String> v) { this.registries = v; }

        public String getUniversalResolverUrl() { return universalResolverUrl; }
        public void setUniversalResolverUrl(String v) { this.universalResolverUrl = v; }
        public List<String> getUniversalResolverMethods() { return universalResolverMethods; }
        public void setUniversalResolverMethods(List<String> v) { this.universalResolverMethods = v; }
    }

    public static class Anonymous {
        private boolean enabled = true;
        private List<String> frameworks = new ArrayList<>();
        private boolean allowUnregisteredMetadata = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public List<String> getFrameworks() { return frameworks; }
        public void setFrameworks(List<String> v) { this.frameworks = v; }
        public boolean isAllowUnregisteredMetadata() { return allowUnregisteredMetadata; }
        public void setAllowUnregisteredMetadata(boolean v) { this.allowUnregisteredMetadata = v; }
    }

    public static class Framework {
        private String id;
        private String name;
        private String description;
        private String governanceUri;
        private Map<String, String> attributes = new LinkedHashMap<>();

        public String getId() { return id; }
        public void setId(String v) { this.id = v; }
        public String getName() { return name; }
        public void setName(String v) { this.name = v; }
        public String getDescription() { return description; }
        public void setDescription(String v) { this.description = v; }
        public String getGovernanceUri() { return governanceUri; }
        public void setGovernanceUri(String v) { this.governanceUri = v; }
        public Map<String, String> getAttributes() { return attributes; }
        public void setAttributes(Map<String, String> v) { this.attributes = v; }
    }

    public static class Source {
        private String id;
        private String type;
        private String framework;
        private Duration refresh = Duration.ofHours(1);
        private boolean enabled = true;
        private Map<String, Object> properties = new LinkedHashMap<>();

        public String getId() { return id; }
        public void setId(String v) { this.id = v; }
        public String getType() { return type; }
        public void setType(String v) { this.type = v; }
        public String getFramework() { return framework; }
        public void setFramework(String v) { this.framework = v; }
        public Duration getRefresh() { return refresh; }
        public void setRefresh(Duration v) { this.refresh = v; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> v) { this.properties = v; }
    }

    public static class Client {
        private String id;
        private String name;
        private String apiKey;
        private List<String> frameworks = new ArrayList<>();
        private boolean strictAuthorization = false;
        private boolean allowUnregisteredMetadata = true;
        private boolean admin = false;

        public String getId() { return id; }
        public void setId(String v) { this.id = v; }
        public String getName() { return name; }
        public void setName(String v) { this.name = v; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String v) { this.apiKey = v; }
        public List<String> getFrameworks() { return frameworks; }
        public void setFrameworks(List<String> v) { this.frameworks = v; }
        public boolean isStrictAuthorization() { return strictAuthorization; }
        public void setStrictAuthorization(boolean v) { this.strictAuthorization = v; }
        public boolean isAllowUnregisteredMetadata() { return allowUnregisteredMetadata; }
        public void setAllowUnregisteredMetadata(boolean v) { this.allowUnregisteredMetadata = v; }
        public boolean isAdmin() { return admin; }
        public void setAdmin(boolean v) { this.admin = v; }
    }

    public Service getService() { return service; }
    public void setService(Service v) { this.service = v; }
    public Http getHttp() { return http; }
    public void setHttp(Http v) { this.http = v; }
    public Cache getCache() { return cache; }
    public void setCache(Cache v) { this.cache = v; }
    public Did getDid() { return did; }
    public void setDid(Did v) { this.did = v; }
    public Anonymous getAnonymous() { return anonymous; }
    public void setAnonymous(Anonymous v) { this.anonymous = v; }
    public List<Framework> getFrameworks() { return frameworks; }
    public void setFrameworks(List<Framework> v) { this.frameworks = v; }
    public List<Source> getSources() { return sources; }
    public void setSources(List<Source> v) { this.sources = v; }
    public List<Client> getClients() { return clients; }
    public void setClients(List<Client> v) { this.clients = v; }
    public List<String> getCorsOrigins() { return corsOrigins; }
    public void setCorsOrigins(List<String> v) { this.corsOrigins = v; }
}
