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
    private Revocation revocation = new Revocation();
    private Anonymous anonymous = new Anonymous();
    private Auth auth = new Auth();
    private List<Framework> frameworks = new ArrayList<>();
    private List<Source> sources = new ArrayList<>();
    private List<Client> clients = new ArrayList<>();
    private List<String> corsOrigins = new ArrayList<>(List.of("*"));

    public static class Service {
        /** Identifier of this service; {@code iss} of signed responses and snapshots. */
        private String issuer = "http://localhost:8090";
        /** JWK file holding the EC P-256 signing key; generated on first start if missing (shorthand for signing-key.file). */
        private String signingKeyFile = "./data/signing-key.jwk";
        private SigningKey signingKey = new SigningKey();
        private Duration decisionTtl = Duration.ofHours(1);
        private Duration snapshotTtl = Duration.ofHours(24);
        private Duration signedResponseTtl = Duration.ofMinutes(10);
        /** Largest request body accepted, in bytes (an entry sent to the admin API may carry certificates and a CRL). */
        private long maxRequestBytes = 2 * 1024 * 1024;
        /** Embed the DID documents of registered DID identifiers in snapshots (offline, private verification). */
        private boolean snapshotDidDocuments = true;
        private int snapshotMaxDidDocuments = 200;
        /** How long a snapshot build waits for DID documents and for JSON-LD contexts; what is slower is left out of that snapshot. */
        private Duration snapshotDidDeadline = Duration.ofSeconds(5);
        /** JSON-LD context documents are embedded in a snapshot up to this total; past it only their digests are. */
        private int snapshotMaxContextBytes = 256 * 1024;
        /** How often a client's snapshot content is re-derived (DID documents and contexts change without the registry). */
        private Duration snapshotRecheck = Duration.ofMinutes(1);

        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getSigningKeyFile() { return signingKeyFile; }
        public void setSigningKeyFile(String signingKeyFile) { this.signingKeyFile = signingKeyFile; }
        public SigningKey getSigningKey() { return signingKey; }
        public void setSigningKey(SigningKey v) { this.signingKey = v; }
        public Duration getDecisionTtl() { return decisionTtl; }
        public void setDecisionTtl(Duration decisionTtl) { this.decisionTtl = decisionTtl; }
        public Duration getSnapshotTtl() { return snapshotTtl; }
        public void setSnapshotTtl(Duration snapshotTtl) { this.snapshotTtl = snapshotTtl; }
        public Duration getSignedResponseTtl() { return signedResponseTtl; }
        public long getMaxRequestBytes() { return maxRequestBytes; }
        public void setMaxRequestBytes(long v) { this.maxRequestBytes = v; }
        public void setSignedResponseTtl(Duration signedResponseTtl) { this.signedResponseTtl = signedResponseTtl; }
        public boolean isSnapshotDidDocuments() { return snapshotDidDocuments; }
        public void setSnapshotDidDocuments(boolean v) { this.snapshotDidDocuments = v; }
        public int getSnapshotMaxDidDocuments() { return snapshotMaxDidDocuments; }
        public void setSnapshotMaxDidDocuments(int v) { this.snapshotMaxDidDocuments = v; }
        public Duration getSnapshotDidDeadline() { return snapshotDidDeadline; }
        public void setSnapshotDidDeadline(Duration v) { this.snapshotDidDeadline = v; }
        public int getSnapshotMaxContextBytes() { return snapshotMaxContextBytes; }
        public void setSnapshotMaxContextBytes(int v) { this.snapshotMaxContextBytes = v; }
        public Duration getSnapshotRecheck() { return snapshotRecheck; }
        public void setSnapshotRecheck(Duration v) { this.snapshotRecheck = v; }
    }

    /**
     * The service's ES256 (P-256) signing key for snapshots and signed responses. {@code jwk-file} suits development;
     * {@code keystore} reads a PKCS#12 / JKS file; {@code pkcs11} uses a key that never leaves an HSM. Retired keys are
     * listed in {@code previous-keys} so clients pinning several thumbprints can rotate without an outage.
     */
    public static class SigningKey {
        /** {@code jwk-file}, {@code keystore} or {@code pkcs11}. */
        private String type = "jwk-file";
        /** jwk-file: the JWK file; defaults to {@code trust.service.signing-key-file}. */
        private String file;
        /** keystore: the PKCS#12 or JKS file. */
        private String keystore;
        private String keystoreType = "PKCS12";
        /** keystore: the store password. */
        private String password;
        /** keystore: the key entry password; defaults to {@code password}. */
        private String keyPassword;
        /** keystore / pkcs11: the key entry alias (required when the store holds more than one key). */
        private String alias;
        /** pkcs11: SunPKCS11 provider configuration file (library, slot). */
        private String pkcs11Config;
        /** pkcs11: the token PIN. */
        private String pin;
        /** {@code kid} published for the key; defaults to its RFC 7638 thumbprint. */
        private String keyId;
        /** Public JWKs of retired keys, still published in the JWKS: inline JSON, a file path, {@code file:} or {@code classpath:}. */
        private List<String> previousKeys = new ArrayList<>();

        public String getType() { return type; }
        public void setType(String v) { this.type = v; }
        public String getFile() { return file; }
        public void setFile(String v) { this.file = v; }
        public String getKeystore() { return keystore; }
        public void setKeystore(String v) { this.keystore = v; }
        public String getKeystoreType() { return keystoreType; }
        public void setKeystoreType(String v) { this.keystoreType = v; }
        public String getPassword() { return password; }
        public void setPassword(String v) { this.password = v; }
        public String getKeyPassword() { return keyPassword; }
        public void setKeyPassword(String v) { this.keyPassword = v; }
        public String getAlias() { return alias; }
        public void setAlias(String v) { this.alias = v; }
        public String getPkcs11Config() { return pkcs11Config; }
        public void setPkcs11Config(String v) { this.pkcs11Config = v; }
        public String getPin() { return pin; }
        public void setPin(String v) { this.pin = v; }
        public String getKeyId() { return keyId; }
        public void setKeyId(String v) { this.keyId = v; }
        public List<String> getPreviousKeys() { return previousKeys; }
        public void setPreviousKeys(List<String> v) { this.previousKeys = v; }
    }

    public static class Http {
        private Duration connectTimeout = Duration.ofSeconds(3);
        private Duration readTimeout = Duration.ofSeconds(10);
        /** Upper bound on one fetch including the body download (a slow, dripping response is cut off). */
        private Duration totalTimeout = Duration.ofSeconds(60);
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
        public Duration getTotalTimeout() { return totalTimeout; }
        public void setTotalTimeout(Duration v) { this.totalTimeout = v; }
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

    /** The proxy's caches (issuer metadata, DID documents, CRLs, status lists, JSON-LD contexts). */
    public static class Cache {
        private Duration metadataMinTtl = Duration.ofMinutes(1);
        private Duration metadataMaxTtl = Duration.ofHours(1);
        private Duration didTtl = Duration.ofMinutes(15);
        /** JSON-LD contexts are meant to be immutable; a changed one is logged. */
        private Duration contextTtl = Duration.ofHours(24);
        /** Serve {@code /api/v1/proxy/context}: contexts a snapshot does not carry, relayed from this cache. */
        private boolean relayContexts = true;
        /** How long a failure is remembered, and how long a failed refresh is not retried. */
        private Duration negativeTtl = Duration.ofSeconds(30);
        /** How long a stale entry may be served when the upstream is unavailable. */
        private Duration staleIfError = Duration.ofHours(24);
        /** Bound on each cache, in bytes of cached content. */
        private long maxBytes = 32L * 1024 * 1024;
        /** Largest issuer metadata document, DID document or JSON-LD context the proxy will hold. */
        private int maxDocumentBytes = 1024 * 1024;

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
        /** Settings every proxy cache shares; {@code refreshInBackground}: serve a stale entry at once and refresh it off the request. */
        public io.vctrust.trust.server.cache.ResourceCache.Settings settings(boolean refreshInBackground) {
            return new io.vctrust.trust.server.cache.ResourceCache.Settings(maxBytes, negativeTtl, staleIfError, refreshInBackground);
        }

        public Duration getContextTtl() { return contextTtl; }
        public void setContextTtl(Duration v) { this.contextTtl = v; }
        public boolean isRelayContexts() { return relayContexts; }
        public void setRelayContexts(boolean v) { this.relayContexts = v; }
        public long getMaxBytes() { return maxBytes; }
        public void setMaxBytes(long v) { this.maxBytes = v; }
        public int getMaxDocumentBytes() { return maxDocumentBytes; }
        public void setMaxDocumentBytes(int v) { this.maxDocumentBytes = v; }
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

    /** Certificate revocation (CRLs) and the CRL / status list relays. */
    public static class Revocation {
        private boolean enabled = true;
        /** Anchor CRLs are re-fetched after min(refresh, nextUpdate - now), at least a minute apart. */
        private Duration refresh = Duration.ofHours(1);
        private int maxCrlBytes = 1024 * 1024;
        /** Larger CRLs are not embedded in snapshots (clients fetch them per their lookup policy). */
        private int snapshotMaxCrlBytes = 256 * 1024;
        /** Fetch the CRL distribution points of non-anchor issuers during server-side checks. */
        private boolean fetchOnDemand = true;
        /**
         * Fetch each anchor's CRL from its configured URLs or the anchor's own distribution point. False: only CRLs
         * pushed with an anchor are held (a service without outbound access, and tests that must not use the network).
         */
        private boolean fetchAnchorCrls = true;
        private boolean relayCrls = true;
        private boolean relayStatusLists = true;
        private Duration statusListMaxTtl = Duration.ofHours(1);
        private Duration statusListDefaultTtl = Duration.ofMinutes(5);
        private int maxStatusListBytes = 2 * 1024 * 1024;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public Duration getRefresh() { return refresh; }
        public void setRefresh(Duration v) { this.refresh = v; }
        public int getMaxCrlBytes() { return maxCrlBytes; }
        public void setMaxCrlBytes(int v) { this.maxCrlBytes = v; }
        public int getSnapshotMaxCrlBytes() { return snapshotMaxCrlBytes; }
        public void setSnapshotMaxCrlBytes(int v) { this.snapshotMaxCrlBytes = v; }
        public boolean isFetchAnchorCrls() { return fetchAnchorCrls; }
        public void setFetchAnchorCrls(boolean v) { this.fetchAnchorCrls = v; }
        public boolean isFetchOnDemand() { return fetchOnDemand; }
        public void setFetchOnDemand(boolean v) { this.fetchOnDemand = v; }
        public boolean isRelayCrls() { return relayCrls; }
        public void setRelayCrls(boolean v) { this.relayCrls = v; }
        public boolean isRelayStatusLists() { return relayStatusLists; }
        public void setRelayStatusLists(boolean v) { this.relayStatusLists = v; }
        public Duration getStatusListMaxTtl() { return statusListMaxTtl; }
        public void setStatusListMaxTtl(Duration v) { this.statusListMaxTtl = v; }
        public Duration getStatusListDefaultTtl() { return statusListDefaultTtl; }
        public void setStatusListDefaultTtl(Duration v) { this.statusListDefaultTtl = v; }
        public int getMaxStatusListBytes() { return maxStatusListBytes; }
        public void setMaxStatusListBytes(int v) { this.maxStatusListBytes = v; }
    }

    /** Requests without credentials. Off unless an operator turns it on and names the frameworks they may see. */
    public static class Anonymous {
        private boolean enabled = false;
        private List<String> frameworks = new ArrayList<>();
        private boolean allowUnregisteredMetadata = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public List<String> getFrameworks() { return frameworks; }
        public void setFrameworks(List<String> v) { this.frameworks = v; }
        public boolean isAllowUnregisteredMetadata() { return allowUnregisteredMetadata; }
        public void setAllowUnregisteredMetadata(boolean v) { this.allowUnregisteredMetadata = v; }
    }

    /**
     * How clients authenticate. API keys suit development; production deployments use OAuth 2.0 access tokens
     * (RFC 9068 JWTs from the operator's authorization server) and/or TLS client certificates.
     */
    public static class Auth {
        /** Accept API keys ({@code Authorization: Bearer <key>} or {@code X-API-Key}). */
        private boolean apiKeys = true;
        private OAuth oauth = new OAuth();
        private Mtls mtls = new Mtls();
        private RateLimit rateLimit = new RateLimit();
        /**
         * Peer addresses or CIDRs of reverse proxies whose {@code X-Forwarded-For} names the caller (for per-address
         * rate limits). Forwarded headers from any other peer are ignored.
         */
        private List<String> trustedProxies = new ArrayList<>();

        public boolean isApiKeys() { return apiKeys; }
        public void setApiKeys(boolean v) { this.apiKeys = v; }
        public OAuth getOauth() { return oauth; }
        public void setOauth(OAuth v) { this.oauth = v; }
        public Mtls getMtls() { return mtls; }
        public void setMtls(Mtls v) { this.mtls = v; }
        public RateLimit getRateLimit() { return rateLimit; }
        public void setRateLimit(RateLimit v) { this.rateLimit = v; }
        public List<String> getTrustedProxies() { return trustedProxies; }
        public void setTrustedProxies(List<String> v) { this.trustedProxies = v; }
    }

    /** JWT access tokens (RFC 9068) from an authorization server, e.g. obtained with the client credentials grant. */
    public static class OAuth {
        private boolean enabled = false;
        /** Required {@code iss}. */
        private String issuer;
        /** Accepted {@code aud} values; empty means {@code trust.service.issuer}. */
        private List<String> audiences = new ArrayList<>();
        /** The authorization server's JWKS: https URL (cached, refreshed on unknown kid), {@code file:} or {@code classpath:}. */
        private String jwksUri;
        /** Accepted JWS algorithms (ES256/384/512, RS256/384/512, PS256/384/512, EdDSA). */
        private List<String> algorithms = new ArrayList<>(List.of("ES256", "RS256"));
        /** Accepted JOSE {@code typ} values; {@code jwt} also admits tokens without {@code typ}. */
        private List<String> tokenTypes = new ArrayList<>(List.of("at+jwt", "jwt"));
        /** Claims naming the client, tried in order; matched against a client's {@code oauth-client-id} (default its id). */
        private List<String> clientIdClaims = new ArrayList<>(List.of("client_id", "azp"));
        /** Scope every token must carry ({@code scope} string or {@code scp} array); empty for none. */
        private String requiredScope;
        private Duration clockSkew = Duration.ofSeconds(60);

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String v) { this.issuer = v; }
        public List<String> getAudiences() { return audiences; }
        public void setAudiences(List<String> v) { this.audiences = v; }
        public String getJwksUri() { return jwksUri; }
        public void setJwksUri(String v) { this.jwksUri = v; }
        public List<String> getAlgorithms() { return algorithms; }
        public void setAlgorithms(List<String> v) { this.algorithms = v; }
        public List<String> getTokenTypes() { return tokenTypes; }
        public void setTokenTypes(List<String> v) { this.tokenTypes = v; }
        public List<String> getClientIdClaims() { return clientIdClaims; }
        public void setClientIdClaims(List<String> v) { this.clientIdClaims = v; }
        public String getRequiredScope() { return requiredScope; }
        public void setRequiredScope(String v) { this.requiredScope = v; }
        public Duration getClockSkew() { return clockSkew; }
        public void setClockSkew(Duration v) { this.clockSkew = v; }
    }

    /**
     * TLS client certificates: from this server's TLS connector, or from a header set by a TLS-terminating proxy.
     * Certificate-bound access tokens (RFC 8705 {@code cnf.x5t#S256}) are always checked against the presented
     * certificate; {@code enabled} additionally lets a certificate alone authenticate a client.
     */
    public static class Mtls {
        private boolean enabled = false;
        /** Header holding the URL-encoded PEM client certificate (nginx {@code $ssl_client_escaped_cert}); empty for none. */
        private String certificateHeader;
        /** Peer addresses or CIDRs of proxies whose certificate header is believed; a header from anyone else is ignored. */
        private List<String> trustedProxies = new ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public String getCertificateHeader() { return certificateHeader; }
        public void setCertificateHeader(String v) { this.certificateHeader = v; }
        public List<String> getTrustedProxies() { return trustedProxies; }
        public void setTrustedProxies(List<String> v) { this.trustedProxies = v; }
    }

    /** Per-client token bucket; anonymous callers are limited per address. */
    public static class RateLimit {
        private boolean enabled = true;
        private int requestsPerMinute = 600;
        /** Requests a client may make at once before the per-minute rate applies. */
        private int burst = 100;
        private boolean exemptAdmin = true;
        /** Requests one caller may have in progress at once (0: no limit); more are answered 429. */
        private int maxConcurrent = 32;
        /** Refused credentials per minute from one address before further ones are turned away unseen (0: no limit). */
        private int refusedPerMinute = 60;

        public int getMaxConcurrent() { return maxConcurrent; }
        public void setMaxConcurrent(int v) { this.maxConcurrent = v; }
        public int getRefusedPerMinute() { return refusedPerMinute; }
        public void setRefusedPerMinute(int v) { this.refusedPerMinute = v; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int v) { this.requestsPerMinute = v; }
        public int getBurst() { return burst; }
        public void setBurst(int v) { this.burst = v; }
        public boolean isExemptAdmin() { return exemptAdmin; }
        public void setExemptAdmin(boolean v) { this.exemptAdmin = v; }
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
        /** The service is not ready (and serves no snapshot) until every required source has loaded once. */
        private boolean required = true;
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
        public boolean isRequired() { return required; }
        public void setRequired(boolean v) { this.required = v; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> v) { this.properties = v; }
    }

    public static class Client {
        private String id;
        private String name;
        /** API key in clear (development). */
        private String apiKey;
        /** SHA-256 of the API key, hex, so the configuration holds no secret. */
        private String apiKeySha256;
        /** The client's id at the authorization server, when it differs from {@code id}. */
        private String oauthClientId;
        /** SHA-256 thumbprints (hex or base64url) of the TLS client certificates that authenticate this client. */
        private List<String> certificateSha256 = new ArrayList<>();
        /** Overrides {@code trust.auth.rate-limit.requests-per-minute} for this client. */
        private Integer requestsPerMinute;
        private List<String> frameworks = new ArrayList<>();
        private boolean strictAuthorization = false;
        /** Whether the metadata proxy fetches issuers that are in none of the client's frameworks. */
        private boolean allowUnregisteredMetadata = false;
        private boolean admin = false;
        /** An undeterminable certificate revocation status fails validation (otherwise a warning). */
        private boolean requireRevocationStatus = false;
        /** Issuer metadata must be signed by a certificate under a credential-issuer anchor (HAIP 1.0 §4.1 ecosystems). */
        private boolean requireSignedIssuerMetadata = false;

        public String getId() { return id; }
        public void setId(String v) { this.id = v; }
        public String getName() { return name; }
        public void setName(String v) { this.name = v; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String v) { this.apiKey = v; }
        public String getApiKeySha256() { return apiKeySha256; }
        public void setApiKeySha256(String v) { this.apiKeySha256 = v; }
        public String getOauthClientId() { return oauthClientId; }
        public void setOauthClientId(String v) { this.oauthClientId = v; }
        public List<String> getCertificateSha256() { return certificateSha256; }
        public void setCertificateSha256(List<String> v) { this.certificateSha256 = v; }
        public Integer getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(Integer v) { this.requestsPerMinute = v; }
        public List<String> getFrameworks() { return frameworks; }
        public void setFrameworks(List<String> v) { this.frameworks = v; }
        public boolean isStrictAuthorization() { return strictAuthorization; }
        public void setStrictAuthorization(boolean v) { this.strictAuthorization = v; }
        public boolean isAllowUnregisteredMetadata() { return allowUnregisteredMetadata; }
        public void setAllowUnregisteredMetadata(boolean v) { this.allowUnregisteredMetadata = v; }
        public boolean isAdmin() { return admin; }
        public void setAdmin(boolean v) { this.admin = v; }
        public boolean isRequireRevocationStatus() { return requireRevocationStatus; }
        public void setRequireRevocationStatus(boolean v) { this.requireRevocationStatus = v; }
        public boolean isRequireSignedIssuerMetadata() { return requireSignedIssuerMetadata; }
        public void setRequireSignedIssuerMetadata(boolean v) { this.requireSignedIssuerMetadata = v; }
    }

    public Service getService() { return service; }
    public void setService(Service v) { this.service = v; }
    public Http getHttp() { return http; }
    public void setHttp(Http v) { this.http = v; }
    public Cache getCache() { return cache; }
    public void setCache(Cache v) { this.cache = v; }
    public Did getDid() { return did; }
    public void setDid(Did v) { this.did = v; }
    public Revocation getRevocation() { return revocation; }
    public void setRevocation(Revocation v) { this.revocation = v; }
    public Anonymous getAnonymous() { return anonymous; }
    public void setAnonymous(Anonymous v) { this.anonymous = v; }
    public Auth getAuth() { return auth; }
    public void setAuth(Auth v) { this.auth = v; }
    public List<Framework> getFrameworks() { return frameworks; }
    public void setFrameworks(List<Framework> v) { this.frameworks = v; }
    public List<Source> getSources() { return sources; }
    public void setSources(List<Source> v) { this.sources = v; }
    public List<Client> getClients() { return clients; }
    public void setClients(List<Client> v) { this.clients = v; }
    public List<String> getCorsOrigins() { return corsOrigins; }
    public void setCorsOrigins(List<String> v) { this.corsOrigins = v; }
}
