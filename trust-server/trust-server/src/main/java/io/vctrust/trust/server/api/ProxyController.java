package io.vctrust.trust.server.api;

import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.service.CrlService;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.StatusListRelay;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

/**
 * The proxy: what a wallet would otherwise fetch from each counterparty, fetched, checked and cached here.
 *
 * <ul>
 * <li>{@code issuer-metadata} and {@code did}: documents that carry no signature of their own. With
 *     {@code Accept: application/jwt} the answer is signed by the service key, so a client verifies it like a
 *     snapshot.</li>
 * <li>{@code crl} and {@code status-list}: objects signed by their issuer, passed through byte for byte; the client
 *     verifies them, so the proxy need not be trusted for them.</li>
 * </ul>
 *
 * Every call tells the service which party a client is dealing with; clients that must not reveal that fetch from
 * the party directly, which is also what they do when the proxy is unavailable.
 */
@RestController
@RequestMapping("/api/v1/proxy")
public class ProxyController {

    static final MediaType PKIX_CRL = MediaType.parseMediaType("application/pkix-crl");

    private final MetadataService metadata;
    private final DidService dids;
    private final CrlService crls;
    private final StatusListRelay statusLists;
    private final ResponseSigner signer;
    private final TrustProperties.Revocation revocation;
    private final Clock clock;

    public ProxyController(MetadataService metadata, DidService dids, CrlService crls, StatusListRelay statusLists,
                           ResponseSigner signer, TrustProperties props, Clock clock) {
        this.metadata = metadata;
        this.dids = dids;
        this.crls = crls;
        this.statusLists = statusLists;
        this.signer = signer;
        this.revocation = props.getRevocation();
        this.clock = clock;
    }

    /** OpenID4VCI issuer and authorization server metadata, validated, with the registry's metadata policy applied. */
    @GetMapping("/issuer-metadata")
    public ResponseEntity<Object> issuerMetadata(ClientProfile client, HttpServletRequest req, @RequestParam String issuer) {
        MetadataService.IssuerMetadataEnvelope env = metadata.issuer(issuer, client);
        return signer.respond(req, client, "trust-metadata+jwt", env, ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(metadata.maxAgeSeconds(env))).cachePrivate())
                .header("X-Trust-Source", env.stale() ? "cache-stale" : "trust-service"));
    }

    /** DID resolution: {@code /api/v1/proxy/did/did:web:issuer.example}; the result has the W3C DID Resolution shape. */
    @GetMapping("/did/**")
    public ResponseEntity<Object> did(ClientProfile client, HttpServletRequest req) {
        String raw = req.getRequestURI();
        String did = raw.substring(raw.indexOf("/proxy/did/") + "/proxy/did/".length());
        if (did.startsWith("did%3A") || did.startsWith("did%3a")) {
            did = URLDecoder.decode(did, StandardCharsets.UTF_8);
        }
        DidResolutionResult r = dids.resolve(did);
        return signer.respond(req, client, "trust-did-resolution+jwt", r.toJson(),
                ResponseEntity.status(DidResolutionResult.httpStatus(r.error().orElse(null))).cacheControl(cacheControl(r)));
    }

    /** The CRL at {@code url}, unmodified. */
    @GetMapping("/crl")
    public ResponseEntity<byte[]> crl(ClientProfile client, @RequestParam String url) {
        if (!revocation.isEnabled() || !revocation.isRelayCrls()) {
            throw ApiException.notFound("The CRL relay is disabled");
        }
        checkUrl(url);
        CrlService.Relayed r;
        try {
            r = crls.relay(url);
        } catch (HttpFetcher.BlockedException e) {
            throw ApiException.badRequest("invalid_request", e.getMessage());
        } catch (IOException e) {
            if (e.getCause() instanceof IllegalArgumentException) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "invalid_crl", e.getMessage());
            }
            throw new ApiException(HttpStatus.BAD_GATEWAY, "upstream_unavailable", "CRL unavailable: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "invalid_crl", e.getMessage());
        }
        return ResponseEntity.ok().contentType(PKIX_CRL).cacheControl(maxAge(r.expiresAt())).body(r.der());
    }

    /** The status list at {@code uri}, byte for byte, with its content type. */
    @GetMapping("/status-list")
    public ResponseEntity<byte[]> statusList(ClientProfile client, HttpServletRequest req, @RequestParam String uri) {
        if (!revocation.isEnabled() || !revocation.isRelayStatusLists()) {
            throw ApiException.notFound("The status list relay is disabled");
        }
        checkUrl(uri);
        StatusListRelay.Relayed r;
        try {
            r = statusLists.fetch(uri, req.getHeader("Accept"));
        } catch (HttpFetcher.BlockedException e) {
            throw ApiException.badRequest("invalid_request", e.getMessage());
        } catch (StatusListRelay.InvalidStatusListException e) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "invalid_status_list", e.getMessage());
        } catch (IOException e) {
            throw new ApiException(HttpStatus.BAD_GATEWAY, "upstream_unavailable", "Status list unavailable: " + e.getMessage());
        }
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(r.contentType()))
                .cacheControl(maxAge(r.expiresAt()).cachePrivate()).body(r.body());
    }

    private CacheControl maxAge(Instant expiresAt) {
        Duration d = Duration.between(clock.instant(), expiresAt);
        return CacheControl.maxAge(d.isNegative() ? Duration.ZERO : d);
    }

    private CacheControl cacheControl(DidResolutionResult r) {
        if (!r.isSuccess()) {
            return CacheControl.maxAge(Duration.ofSeconds(30));
        }
        if (r.didResolutionMetadata().get("cache") instanceof Map<?, ?> m && m.get("expiresAt") instanceof String exp) {
            return maxAge(Instant.parse(exp)).cachePrivate();
        }
        return CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate();
    }

    private static void checkUrl(String url) {
        try {
            URI u = URI.create(url);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!("https".equals(scheme) || "http".equals(scheme)) || u.getHost() == null) {
                throw ApiException.badRequest("invalid_request", "An absolute http(s) URL is required");
            }
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("invalid_request", "Malformed URL: " + e.getMessage());
        }
    }
}
