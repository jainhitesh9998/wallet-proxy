package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.service.CrlService;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Revocation data: the trust anchor CRLs the service holds, and two opt-in relays — CRLs (signed by their CA) and
 * credential status lists (signed by their issuer). Relayed objects are passed through unmodified; clients verify
 * them, so the relays need not be trusted, only the privacy trade-off accepted (the service sees what is fetched).
 */
@RestController
@RequestMapping("/api/v1/revocation")
public class RevocationController {

    static final MediaType PKIX_CRL = MediaType.parseMediaType("application/pkix-crl");

    private final CrlService crls;
    private final StatusListRelay statusLists;
    private final TrustProperties.Revocation cfg;
    private final Clock clock;

    public RevocationController(CrlService crls, StatusListRelay statusLists, TrustProperties props, Clock clock) {
        this.crls = crls;
        this.statusLists = statusLists;
        this.cfg = props.getRevocation();
        this.clock = clock;
    }

    /** The trust anchor CRLs held for the anchors this client can see. */
    @GetMapping(value = "/crls", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> crls(ClientProfile client) {
        return crls.listing(a -> client.accepts(a.frameworkId()));
    }

    /** CRL relay: the CRL at {@code url}, unmodified (the client verifies it against the issuing CA). */
    @GetMapping("/crl")
    public ResponseEntity<byte[]> crl(ClientProfile client, @RequestParam String url) {
        if (!cfg.isEnabled() || !cfg.isRelayCrls()) {
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

    /** Status list relay (opt-in on the client): the list at {@code uri}, byte for byte, with its content type. */
    @GetMapping("/status-list")
    public ResponseEntity<byte[]> statusList(ClientProfile client, HttpServletRequest req, @RequestParam String uri) {
        if (!cfg.isEnabled() || !cfg.isRelayStatusLists()) {
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
