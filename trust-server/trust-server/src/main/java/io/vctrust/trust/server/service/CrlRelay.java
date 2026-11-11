package io.vctrust.trust.server.service;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.server.config.TrustProperties;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;

/**
 * The CRL relay: the CRL at a URL a client names, unmodified. A CRL is signed by its issuer and verified by the
 * client, so the relay need not be trusted for it. Decides whether the relay is on, which URLs may be asked for, and
 * what a failed fetch means to the caller.
 */
public class CrlRelay {

    /** A relayed CRL, and for how long the copy may be reused. */
    public record Relayed(byte[] der, Duration maxAge) {
    }

    private final CrlService crls;
    private final TrustProperties.Revocation revocation;
    private final Clock clock;

    public CrlRelay(CrlService crls, TrustProperties.Revocation revocation, Clock clock) {
        this.crls = crls;
        this.revocation = revocation;
        this.clock = clock;
    }

    public Relayed relay(String url) {
        if (!revocation.isEnabled() || !revocation.isRelayCrls()) {
            throw ServiceException.notFound("The CRL relay is disabled");
        }
        RelayTarget.check(url);
        CrlService.Relayed r;
        try {
            r = crls.relay(url);
        } catch (HttpFetcher.BlockedException e) {
            throw ServiceException.invalidRequest("invalid_request", e.getMessage());
        } catch (IOException e) {
            if (e.getCause() instanceof IllegalArgumentException) {
                throw ServiceException.upstreamFailed("invalid_crl", e.getMessage());
            }
            throw ServiceException.upstreamFailed("upstream_unavailable", "CRL unavailable: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw ServiceException.upstreamFailed("invalid_crl", e.getMessage());
        }
        return new Relayed(r.der(), Freshness.remaining(r.expiresAt(), clock));
    }
}
