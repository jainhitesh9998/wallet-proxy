package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.Did;
import io.vctrust.trust.core.did.DidMethodDriver;
import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.server.config.TrustProperties;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/** What the DID relay makes of a resolution: an answer about the DID, a failure where it lives, or its own failure. */
class DidServiceTest {

    static final String DID = "did:web:issuer.example";

    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-12T10:00:00Z");

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    final MutableClock clock = new MutableClock();
    final TrustProperties.Cache cfg = new TrustProperties.Cache();

    DidService service(Function<Did, DidResolutionResult> driver) {
        return new DidService(new DidResolver(List.of(new DidMethodDriver() {
            @Override
            public Set<String> methods() {
                return Set.of("web");
            }

            @Override
            public DidResolutionResult resolve(Did did) {
                return driver.apply(did);
            }
        })), cfg, clock);
    }

    static ServiceException upstreamFailure(DidService service) {
        ServiceException e = catchThrowableOfType(ServiceException.class, () -> service.resolveFromPath(DID));
        assertThat(e).as("a failure upstream").isNotNull();
        return e;
    }

    static DidResolutionResult document() {
        return DidResolutionResult.success(Map.of("id", DID, "verificationMethod", List.of()), Map.of(), Map.of());
    }

    @Test
    void whereTheDidLivesGivingNoAnswerIsAFailureUpstream() {
        DidService service = service(d -> DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "HTTP 503 from https://issuer.example/.well-known/did.json"));
        ServiceException e = upstreamFailure(service);
        assertThat(e.kind()).isEqualTo(ServiceException.Kind.UPSTREAM_FAILED);
        assertThat(e.code()).isEqualTo("upstream_unavailable");
        assertThat(e.getMessage()).isEqualTo("DID document unavailable: HTTP 503 from https://issuer.example/.well-known/did.json");
        // Remembered for a while, and reported the same way meanwhile.
        assertThat(upstreamFailure(service).code()).isEqualTo("upstream_unavailable");
        // The service's own use of the DID sees the same error, as before.
        assertThat(service.resolve(DID).error()).contains(DidResolutionResult.INTERNAL_ERROR);
    }

    @Test
    void aDocumentLargerThanTheRelayCarriesIsAFailureUpstream() {
        cfg.setMaxDocumentBytes(64);
        DidService service = service(d -> DidResolutionResult.success(Map.of("id", DID, "pad", "x".repeat(100)), Map.of(), Map.of()));
        assertThat(upstreamFailure(service).code()).isEqualTo("upstream_unavailable");
        // Also from the cache, where the refusal is held for a while.
        assertThat(upstreamFailure(service).getMessage()).contains("exceeds 64 bytes");
    }

    @Test
    void anAnswerAboutTheDidStaysItsAnswer() {
        DidService service = service(d -> DidResolutionResult.error(DidResolutionResult.NOT_FOUND, "HTTP 404 from https://issuer.example/.well-known/did.json"));
        DidService.Answer a = service.resolveFromPath(DID);
        assertThat(a.result().error()).contains(DidResolutionResult.NOT_FOUND);
        assertThat(DidResolutionResult.httpStatus(a.result().error().orElseThrow())).isEqualTo(404);
        assertThat(service.resolveFromPath("not-a-did").result().error()).contains(DidResolutionResult.INVALID_DID);
        assertThat(service.resolveFromPath("did:example:123").result().error()).contains(DidResolutionResult.METHOD_NOT_SUPPORTED);
    }

    @Test
    void aFailureOfTheServiceItselfIsNotTakenForOneUpstream() {
        DidService service = service(d -> {
            throw new IllegalStateException("a bug in a driver");
        });
        DidService.Answer a = service.resolveFromPath(DID);
        assertThat(a.result().upstreamFailed()).isFalse();
        assertThat(a.result().error()).contains(DidResolutionResult.INTERNAL_ERROR);
        assertThat(DidResolutionResult.httpStatus(a.result().error().orElseThrow())).isEqualTo(500);
    }

    @Test
    void aLastGoodDocumentStandsInForAFailureUpstream() {
        DidResolutionResult[] next = {document()};
        DidService service = service(d -> next[0]);
        assertThat(service.resolveFromPath(DID).result().isSuccess()).isTrue();
        next[0] = DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "HTTP 503 from https://issuer.example/.well-known/did.json");
        clock.now = clock.now.plus(cfg.getDidTtl()).plus(Duration.ofMinutes(1));
        DidResolutionResult stale = service.resolveFromPath(DID).result();
        assertThat(stale.isSuccess()).isTrue();
        assertThat(((Map<?, ?>) stale.didResolutionMetadata().get("cache")).get("stale")).isEqualTo(true);
    }
}
