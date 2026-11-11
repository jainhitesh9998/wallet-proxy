package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class TrustSourceManagerTest {

    /** A source whose content and availability the test controls. */
    static final class Source implements TrustSource {
        final SourceDefinition def;
        final AtomicBoolean failing = new AtomicBoolean();
        volatile String issuerUrl = "https://issuer.example";

        Source(String id, boolean required) {
            def = new SourceDefinition(id, "test", "fw", null, true, required, Map.of());
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
            if (failing.get()) {
                throw new TrustSourceException("upstream down");
            }
            // The retrieval time differs on every load, as it does for real sources.
            var entity = TrustedEntity.builder(def.id() + "-issuer").framework("fw").role(EntityRole.CREDENTIAL_ISSUER)
                    .identifier(IdentifierType.URL, issuerUrl).provenance(Provenance.of(def.id(), "test", "fw", null, Instant.now())).build();
            return new SourceLoadResult(List.of(entity), List.of(), ListInfo.unsigned(), List.of());
        }
    }

    @Test
    void isNotReadyUntilEveryRequiredSourceHasLoadedOnce() {
        var required = new Source("list", true);
        var optional = new Source("sandbox", false);
        required.failing.set(true);
        optional.failing.set(true);
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(required, optional), Clock.systemUTC())) {
            manager.start();
            // A registry without the required list would look like its parties having been delisted.
            assertThat(manager.ready()).isFalse();
            assertThat(manager.waitingFor()).containsExactly("list");
            required.failing.set(false);
            manager.refresh("list");
            assertThat(manager.ready()).isTrue();
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("list-issuer");
            // Once loaded, a failure keeps the last good result: still ready, still listed.
            required.failing.set(true);
            manager.refresh("list");
            assertThat(manager.ready()).isTrue();
            assertThat(registry.snapshot().entities()).hasSize(1);
        }
    }

    @Test
    void publishesANewVersionOnlyWhenTheContentChanged() {
        var source = new Source("list", true);
        var registry = new TrustRegistry();
        AtomicInteger published = new AtomicInteger();
        registry.onChange(s -> published.incrementAndGet());
        try (var manager = new TrustSourceManager(registry, List.of(), List.of(source), Clock.systemUTC())) {
            manager.start();
            long version = registry.snapshot().version();
            int count = published.get();
            manager.refresh("list");
            manager.refresh("list");
            assertThat(registry.snapshot().version()).isEqualTo(version);
            assertThat(published).hasValue(count);
            source.issuerUrl = "https://issuer.example/v2";
            manager.refresh("list");
            assertThat(registry.snapshot().version()).isEqualTo(version + 1);
        }
    }
}
