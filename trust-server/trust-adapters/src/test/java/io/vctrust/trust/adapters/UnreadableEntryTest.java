package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A static registry that holds an entry the parser cannot read fails to load: the source keeps its last good content,
 * its state names the entry and what is wrong with it, and a required source that never loaded keeps the service not
 * ready. Skipped, a revoked entity would let its party be trusted through the CA, and a skipped anchor would drop out.
 */
class UnreadableEntryTest {

    static final TestPki.Issued CA = TestPki.rootCa("CN=Shared Issuer CA,C=UT");
    static final TestPki.Issued ACME = TestPki.leaf("CN=Acme Issuer,C=UT", CA, List.of(), null);

    final TestContext ctx = new TestContext();

    static String registry(String acme) {
        return """
                entities:
                  - id: acme
                    roles: [CREDENTIAL_ISSUER]
                    certificates:
                      - |
                %s
                %s
                anchors:
                  - id: shared-ca
                    domain: credential-issuer
                    certificate: |
                %s
                """.formatted(Certificates.toPem(ACME.certificate()).indent(8), acme.indent(4), Certificates.toPem(CA.certificate()).indent(6));
    }

    TrustSourceManager manager(TrustRegistry registry, boolean required) {
        TrustSource source = new StaticTrustSourceFactory().create(new SourceDefinition("list", "static", "fw", null, true, required,
                Map.of("location", "mem:registry.yaml")), ctx);
        return new TrustSourceManager(registry, List.of(new TrustFramework("fw", "Framework", null, null, null)), List.of(source), Clock.systemUTC());
    }

    static Decision acmeDecision(TrustRegistry registry, TrustSourceManager sources) {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                        new TrustQuery.Subject(null, List.of(Certificates.toBase64(ACME.certificate())), null, null),
                        new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())),
                        ClientProfile.unrestricted("wallet")).decision();
    }

    static SourceState state(TrustSourceManager sources) {
        return sources.states().getFirst();
    }

    @Test
    void aRevokedEntityWhoseDateCannotBeReadKeepsItsPartyOut() {
        ctx.put("mem:registry.yaml", registry("status: REVOKED\nvalidUntil: 2030-01-01T00:00:00Z"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry, true)) {
            sources.start();
            assertThat(acmeDecision(registry, sources)).isEqualTo(Decision.NOT_TRUSTED);

            // The operator edits the entry and writes a date that is not one.
            ctx.put("mem:registry.yaml", registry("status: REVOKED\nvalidUntil: 2030-01-32T00:00:00Z"));
            SourceState st = sources.refresh("list");
            assertThat(st.lastError()).startsWith("Cannot load static registry mem:registry.yaml: entity 'acme' cannot be read: ")
                    .contains("2030-01-32");
            assertThat(st.warnings()).isEmpty();
            // The last good content stays: the party is still revoked, not trusted through the CA.
            assertThat(registry.snapshot().entity("acme")).get().satisfies(e -> assertThat(e.status()).isEqualTo(EntityStatus.REVOKED));
            assertThat(acmeDecision(registry, sources)).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void aRequiredSourceWithAnUnreadableEntryIsNotReadyUntilItLoads() {
        ctx.put("mem:registry.yaml", registry("status: REVOKED\nvalidUntil: 2030-01-32T00:00:00Z"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry, true)) {
            sources.start();
            assertThat(sources.ready()).isFalse();
            assertThat(sources.waitingFor()).containsExactly("list");
            assertThat(state(sources).lastError()).contains("entity 'acme' cannot be read");
            ctx.put("mem:registry.yaml", registry("status: REVOKED\nvalidUntil: 2030-01-31T00:00:00Z"));
            assertThat(sources.refresh("list").lastError()).isNull();
            assertThat(sources.ready()).isTrue();
            assertThat(acmeDecision(registry, sources)).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void anAnchorWhoseCertificateCannotBeFetchedDoesNotDropOut() {
        ctx.http.json("https://pki.example/ca.json", "{\"pem\":" + io.vctrust.trust.core.json.Json.write(Certificates.toPem(CA.certificate())) + "}");
        String yaml = """
                anchors:
                  - domain: credential-issuer
                    certificateLocation: https://pki.example/ca.json
                    certificateJsonField: pem
                """;
        ctx.put("mem:registry.yaml", yaml);
        var registry = new TrustRegistry();
        try (var sources = manager(registry, true)) {
            sources.start();
            assertThat(registry.snapshot().allAnchors()).hasSize(1);
            // The location is down: the anchor is not dropped until the next refresh, the load fails.
            ctx.http.respond("https://pki.example/ca.json", 503, "text/plain", "down".getBytes());
            SourceState st = sources.refresh("list");
            assertThat(st.lastError()).contains("anchor anchors[0] cannot be read: ").contains("503");
            assertThat(registry.snapshot().allAnchors()).hasSize(1);
        }
    }

    @Test
    void anEntryIsNamedByItsIdOrByItsPlace() {
        var def = new SourceDefinition("list", "static", "fw", null, true, Map.of("location", "mem:registry.yaml"));
        ctx.put("mem:registry.yaml", """
                entities:
                  - {id: fine, roles: [VERIFIER]}
                  - "not an entry"
                """);
        assertThatThrownBy(() -> new StaticTrustSourceFactory().create(def, ctx).load()).isInstanceOf(TrustSourceException.class)
                .hasMessage("Cannot load static registry mem:registry.yaml: entity entities[1] cannot be read: it is not an object");
        ctx.put("mem:registry.yaml", """
                entities:
                  - {roles: [VERIFIER]}
                """);
        assertThatThrownBy(() -> new StaticTrustSourceFactory().create(def, ctx).load()).isInstanceOf(TrustSourceException.class)
                .hasMessage("Cannot load static registry mem:registry.yaml: entity entities[0] cannot be read: it has no id");
        ctx.put("mem:registry.yaml", """
                anchors:
                  - {id: no-domain, certificate: "MIIB"}
                """);
        assertThatThrownBy(() -> new StaticTrustSourceFactory().create(def, ctx).load()).isInstanceOf(TrustSourceException.class)
                .hasMessage("Cannot load static registry mem:registry.yaml: anchor 'no-domain' cannot be read: it has no domain");
    }
}
