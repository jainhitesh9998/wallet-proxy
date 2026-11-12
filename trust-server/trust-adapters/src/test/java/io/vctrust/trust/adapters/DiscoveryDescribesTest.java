package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.oid4vci.Oid4vciDiscoverySourceFactory;
import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.Reason;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code oid4vci-discovery} source describes issuers registered elsewhere and authorizes nothing: it never makes an
 * entity of its own. With its {@code entityId} misspelt it made one, ACTIVE, so that the issuer's URL was TRUSTED beside
 * its REVOKED entry under the right id, and an anchor written with the same misspelling was tied to it; and so it did in
 * the plain form (a URL alone) when the registry lists the issuer under another id.
 */
class DiscoveryDescribesTest {

    static final TestPki.Issued IACA = TestPki.rootCa("CN=Utopia IACA,C=UT");
    static final TestPki.Issued SIGNER = TestPki.leaf("CN=Utopia Document Signer,C=UT", IACA, List.of(), null);
    static final String URL = "https://issuer.utopia.example";
    static final String CONTEXT = "https://issuer.utopia.example/contexts/diploma/v1";

    /** The operator's registry: the DMV, {@code status}, under {@code utopia-dmv} and bound to its URL; its IACA tied to {@code anchorEntity}. */
    static String registry(String status, String anchorEntity) {
        String pem = Certificates.toPem(IACA.certificate()).replace("\n", "\\n");
        return """
                entities:
                  - id: utopia-dmv
                    roles: [CREDENTIAL_ISSUER]
                    status: %s
                    identifiers:
                      - { type: URL, value: "%s" }
                anchors:
                  - id: utopia-iaca
                    domain: credential-issuer
                    entity: %s
                    certificate: "%s"
                """.formatted(status, URL, anchorEntity, pem);
    }

    /** The issuer's own metadata: a name it gives itself and the JSON-LD context of a credential. */
    static TestContext issuerSays(TestContext ctx) {
        ctx.http.json("https://issuer.utopia.example/.well-known/openid-credential-issuer",
                "{\"credential_issuer\":\"" + URL + "\",\"credential_endpoint\":\"" + URL + "/credential\","
                        + "\"display\":[{\"name\":\"Utopia DMV (self)\",\"locale\":\"en\"}],\"credential_configurations_supported\":{"
                        + "\"diploma\":{\"format\":\"ldp_vc\",\"credential_definition\":{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\""
                        + CONTEXT + "\"],\"type\":[\"VerifiableCredential\",\"Diploma\"]}}}}");
        ctx.http.json("https://issuer.utopia.example/.well-known/oauth-authorization-server", "{\"issuer\":\"" + URL + "\"}");
        return ctx;
    }

    record Run(TrustRegistry registry, TrustSourceManager manager) implements AutoCloseable {
        @Override
        public void close() {
            manager.close();
        }

        List<String> warnings(String source) {
            return manager.states().stream().filter(s -> s.id().equals(source)).findFirst().orElseThrow().warnings();
        }

        TrustDecision decide(boolean byUrl) {
            TrustEvaluator evaluator = new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(),
                    Clock.systemUTC(), Duration.ofHours(1));
            return evaluator.evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, byUrl ? new TrustQuery.Subject(URL, List.of(), null, null)
                            : new TrustQuery.Subject(null, List.of(Certificates.toBase64(SIGNER.certificate())), null, null),
                            new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())),
                    new ClientProfile("wallet", "Wallet", Set.of("example"), false, false, false));
        }
    }

    /** The operator's registry and the discovery source, in that order or the other; {@code issuer} is how the issuer is configured. */
    static Run run(String status, String anchorEntity, Object issuer, boolean discoveryFirst) {
        TestContext ctx = issuerSays(new TestContext());
        ctx.put("mem:registry.yaml", registry(status, anchorEntity));
        List<TrustSource> sources = new ArrayList<>();
        sources.add(new StaticTrustSourceFactory().create(new SourceDefinition("registry", "static", "example", null, true,
                Map.of("location", "mem:registry.yaml")), ctx));
        sources.add(discoveryFirst ? 0 : 1, new Oid4vciDiscoverySourceFactory().create(new SourceDefinition("discovery", "oid4vci-discovery",
                "example", null, true, Map.of("issuers", List.of(issuer))), ctx));
        TrustRegistry registry = new TrustRegistry();
        TrustSourceManager manager = new TrustSourceManager(registry, List.of(new TrustFramework("example", "Example", null, null, null)),
                sources, Clock.systemUTC());
        manager.start();
        return new Run(registry, manager);
    }

    static Map<String, Object> named(String entityId) {
        return Map.of("url", URL, "entityId", entityId);
    }

    static final String MISSPELT = "The description of '" + URL + "' is not loaded: no other source of framework 'example' lists entity "
            + "'Utopia-DMV', and a description makes no entity of its own";

    @Test
    void aMisspeltEntityIdDescribesNobodyAndTheIssuerIsDecidedByItsEntry() {
        for (boolean discoveryFirst : List.of(false, true)) {
            try (Run r = run("REVOKED", "utopia-dmv", named("Utopia-DMV"), discoveryFirst)) {
                assertThat(r.registry().snapshot().entities()).extracting(TrustedEntity::id).containsExactly("utopia-dmv");
                assertThat(r.warnings("discovery")).containsExactly(MISSPELT);
                // By its URL the issuer was TRUSTED: the description's own entity, ACTIVE, beside the REVOKED entry.
                for (boolean byUrl : List.of(true, false)) {
                    TrustDecision d = r.decide(byUrl);
                    assertThat(d.decision()).as(byUrl + ": " + d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                    assertThat(d.entity().id()).isEqualTo("utopia-dmv");
                    assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
                }
            }
        }
    }

    @Test
    void anAnchorMisspeltLikeTheEntityIdIsRefusedByTheAnchorTieRule() {
        try (Run r = run("REVOKED", "Utopia-DMV", named("Utopia-DMV"), false)) {
            // Tied to the description's entity, the CA's chain was TRUSTED.
            assertThat(r.registry().snapshot().allAnchors()).isEmpty();
            assertThat(r.warnings("registry")).containsExactly("Anchor 'utopia-iaca' is not loaded: it belongs to entity 'Utopia-DMV', "
                    + "which no source of framework 'example' lists");
            assertThat(r.warnings("discovery")).containsExactly(MISSPELT);
            TrustDecision d = r.decide(false);
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.UNKNOWN);
            assertThat(d.reasons()).extracting(Reason::code).contains("x509.no_anchor");
            assertThat(r.decide(true).decision()).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void theUrlAloneDescribesTheEntityThatListsTheIssuersUrl() {
        for (boolean discoveryFirst : List.of(false, true)) {
            // The issuer listed REVOKED under another id than its URL: the description made an ACTIVE entity of the URL.
            try (Run r = run("REVOKED", "utopia-dmv", URL, discoveryFirst)) {
                assertThat(r.registry().snapshot().entities()).extracting(TrustedEntity::id).containsExactly("utopia-dmv");
                assertThat(r.warnings("discovery")).isEmpty();
                TrustDecision d = r.decide(true);
                assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.entity().id()).isEqualTo("utopia-dmv");
            }
        }
    }

    @Test
    void aDescriptionOfAListedIssuerReachesItsEntity() {
        // The honest cases: the entity named right, or found by its URL. Display and contexts reach it, and it is trusted
        // as its own entry says.
        for (Object issuer : List.of(named("utopia-dmv"), URL)) {
            for (boolean discoveryFirst : List.of(false, true)) {
                try (Run r = run("ACTIVE", "utopia-dmv", issuer, discoveryFirst)) {
                    String as = issuer + ", discovery first: " + discoveryFirst;
                    assertThat(r.warnings("discovery")).as(as).isEmpty();
                    assertThat(r.warnings("registry")).as(as).isEmpty();
                    assertThat(r.registry().snapshot().entities()).as(as).singleElement().satisfies(e -> {
                        assertThat(e.id()).isEqualTo("utopia-dmv");
                        assertThat(e.displayName("en")).isEqualTo("Utopia DMV (self)");
                        assertThat(e.attributes().get("jsonLdContexts")).isEqualTo(List.of("https://www.w3.org/ns/credentials/v2", CONTEXT));
                        assertThat(e.authorizations()).isEmpty();
                    });
                    assertThat(r.decide(true).decision()).as(as).isEqualTo(Decision.TRUSTED);
                    assertThat(r.decide(false).decision()).as(as).isEqualTo(Decision.TRUSTED);
                }
            }
        }
    }
}
