package io.vctrust.trust.server.service;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.managed.ManagedEntityStore;
import io.vctrust.trust.server.managed.ManagedSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Entries sent to the admin API are stored for the framework of the managed source. Such an entry cannot take the
 * name another framework's entry is listed under when its id is taken ({@code <id>@<that framework>}): written with
 * it, it would keep that entry (a withdrawn issuer of "other", here) out of the registry.
 */
class ManagedEntryServiceTest {

    static final ClientProfile OPERATOR = new ClientProfile("ops", "ops", Set.of(ClientProfile.ALL_FRAMEWORKS), false, false, true);
    static final ClientProfile OTHER = new ClientProfile("other-wallet", "Other", Set.of("other"), false, false, false);
    static final TestPki.Issued SHARED_CA = TestPki.rootCa("CN=Shared Issuer CA,C=UT");
    static final TestPki.Issued VICTIM = TestPki.leaf("CN=Victim Issuer,C=UT", SHARED_CA, List.of(), null);

    /** The managed documents, in memory. */
    static final class Store extends ManagedEntityStore {
        final Map<Kind, Map<String, Map<String, Object>>> docs = new TreeMap<>();

        Store() {
            super(null);
        }

        @Override
        public List<Map<String, Object>> list(Kind kind) {
            return List.copyOf(docs.getOrDefault(kind, Map.of()).values());
        }

        @Override
        public Optional<Map<String, Object>> get(Kind kind, String id) {
            return Optional.ofNullable(docs.getOrDefault(kind, Map.of()).get(id));
        }

        @Override
        public void put(Kind kind, String id, Map<String, Object> document) {
            docs.computeIfAbsent(kind, k -> new TreeMap<>()).put(id, document);
        }

        @Override
        public boolean delete(Kind kind, String id) {
            return docs.getOrDefault(kind, new TreeMap<>()).remove(id) != null;
        }
    }

    final Store store = new Store();
    final TrustRegistry registry = new TrustRegistry();
    final TrustSourceManager sources;
    final ManagedEntryService managed;

    ManagedEntryServiceTest() {
        // "official" (framework other) lists the victim as withdrawn under a shared CA; the managed source is the partner's.
        TrustedEntity victim = TrustedEntity.builder("victim").framework("other").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(VICTIM.certificate())).status(EntityStatus.REVOKED).build();
        TrustAnchor ca = new TrustAnchor("iaca", TrustDomain.CREDENTIAL_ISSUER, SHARED_CA.certificate(), "other", null, null, null, null);
        SourceDefinition officialDef = new SourceDefinition("official", "test", "other", null, true, true, Map.of());
        TrustSource official = new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return officialDef;
            }

            @Override
            public SourceLoadResult load() {
                return new SourceLoadResult(List.of(victim), List.of(ca), ListInfo.unsigned(), List.of());
            }
        };
        ResourceLoader loader = location -> new byte[0];
        SourceContext ctx = new SourceContext() {
            @Override
            public HttpFetcher http() {
                return null;
            }

            @Override
            public ResourceLoader resources() {
                return loader;
            }

            @Override
            public Clock clock() {
                return Clock.systemUTC();
            }
        };
        TrustSource partner = new ManagedSourceFactory(store).create(
                new SourceDefinition("managed", "managed", "partner", null, true, false, Map.of()), ctx);
        // The managed source is configured first: it loads before the official list.
        sources = new TrustSourceManager(registry, List.of(new TrustFramework("other", "Other", null, null, null),
                new TrustFramework("partner", "Partner", null, null, null)), List.of(partner, official), Clock.systemUTC());
        sources.start();
        managed = new ManagedEntryService(store, loader, sources);
    }

    @AfterEach
    void close() {
        sources.close();
    }

    Decision victimDecision() {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                        new TrustQuery.Subject(null, List.of(Certificates.toBase64(VICTIM.certificate())), null, null),
                        new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())), OTHER).decision();
    }

    static Map<String, Object> entity(String url) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("roles", List.of("CREDENTIAL_ISSUER"));
        doc.put("identifiers", List.of(url));
        return doc;
    }

    @Test
    void anEntryCannotTakeAnotherFrameworksFallbackName() {
        assertThat(victimDecision()).isEqualTo(Decision.NOT_TRUSTED);
        managed.put(OPERATOR, "entities", "victim", entity("https://partner.example/a"));
        assertThat(victimDecision()).isEqualTo(Decision.NOT_TRUSTED);

        assertThatThrownBy(() -> managed.put(OPERATOR, "entities", "victim@other", entity("https://partner.example/b")))
                .isInstanceOfSatisfying(ServiceException.class, e -> {
                    assertThat(e.kind()).isEqualTo(ServiceException.Kind.INVALID_REQUEST);
                    assertThat(e.code()).isEqualTo("invalid_document");
                    assertThat(e.getMessage()).contains("'other'");
                });
        Map<String, Object> anchor = new LinkedHashMap<>();
        anchor.put("domain", "credential-issuer");
        anchor.put("certificate", Certificates.toPem(TestPki.rootCa("CN=Partner CA,C=UT").certificate()));
        assertThatThrownBy(() -> managed.put(OPERATOR, "anchors", "iaca@other", anchor))
                .isInstanceOfSatisfying(ServiceException.class, e -> assertThat(e.code()).isEqualTo("invalid_document"));
        assertThat(managed.list(OPERATOR, "entities")).extracting(d -> d.get("id")).containsExactly("victim");
        assertThat(managed.list(OPERATOR, "anchors")).isEmpty();
        assertThat(victimDecision()).isEqualTo(Decision.NOT_TRUSTED);

        // Its own framework's name is the partner's to use.
        managed.put(OPERATOR, "entities", "victim@partner", entity("https://partner.example/c"));
        assertThat(registry.snapshot().entity("victim@partner")).get().satisfies(e -> assertThat(e.frameworkId()).isEqualTo("partner"));
    }

    @Test
    void anEntryStoredBeforeTheRuleIsNotLoaded() {
        // Written to the database directly, or before this check existed: the registry refuses it all the same.
        Map<String, Object> doc = entity("https://partner.example/b");
        doc.put("id", "victim@other");
        doc.put("framework", "partner");
        store.put(ManagedEntityStore.Kind.ENTITY, "victim@other", doc);
        managed.put(OPERATOR, "entities", "victim", entity("https://partner.example/a"));
        assertThat(victimDecision()).isEqualTo(Decision.NOT_TRUSTED);
        assertThat(sources.states()).filteredOn(s -> s.id().equals("managed")).singleElement()
                .satisfies(s -> assertThat(s.warnings()).anyMatch(w -> w.startsWith("Entity 'victim@other' is not loaded")));
    }
}
