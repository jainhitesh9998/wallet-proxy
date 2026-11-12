package io.vctrust.trust.core.registry;

import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.Reason;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustSourceManagerTest.Fixed;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.vctrust.trust.core.registry.AnchorTieTest.FRAMEWORKS;
import static io.vctrust.trust.core.registry.AnchorTieTest.decide;
import static io.vctrust.trust.core.registry.AnchorTieTest.dmv;
import static io.vctrust.trust.core.registry.AnchorTieTest.iaca;
import static io.vctrust.trust.core.registry.AnchorTieTest.source;
import static io.vctrust.trust.core.registry.AnchorTieTest.warnings;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An entry that only describes a party (what an issuer says about itself, {@link SourceLoadResult#describing}) never
 * makes an entity, nor one usable. Merged as an entry, a description written with a misspelt id made an ACTIVE issuer
 * of its own: the issuer's URL was trusted beside its REVOKED entry under the right id, and an anchor tied to the same
 * misspelt id was tied to it instead of being refused. A description is merged, after every other entry, only into the
 * one entity of its framework that another source lists, and only for what describes.
 */
class DescribingEntriesTest {

    static final String URL = "https://issuer.utopia.example";
    static final String CONTEXT = "https://issuer.utopia.example/contexts/v1";

    /** What the issuer says about itself, as a description of entity {@code id}. */
    static TrustedEntity.Builder description(String id) {
        return TrustedEntity.builder(id).framework("example").role(EntityRole.CREDENTIAL_ISSUER)
                .display(LocalizedDisplay.of("en", "Utopia DMV (self)"))
                .attribute(Oid4vciMetadataMapper.CONTEXTS, List.of(CONTEXT))
                .provenance(Provenance.of("discovery", "test", "example", URL, Instant.now()));
    }

    /** The same, naming the entity that lists the issuer's URL. */
    static TrustedEntity.Builder byUrl() {
        return description(URL).identifier(IdentifierType.URL, URL);
    }

    static Fixed describing(TrustedEntity... descriptions) {
        return new Fixed("discovery", "example", SourceLoadResult.describing(List.of(descriptions), ListInfo.unsigned(), List.of()));
    }

    /** What a client of {@code example} is told about the issuer by its URL alone (a credential offer). */
    static TrustDecision byIdentifier(TrustRegistry registry, TrustSourceManager manager) {
        return new TrustEvaluator(registry, manager, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(URL, List.of(), null, null),
                        new TrustQuery.Context("oid4vci", "dc+sd-jwt", "org.example.diploma", null, null, List.of())),
                        new ClientProfile("wallet", "Wallet", Set.of("example"), false, false, false));
    }

    @Test
    void aDescriptionAddsWhatDescribesAndNothingThatRestrictsOrBinds() {
        TrustedEntity listed = TrustedEntity.builder("utopia-dmv").framework("example").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, URL).status(EntityStatus.SUSPENDED).validUntil(Instant.parse("2030-01-01T00:00:00Z"))
                .authorization(CredentialAuthorization.of("mso_mdoc", "org.iso.18013.5.1.mDL"))
                .provenance(Provenance.of("registry", "test", "example", null, Instant.now())).build();
        // Everything a description could say, beside what describes the party.
        TrustedEntity said = byUrl().role(EntityRole.VERIFIER).identifier(IdentifierType.DNS, "elsewhere.example")
                .status(EntityStatus.ACTIVE).validFrom(Instant.parse("2020-01-01T00:00:00Z")).validUntil(Instant.parse("2099-01-01T00:00:00Z"))
                .authorization(CredentialAuthorization.of("dc+sd-jwt", null)).certificate(AnchorTieTest.SIGNER.certificate())
                .attribute(Oid4vciMetadataMapper.CONTEXT_DIGESTS, Map.of(CONTEXT, "digest"))
                .attribute("trustAnchor", "https://federation.example").attribute("country", "UT")
                .metadata("openid_credential_issuer", Map.of("credential_issuer", URL))
                .metadataPolicy("openid_credential_issuer", Map.of("display", Map.of("value", List.of()))).build();
        for (boolean describedFirst : List.of(true, false)) {
            var registry = new TrustRegistry();
            Fixed lists = source("registry", "example", List.of(listed), List.of());
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, describedFirst ? List.of(describing(said), lists)
                    : List.of(lists, describing(said)), Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().entities()).as("first: %s", describedFirst).singleElement().satisfies(e -> {
                    assertThat(e.id()).isEqualTo("utopia-dmv");
                    // What describes reaches the entity.
                    assertThat(e.displayName("en")).isEqualTo("Utopia DMV (self)");
                    assertThat(e.attributes()).containsEntry(Oid4vciMetadataMapper.CONTEXTS, List.of(CONTEXT))
                            .containsEntry(Oid4vciMetadataMapper.CONTEXT_DIGESTS, Map.of(CONTEXT, "digest"))
                            .containsEntry("mergedFrom", List.of("registry", "discovery"))
                            .doesNotContainKeys("trustAnchor", "country");
                    assertThat(e.metadata()).containsOnlyKeys("openid_credential_issuer");
                    // Nothing else does.
                    assertThat(e.roles()).containsExactly(EntityRole.CREDENTIAL_ISSUER);
                    assertThat(e.identifiers()).containsExactly(Identifier.url(URL));
                    assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED);
                    assertThat(e.validFrom()).isNull();
                    assertThat(e.validUntil()).isEqualTo(Instant.parse("2030-01-01T00:00:00Z"));
                    assertThat(e.authorizations()).containsExactly(CredentialAuthorization.of("mso_mdoc", "org.iso.18013.5.1.mDL"));
                    assertThat(e.certificates()).isEmpty();
                    assertThat(e.metadataPolicy()).isEmpty();
                });
                assertThat(warnings(manager, "discovery")).isEmpty();
            }
        }
        // A display of the entity's own stands, as do its contexts.
        TrustedEntity curated = TrustedEntity.builder("utopia-dmv").framework("example").role(EntityRole.CREDENTIAL_ISSUER)
                .display(LocalizedDisplay.of("en", "Utopia DMV")).attribute(Oid4vciMetadataMapper.CONTEXTS, List.of("https://curated.example/v1")).build();
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(describing(description("utopia-dmv").build()),
                source("registry", "example", List.of(curated), List.of())), Clock.systemUTC())) {
            manager.start();
            TrustedEntity e = registry.snapshot().entity("utopia-dmv").orElseThrow();
            assertThat(e.displayName("en")).isEqualTo("Utopia DMV");
            assertThat(e.attributes()).containsEntry(Oid4vciMetadataMapper.CONTEXTS, List.of("https://curated.example/v1"));
        }
    }

    @Test
    void aDescriptionOfAnIdNoOtherSourceListsMakesNoEntity() {
        // The description's entityId misspelt, the anchor tied right: the CA's chain is decided by the DMV's withdrawal.
        for (boolean describedFirst : List.of(true, false)) {
            var registry = new TrustRegistry();
            Fixed lists = source("registry", "example", List.of(dmv("example")), List.of(iaca("example", "utopia-dmv")));
            Fixed describes = describing(description("Utopia-DMV").build());
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, describedFirst ? List.of(describes, lists) : List.of(lists, describes),
                    Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("utopia-dmv");
                assertThat(warnings(manager, "discovery")).containsExactly("The description of '" + URL + "' is not loaded: no other source "
                        + "of framework 'example' lists entity 'Utopia-DMV', and a description makes no entity of its own");
                TrustDecision d = decide(registry, manager, "example");
                assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.entity().id()).isEqualTo("utopia-dmv");
                // By its URL the issuer was TRUSTED as the description's own ACTIVE entity, beside its REVOKED entry.
                TrustDecision byUrl = byIdentifier(registry, manager);
                assertThat(byUrl.decision()).as(byUrl.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(byUrl.entity().id()).isEqualTo("utopia-dmv");
            }
        }
        // The anchor misspelt the same way: it was tied to the description's entity, and the chain TRUSTED.
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(source("registry", "example", List.of(dmv("example")),
                List.of(iaca("example", "Utopia-DMV"))), describing(description("Utopia-DMV").build())), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().allAnchors()).isEmpty();
            assertThat(warnings(manager, "registry")).containsExactly("Anchor 'utopia-iaca' is not loaded: it belongs to entity 'Utopia-DMV', "
                    + "which no source of framework 'example' lists");
            TrustDecision d = decide(registry, manager, "example");
            assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.UNKNOWN);
            assertThat(d.reasons()).extracting(Reason::code).contains("x509.no_anchor");
        }
    }

    @Test
    void aDescriptionByUrlMeetsTheOneEntityOfItsFrameworkThatListsTheUrl() {
        // The issuer listed REVOKED under another id: the description made an ACTIVE entity of the URL, and the URL was TRUSTED.
        for (boolean describedFirst : List.of(true, false)) {
            var registry = new TrustRegistry();
            Fixed lists = source("registry", "example", List.of(dmv("example")), List.of(iaca("example", "utopia-dmv")));
            Fixed describes = describing(byUrl().build());
            try (var manager = new TrustSourceManager(registry, FRAMEWORKS, describedFirst ? List.of(describes, lists) : List.of(lists, describes),
                    Clock.systemUTC())) {
                manager.start();
                assertThat(registry.snapshot().entities()).singleElement().satisfies(e -> {
                    assertThat(e.id()).isEqualTo("utopia-dmv");
                    assertThat(e.displayName("en")).isEqualTo("Utopia DMV (self)");
                    assertThat(e.attributes()).containsEntry(Oid4vciMetadataMapper.CONTEXTS, List.of(CONTEXT));
                });
                assertThat(warnings(manager, "discovery")).isEmpty();
                TrustDecision d = byIdentifier(registry, manager);
                assertThat(d.decision()).as(d.summary()).isEqualTo(Decision.NOT_TRUSTED);
                assertThat(d.entity().id()).isEqualTo("utopia-dmv");
                assertThat(d.reasons()).filteredOn(Reason::isError).extracting(Reason::code).containsExactly("entity.status");
            }
        }
        // Listed by nobody, or by an entity of another framework only: left out.
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(source("elsewhere", "other", List.of(dmv("other")), List.of()),
                describing(byUrl().build())), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("utopia-dmv");
            assertThat(registry.snapshot().entity("utopia-dmv").orElseThrow().display()).isEmpty();
            assertThat(warnings(manager, "discovery")).containsExactly("The description of '" + URL + "' is not loaded: no entity of framework "
                    + "'example' lists URL '" + URL + "' as an identifier, and a description makes no entity of its own");
            assertThat(byIdentifier(registry, manager).decision()).isEqualTo(Decision.UNKNOWN);
        }
    }

    @Test
    void aDescriptionByUrlThatSeveralEntitiesListIsLeftOut() {
        TrustedEntity college = TrustedEntity.builder("utopia-college").framework("example").role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(IdentifierType.URL, URL).build();
        var registry = new TrustRegistry();
        try (var manager = new TrustSourceManager(registry, FRAMEWORKS, List.of(source("registry", "example", List.of(dmv("example"), college),
                List.of()), describing(byUrl().build())), Clock.systemUTC())) {
            manager.start();
            assertThat(registry.snapshot().entities()).allSatisfy(e -> assertThat(e.display()).isEmpty());
            assertThat(warnings(manager, "discovery")).containsExactly("The description of '" + URL + "' is not loaded: entities 'utopia-dmv' "
                    + "and 'utopia-college' of framework 'example' list URL '" + URL + "', and which one it describes cannot be told");
        }
    }

    @Test
    void aDescribingLoadListsNoAnchors() {
        assertThatThrownBy(() -> new SourceLoadResult(List.of(), List.of(iaca("example", null)), ListInfo.unsigned(), List.of(), true))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
