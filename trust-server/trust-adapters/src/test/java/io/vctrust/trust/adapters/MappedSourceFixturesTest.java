package io.vctrust.trust.adapters;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import io.vctrust.trust.core.did.DidKeyDriver;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.vctrust.trust.adapters.MappedTesting.ROOT;
import static io.vctrust.trust.adapters.MappedTesting.der;
import static io.vctrust.trust.adapters.MappedTesting.jwks;
import static io.vctrust.trust.adapters.MappedTesting.key;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.sign;
import static io.vctrust.trust.adapters.MappedTesting.signer;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.utf8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Lists in other people's shapes, each mapped by configuration alone (a mapping file, as an operator writes it), with
 * the certificates of conformance/pki: the mapping language is expressive enough when these come out right.
 */
class MappedSourceFixturesTest {

    static final ClientProfile CLIENT = ClientProfile.unrestricted("test");

    static TrustDecision decide(TrustRegistry registry, TrustQuery query) {
        return new TrustEvaluator(registry, null, new DidResolver(List.of(new DidKeyDriver())), new X509PathValidator(),
                Clock.systemUTC(), Duration.ofHours(1)).evaluate(query, CLIENT);
    }

    static TrustQuery issuer(String identifier, List<String> x5c, String format, String type) {
        return new TrustQuery(EntityRole.CREDENTIAL_ISSUER, new TrustQuery.Subject(identifier, x5c, null, null),
                new TrustQuery.Context("oid4vci", format, type, null, null, List.of()));
    }

    // 1. A plain list of issuers in someone else's shape: the issuer configuration of a wallet backend.

    static final String WALLET_BACKEND = """
            {"issuers": [
              {"issuer_id": "utopia-dmv", "credential_issuer": "https://issuer.utopia.example",
               "display": [{"name": "Utopia DMV", "language": "en", "logo": "https://issuer.utopia.example/logo.png"},
                           {"name": "Utopia Kraftfahrtamt", "language": "de"}],
               "enabled": true},
              {"issuer_id": "old-university", "credential_issuer": "https://old.university.example",
               "display": [{"name": "Old University", "language": "en"}],
               "enabled": false}
            ]}""";

    static final String WALLET_BACKEND_MAPPING = """
            entities:
              - each: $.issuers[*]
                id: { template: "wallet:{$.issuer_id}" }
                roles: [CREDENTIAL_ISSUER]
                display:
                  - { each: "$.display[*]", locale: $.language, name: $.name, logoUri: $.logo }
                identifiers:
                  - { type: URL, value: $.credential_issuer }
                status: { path: $.enabled, values: { "true": ACTIVE }, default: SUSPENDED }
            """;

    @Test
    void fixture1_aWalletBackendsIssuerListWithDisabledIssuersMarked() throws Exception {
        TestContext ctx = new TestContext();
        ctx.put("file:/etc/trust/wallet-backend-mapping.yaml", WALLET_BACKEND_MAPPING);
        ctx.http.json("https://wallet-backend.example/config/issuers.json", WALLET_BACKEND);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, Map.of("location", "https://wallet-backend.example/config/issuers.json",
                "mappingLocation", "file:/etc/trust/wallet-backend-mapping.yaml")))) {
            RegistrySnapshot snap = registry.snapshot();
            TrustedEntity dmv = snap.entity("wallet:utopia-dmv").orElseThrow();
            assertThat(dmv.identifiers()).containsExactly(Identifier.url("https://issuer.utopia.example"));
            assertThat(dmv.displayName("de")).isEqualTo("Utopia Kraftfahrtamt");
            assertThat(dmv.display().getFirst().logoUri()).isEqualTo("https://issuer.utopia.example/logo.png");
            assertThat(dmv.status()).isEqualTo(EntityStatus.ACTIVE);
            assertThat(snap.entity("wallet:old-university").orElseThrow().status()).isEqualTo(EntityStatus.SUSPENDED);
            assertThat(m.states().getFirst().warnings()).isEmpty();
            assertThat(decide(registry, issuer("https://issuer.utopia.example", List.of(), null, null)).decision()).isEqualTo(Decision.TRUSTED);
            assertThat(decide(registry, issuer("https://old.university.example", List.of(), null, null)).decision()).isEqualTo(Decision.NOT_TRUSTED);
        }
        // Or left out: a filter takes the enabled ones only.
        ctx.put("file:/etc/trust/wallet-backend-mapping.yaml", WALLET_BACKEND_MAPPING.replace("$.issuers[*]", "$.issuers[?@.enabled == true]"));
        SourceLoadResult r = source(ctx, Map.of("location", "https://wallet-backend.example/config/issuers.json",
                "mappingLocation", "file:/etc/trust/wallet-backend-mapping.yaml")).load();
        assertThat(r.entities()).extracting(TrustedEntity::id).containsExactly("wallet:utopia-dmv");
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.NOT_SIGNED);
    }

    // 2. A certificate list in the style of the EU Digital COVID Certificate trust list.

    static String dccList() {
        return """
                {"certificates": [
                  {"certificateType": "CSCA", "country": "UT", "kid": "iaca-ut", "rawData": "%s"},
                  {"certificateType": "RPCA", "country": "UT", "kid": "rp-ca-ut", "rawData": "%s"},
                  {"certificateType": "DSC", "country": "UT", "kid": "ds-ut-1", "rawData": "%s"},
                  {"certificateType": "DSC", "country": "UT", "kid": "ds-ut-2", "rawData": "%s"},
                  {"certificateType": "DSC", "country": "NL", "kid": "ds-nl-1", "rawData": "%s"}
                ]}""".formatted(der("iaca"), der("rp-ca"), der("ds"), der("ds-revoked"), der("ds-nl"));
    }

    static final String DCC_MAPPING = """
            # Anchors: the CAs, each in the trust domain its type says.
            anchors:
              - each: $.certificates[?@.certificateType != 'DSC']
                id: { template: "dcc:{$.kid}" }
                domain: { path: $.certificateType, values: { CSCA: mdoc-iaca, RPCA: verifier-access } }
                certificate: $.rawData
                entity: { path: $.certificateType, values: { CSCA: "dcc:issuers" } }
                docTypes: { path: $.certificateType, values: { CSCA: org.iso.18013.5.1.mDL } }
            # Entities: one per country, holding that country's document signers.
            entities:
              - each: $.certificates[?@.certificateType == 'DSC']
                id: { template: "dcc:{$.country}" }
                roles: [CREDENTIAL_ISSUER]
                name: { template: "Document signers of {$.country}" }
                certificates: [$.rawData]
                attributes: { country: $.country }
              # The issuing authorities, which the CSCAs belong to (one record per CSCA; entries with one id are merged).
              - each: $.certificates[?@.certificateType == 'CSCA']
                id: dcc:issuers
                roles: [CREDENTIAL_ISSUER]
                name: Issuing authorities
            """;

    @Test
    void fixture2_aCertificateListInTheStyleOfTheEuDccTrustList() throws Exception {
        TestContext ctx = new TestContext();
        ctx.put("classpath:dcc-mapping.yaml", DCC_MAPPING);
        ctx.http.json("https://dgc.example/trustList", dccList());
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, "dcc", "partner", Map.of("location", "https://dgc.example/trustList",
                "mappingLocation", "classpath:dcc-mapping.yaml")))) {
            assertThat(m.states().getFirst().lastError()).isNull();
            RegistrySnapshot snap = registry.snapshot();
            assertThat(snap.allAnchors()).extracting(a -> a.id() + " " + a.domain()).containsExactlyInAnyOrder(
                    "dcc:iaca-ut mdoc-iaca", "dcc:rp-ca-ut verifier-access");
            TrustAnchor iaca = snap.allAnchors().stream().filter(a -> a.id().equals("dcc:iaca-ut")).findFirst().orElseThrow();
            assertThat(iaca.docTypes()).containsExactly("org.iso.18013.5.1.mDL");
            assertThat(iaca.entityId()).isEqualTo("dcc:issuers");
            // Grouped by country: the two records of UT are one entity with both signers.
            assertThat(snap.entity("dcc:UT").orElseThrow().certificates()).hasSize(2);
            assertThat(snap.entity("dcc:NL").orElseThrow().certificates()).hasSize(1);
            assertThat(snap.entity("dcc:NL").orElseThrow().attributes()).containsEntry("country", "NL");
        }
        // And a decision: the UT document signer chains to the mapped IACA and is the UT entity's pinned certificate.
        TrustDecision d = decide(registry, issuer(null, List.of(der("ds")), "mso_mdoc", "org.iso.18013.5.1.mDL"));
        assertThat(d.decision()).isEqualTo(Decision.TRUSTED);
        assertThat(d.entity().id()).isEqualTo("dcc:issuers");
        assertThat(decide(registry, issuer(null, List.of(der("rogue-ds")), "mso_mdoc", "org.iso.18013.5.1.mDL")).decision())
                .isEqualTo(Decision.UNKNOWN);
    }

    // 3. Another instance of this service: its signed snapshot, mapped back into entities and anchors.

    static final String SNAPSHOT_MAPPING = """
            list:
              issuer: $.iss
              issuedAt: $.iat
              nextUpdate: $.exp
            entities:
              - each: $.entities[*]
                id: $.id
                roles: $.roles[*]
                display:
                  - { each: "$.display[*]", locale: $.locale, name: $.name, description: $.description, logoUri: $.logoUri }
                identifiers:
                  - { each: "$.identifiers[*]", type: $.type, value: $.value }
                certificates: $.certificates[*].certificate
                authorizations:
                  - { each: "$.authorizations[*]", format: $.format, type: $.type }
                status: $.status
                validFrom: $.validFrom
                validUntil: $.validUntil
                metadataPolicy: $.metadataPolicy
            anchors:
              - each: $.anchors[*]
                id: $.id
                domain: $.domain
                certificate: $.certificate
                entity: $.entityId
                status: $.status
                docTypes: $.constraints.docTypes[*]
                crlUrls: $.constraints.crlUrls[*]
            """;

    @SuppressWarnings("unchecked")
    static Map<String, Object> vectorsSnapshot() throws Exception {
        Map<String, Object> vectors = Json.parseObject(Files.readAllBytes(ROOT.resolve("conformance/evaluation/vectors.json")));
        return (Map<String, Object>) ((Map<String, Object>) vectors.get("snapshots")).get("lenient");
    }

    /** What SnapshotService signs: the claims, with iss, aud, iat and exp, as a trust-snapshot+jwt under the service key. */
    static String snapshotJwt(ECKey serviceKey, Map<String, Object> claims, String audience, Instant iat) {
        Map<String, Object> c = new LinkedHashMap<>(claims);
        c.put("iss", "https://upstream-trust.example");
        c.put("aud", audience);
        c.put("iat", iat.getEpochSecond());
        c.put("exp", iat.plus(Duration.ofHours(24)).getEpochSecond());
        return sign(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("trust-snapshot+jwt")).keyID(serviceKey.getKeyID()).build(),
                signer(serviceKey), c);
    }

    @Test
    @SuppressWarnings("unchecked")
    void fixture3_aTrustServiceBehindATrustService() throws Exception {
        ECKey serviceKey = key("upstream-key");
        Map<String, Object> claims = vectorsSnapshot();
        TestContext ctx = new TestContext();
        ctx.put("file:/etc/trust/upstream-mapping.yaml", SNAPSHOT_MAPPING);
        ctx.put("file:/etc/trust/upstream-jwks.json", jwks(serviceKey));
        Instant iat = Instant.now().minusSeconds(60);
        ctx.http.respond("https://upstream-trust.example/api/v1/snapshot", 200, "application/jwt",
                utf8(snapshotJwt(serviceKey, claims, "wallet-proxy-b", iat)));
        Map<String, Object> props = Map.of("location", "https://upstream-trust.example/api/v1/snapshot",
                "headers", Map.of("Authorization", "Bearer upstream-api-key"),
                "format", "jws",
                "verify", Map.of("jwksLocation", "file:/etc/trust/upstream-jwks.json", "typ", "trust-snapshot+jwt", "audience", "wallet-proxy-b"),
                "mappingLocation", "file:/etc/trust/upstream-mapping.yaml");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, "upstream", "partner", props))) {
            var state = m.states().getFirst();
            assertThat(state.lastError()).isNull();
            assertThat(state.warnings()).isEmpty();
            assertThat(state.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
            assertThat(state.listInfo().issuer()).isEqualTo("https://upstream-trust.example");
            assertThat(state.listInfo().issuedAt()).isEqualTo(Instant.ofEpochSecond(iat.getEpochSecond()));
            RegistrySnapshot snap = registry.snapshot();
            // Everything the upstream service listed, and in this service's framework.
            List<Map<String, Object>> entities = (List<Map<String, Object>>) claims.get("entities");
            List<Map<String, Object>> anchors = (List<Map<String, Object>>) claims.get("anchors");
            assertThat(snap.entities()).extracting(TrustedEntity::id)
                    .containsExactlyInAnyOrderElementsOf(entities.stream().map(e -> (String) e.get("id")).toList());
            assertThat(snap.allAnchors()).extracting(TrustAnchor::id)
                    .containsExactlyInAnyOrderElementsOf(anchors.stream().map(a -> (String) a.get("id")).toList());
            assertThat(snap.entities()).allMatch(e -> e.frameworkId().equals("partner"));
            for (Map<String, Object> e : entities) {
                TrustedEntity mapped = snap.entity((String) e.get("id")).orElseThrow();
                assertThat(mapped.status().name()).isEqualTo(e.get("status"));
                assertThat(mapped.identifiers()).hasSameSizeAs((List<?>) e.get("identifiers"));
                assertThat(mapped.authorizations()).hasSameSizeAs((List<?>) e.get("authorizations"));
                assertThat(mapped.certificates()).hasSameSizeAs((List<?>) e.get("certificates"));
                assertThat(mapped.displayName("en")).isEqualTo(((Map<?, ?>) ((List<?>) e.get("display")).getFirst()).get("name"));
                assertThat(mapped.validUntil() == null ? null : mapped.validUntil().toString()).isEqualTo(e.get("validUntil"));
            }
            for (Map<String, Object> a : anchors) {
                TrustAnchor mapped = snap.allAnchors().stream().filter(x -> x.id().equals(a.get("id"))).findFirst().orElseThrow();
                assertThat(mapped.domain().name()).isEqualTo(a.get("domain"));
                assertThat(mapped.entityId()).isEqualTo(a.get("entityId"));
                Object docTypes = ((Map<?, ?>) a.get("constraints")).get("docTypes");
                assertThat(mapped.docTypes()).isEqualTo(docTypes == null ? List.of() : docTypes);
            }
            // The request carried the credential this service has at the upstream one.
            assertThat(ctx.http.requests.getFirst().headers()).containsEntry("Authorization", "Bearer upstream-api-key");
        }
        // It decides as the upstream service did: the first evaluation vector, a document signer under the registered IACA.
        Map<String, Object> first = (Map<String, Object>) ((List<?>) Json.parseObject(Files.readAllBytes(
                ROOT.resolve("conformance/evaluation/vectors.json"))).get("cases")).getFirst();
        Map<String, Object> query = (Map<String, Object>) first.get("query");
        Map<String, Object> context = (Map<String, Object>) query.get("context");
        Map<String, Object> expect = (Map<String, Object>) ((Map<String, Object>) first.get("expect")).get("lenient");
        TrustDecision d = decide(registry, issuer(null, (List<String>) ((Map<String, Object>) query.get("subject")).get("x5c"),
                (String) context.get("credentialFormat"), (String) context.get("credentialType")));
        assertThat(d.decision().name()).isEqualTo(expect.get("decision"));
        assertThat(d.entity().id()).isEqualTo(expect.get("entity"));

        // Another document the upstream key signed is not this one: another type, or a snapshot for another client.
        ctx.http.respond("https://upstream-trust.example/api/v1/snapshot", 200, "application/jwt",
                utf8(sign(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("trust-metadata+jwt")).keyID("upstream-key").build(),
                        signer(serviceKey), Map.of("entities", List.of()))));
        assertThatThrownBy(() -> source(ctx, "upstream", "partner", props).load()).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("typ is 'trust-metadata+jwt'");
        ctx.http.respond("https://upstream-trust.example/api/v1/snapshot", 200, "application/jwt",
                utf8(snapshotJwt(serviceKey, claims, "another-client", iat)));
        assertThatThrownBy(() -> source(ctx, "upstream", "partner", props).load()).hasMessageContaining("addressed to 'another-client'");
        ctx.http.respond("https://upstream-trust.example/api/v1/snapshot", 200, "application/jwt",
                utf8(snapshotJwt(serviceKey, claims, "wallet-proxy-b", Instant.now().minus(Duration.ofDays(2)))));
        assertThatThrownBy(() -> source(ctx, "upstream", "partner", props).load()).hasMessageContaining("expired");
    }

    // 4. A registry that is asked per identifier.

    static final String LOOKUP_MAPPING = """
            lookup:
              url: "https://registry.partner.example/v1/issuers/{identifier}"
              identifierTypes: [DID]
              startsWith: ["did:example:"]
              entity:
                id: { template: "partner:{$.number}" }
                roles: [CREDENTIAL_ISSUER]
                name: $.legal_name
                identifiers:
                  - { type: DID, value: $.did }
                authorizations:
                  - { each: "$.accreditations[?@.valid == true]", format: $.format, type: $.vct }
                status: { path: $.state, values: { active: ACTIVE, suspended: SUSPENDED }, default: REVOKED }
            """;

    @Test
    void fixture4_aRegistryThatIsAskedPerIdentifier() throws Exception {
        TestContext ctx = new TestContext();
        ctx.put("file:/etc/trust/lookup-mapping.yaml", LOOKUP_MAPPING);
        ctx.http.json("https://registry.partner.example/v1/issuers/did%3Aexample%3Auniversity", """
                {"number": "4711", "did": "did:example:university", "legal_name": "Example University", "state": "active",
                 "accreditations": [{"format": "dc+sd-jwt", "vct": "https://credentials.example/diploma", "valid": true},
                                    {"format": "dc+sd-jwt", "vct": "https://credentials.example/transcript", "valid": false}]}""");
        ctx.http.json("https://registry.partner.example/v1/issuers/did%3Aexample%3Aclosed", """
                {"number": "13", "did": "did:example:closed", "legal_name": "Closed College", "state": "closed", "accreditations": []}""");
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager m = manager(registry, source(ctx, Map.of("mappingLocation", "file:/etc/trust/lookup-mapping.yaml")))) {
            assertThat(m.ready()).isTrue();
            assertThat(registry.snapshot().entities()).isEmpty();
            TrustedEntity uni = m.resolveOnDemand(Identifier.did("did:example:university"), f -> true).orElseThrow();
            assertThat(uni.id()).isEqualTo("partner:4711");
            assertThat(uni.frameworkId()).isEqualTo("partner");
            assertThat(uni.displayName("en")).isEqualTo("Example University");
            assertThat(uni.isAuthorizedFor("dc+sd-jwt", "https://credentials.example/diploma", true)).isTrue();
            assertThat(uni.isAuthorizedFor("dc+sd-jwt", "https://credentials.example/transcript", true)).isFalse();
            assertThat(uni.provenance().sourceUri()).isNull();
            assertThat(m.resolveOnDemand(Identifier.did("did:example:closed"), f -> true).orElseThrow().status()).isEqualTo(EntityStatus.REVOKED);
            assertThat(m.resolveOnDemand(Identifier.did("did:example:unknown"), f -> true)).isEmpty();
            // A client that does not see the framework does not make the service ask.
            int asked = ctx.http.requests.size();
            assertThat(m.resolveOnDemand(Identifier.did("did:example:other"), f -> false)).isEmpty();
            assertThat(m.resolveOnDemand(Identifier.did("did:web:university.example"), f -> true)).isEmpty();
            assertThat(ctx.http.requests).hasSize(asked);
        }
    }
}
