package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.core.did.DidResolver;
import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.X509PathValidator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An entity or anchor entry of the registry format holds only the members the format documents, each of its type, and
 * so do the objects in it that are read member by member (an identifier, a display entry, an authorization, a
 * context). Anything else makes the entry unreadable, and the registry is not loaded: an entity written with
 * {@code staus: REVOKED} would otherwise be active, and an anchor whose {@code docTypes} is not a list unconstrained.
 */
class RegistryFormatTest {

    static final TestPki.Issued CA = TestPki.rootCa("CN=Format CA,C=UT");
    static final TestPki.Issued SIGNER = TestPki.leaf("CN=Format Signer,C=UT", CA, List.of(), null);
    static final String PEM = Certificates.toPem(SIGNER.certificate());
    static final String CA_PEM = Certificates.toPem(CA.certificate());

    final TestContext ctx = new TestContext();
    final SourceDefinition def = new SourceDefinition("list", "static", "fw", null, true, Map.of("location", "mem:registry.yaml"));

    SourceLoadResult load(String yaml) throws TrustSourceException {
        ctx.put("mem:registry.yaml", yaml);
        return new StaticTrustSourceFactory().create(def, ctx).load();
    }

    /** One entity, written with {@code members} (YAML flow mappings, indented as members of the entry). */
    static String entity(String members) {
        return "entities:\n  - id: acme\n" + members.indent(4);
    }

    static String anchor(String members) {
        return "anchors:\n  - id: ca\n    domain: credential-issuer\n    certificate: |\n" + CA_PEM.indent(6) + members.indent(4);
    }

    void unreadable(String yaml, String... says) {
        assertThatThrownBy(() -> load(yaml)).as(yaml).isInstanceOf(TrustSourceException.class)
                .satisfies(e -> assertThat(e.getMessage()).as(yaml).contains(says));
    }

    @Test
    void anUnknownMemberMakesAnEntryUnreadable() {
        unreadable(entity("roles: [CREDENTIAL_ISSUER]\nstaus: REVOKED"), "entity 'acme' cannot be read: unknown member 'staus'");
        unreadable(entity("Status: REVOKED"), "unknown member 'Status'");
        unreadable(entity("validuntil: 2020-01-01"), "unknown member 'validuntil'");
        unreadable(entity("identifier: https://acme.example"), "unknown member 'identifier'");
        unreadable(anchor("staus: REVOKED"), "anchor 'ca' cannot be read: unknown member 'staus'");
        unreadable(anchor("docTypes: [org.iso.18013.5.1.mDL]"), "unknown member 'docTypes'");
        unreadable(anchor("crlUrls: [https://pki.example/ca.crl]"), "unknown member 'crlUrls'");
        // In the objects that are read member by member, too.
        unreadable(entity("identifiers:\n  - {type: URL, vaule: https://acme.example}"), "identifiers[0]: unknown member 'vaule'");
        unreadable(entity("identifiers:\n  - {type: URL, value: https://acme.example, status: REVOKED}"), "identifiers[0]: unknown member 'status'");
        unreadable(entity("display:\n  - {locale: en, nmae: Acme}"), "display[0]: unknown member 'nmae'");
        unreadable(entity("authorizations:\n  - {formt: mso_mdoc, type: org.iso.18013.5.1.mDL}"), "authorizations[0]: unknown member 'formt'");
        unreadable(entity("contexts:\n  - {url: https://acme.example/ctx, sha: abc}"), "contexts[0]: unknown member 'sha'");
        // The registry itself holds entities and anchors only: a misspelt list would load nothing from it.
        unreadable("entites:\n  - {id: acme, roles: [VERIFIER]}\n", "unknown member 'entites'");
    }

    @Test
    void aMemberOfTheWrongTypeMakesAnEntryUnreadable() {
        unreadable("entities:\n  - {id: 7, roles: [VERIFIER]}\n", "entity entities[0] cannot be read: 'id' must be text, not a number");
        unreadable(entity("roles: 7"), "'roles' must be a list of role names or one role name, not a number");
        unreadable(entity("roles: [CREDENTIAL_ISSUER, 7]"), "'roles[1]' must be a role name, not a number");
        unreadable(entity("roles: [{role: VERIFIER}]"), "'roles[0]' must be a role name, not an object");
        unreadable(entity("identifiers: https://acme.example"), "'identifiers' must be a list, not text");
        unreadable(entity("identifiers: [7]"), "'identifiers[0]' must be text or an object with type and value, not a number");
        unreadable(entity("identifiers: [[https://acme.example]]"), "'identifiers[0]' must be text or an object with type and value, not a list");
        unreadable(entity("identifiers:\n  - {type: URL}"), "identifiers[0]: 'value' is missing");
        unreadable(entity("identifiers:\n  - {value: https://acme.example}"), "identifiers[0]: 'type' is missing");
        unreadable(entity("identifiers:\n  - {type: URL, value: 7}"), "identifiers[0]: 'value' must be text, not a number");
        unreadable(entity("status: [REVOKED]"), "'status' must be one of the statuses, not a list");
        unreadable(entity("status: REVOKD"), "Unknown status 'REVOKD'");
        unreadable(entity("status:"), "'status' has no value");
        unreadable(entity("validUntil: 2030-01-32T00:00:00Z"), "'validUntil' is not a date: '2030-01-32T00:00:00Z'");
        unreadable(entity("validFrom: yesterday"), "'validFrom' is not a date: 'yesterday'");
        unreadable(entity("validUntil: 1700000000"), "'validUntil' must be a date, not a number");
        unreadable(entity("certificates: |\n" + PEM.indent(2)), "'certificates' must be a list of certificates, not text");
        unreadable(entity("certificates: [not a certificate]"), "'certificates[0]' is not a certificate");
        unreadable(entity("certificates: [7]"), "'certificates[0]' must be a certificate (PEM or base64 DER), not a number");
        unreadable(entity("certificates:\n  - |\n" + (PEM + "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n").indent(4)),
                "'certificates[0]' holds something that is not a certificate");
        unreadable(entity("certificate: [x]"), "'certificate' must be a certificate (PEM or base64 DER), not a list");
        unreadable(entity("certificateJsonField: pem"), "'certificateJsonField' is read only with 'certificateLocation'");
        unreadable(entity("name: [Acme]"), "'name' must be text, not a list");
        unreadable(entity("name: Acme\ndisplay:\n  - {locale: en, name: Acme}"), "both 'name' and 'display'");
        unreadable(entity("display: {locale: en, name: Acme}"), "'display' must be a list, not an object");
        unreadable(entity("display: [Acme]"), "'display[0]' must be an object, not text");
        unreadable(entity("display:\n  - {locale: en, name: Acme, logoUri: 7}"), "display[0]: 'logoUri' must be text, not a number");
        unreadable(entity("authorizations: {format: mso_mdoc}"), "'authorizations' must be a list, not an object");
        unreadable(entity("authorizations: [mso_mdoc]"), "'authorizations[0]' must be an object, not text");
        unreadable(entity("authorizations:\n  - {format: mso_mdoc, type: 7}"), "authorizations[0]: 'type' must be text, not a number");
        unreadable(entity("authorizations:\n  - {format: mso_mdoc, constraints: 7}"), "authorizations[0]: 'constraints' must be an object, not a number");
        unreadable(entity("contexts: https://acme.example/ctx"), "'contexts' must be a list, not text");
        unreadable(entity("contexts: [7]"), "'contexts[0]' must be a URL or an object with url and sha256, not a number");
        unreadable(entity("contexts:\n  - {sha256: abc}"), "contexts[0]: 'url' is missing");
        unreadable(entity("metadata: 7"), "'metadata' must be an object, not a number");
        unreadable(entity("metadata: {openid_credential_issuer: 7}"), "'metadata.openid_credential_issuer' must be an object, not a number");
        unreadable(entity("metadataPolicy: [x]"), "'metadataPolicy' must be an object, not a list");
        unreadable(entity("metadataPolicy: {oauth_authorization_server: [x]}"), "'metadataPolicy.oauth_authorization_server' must be an object, not a list");
        unreadable(entity("attributes: [x]"), "'attributes' must be an object, not a list");
        unreadable(entity("attributes: {country:}"), "'attributes.country' has no value");
        unreadable(entity("framework: [fw]"), "'framework' must be text, not a list");
        unreadable(anchor("status: 7"), "'status' must be one of the statuses, not a number");
        unreadable(anchor("entity: [acme]"), "'entity' must be text, not a list");
        unreadable(anchor("constraints: [org.iso.18013.5.1.mDL]"), "'constraints' must be an object, not a list");
        unreadable(anchor("constraints: {docTypes: org.iso.18013.5.1.mDL}"), "'constraints.docTypes' must be a list of doctypes, not text");
        unreadable(anchor("constraints: {docTypes: [7]}"), "'constraints.docTypes[0]' must be a doctype, not a number");
        unreadable(anchor("constraints: {crlUrls: 7}"), "'constraints.crlUrls' must be a URL or a list of URLs, not a number");
        unreadable(anchor("constraints: {crlUrls: [7]}"), "'constraints.crlUrls[0]' must be a URL, not a number");
        unreadable(anchor("constraints: {crl: [x]}"), "'constraints.crl' must be a CRL (PEM or base64 DER), not a list");
        unreadable(anchor("constraints: {crl:}"), "'constraints.crl' has no value");
        // constraints is free-form, but a member the service reads, written another way, would be read as absent.
        for (String[] nearMiss : new String[][]{{"doctypes", "docTypes"}, {"DocTypes", "docTypes"}, {"doc_types", "docTypes"},
                {"doc-types", "docTypes"}, {"DOC_TYPES", "docTypes"}, {"crlurls", "crlUrls"}, {"crl_urls", "crlUrls"}, {"CRL-URLs", "crlUrls"},
                {"CRL", "crl"}, {"Crl", "crl"}, {"_crl", "crl"}}) {
            unreadable(anchor("constraints: {\"" + nearMiss[0] + "\": [x]}"), "anchor 'ca' cannot be read: 'constraints." + nearMiss[0]
                    + "' is written another way than '" + nearMiss[1] + "', the name the service reads");
        }
        unreadable("entities:\n  - {id: acme}\n  - 7\n", "entity entities[1] cannot be read: it is not an object");
        unreadable("entities: {acme: {roles: [VERIFIER]}}\n", "'entities' must be a list, not an object");
        unreadable("anchors: 7\n", "'anchors' must be a list, not a number");
        unreadable("- {id: acme}\n", "must be an object");
    }

    @Test
    void everyDocumentedMemberIsRead() throws Exception {
        String full = """
                entities:
                  - id: acme
                    framework: fw
                    roles: [CREDENTIAL_ISSUER, verifier]
                    display:
                      - {locale: en, name: Acme, description: An issuer, logoUri: "https://acme.example/logo.png"}
                    identifiers:
                      - {type: URL, value: "https://acme.example"}
                      - did:web:acme.example
                    certificates:
                      - |
                %s
                    certificate: %s
                    authorizations:
                      - {format: mso_mdoc, type: org.iso.18013.5.1.mDL, constraints: {anything: [1, 2]}}
                      - {format: dc+sd-jwt}
                    contexts:
                      - https://acme.example/contexts/v1
                      - {url: "https://acme.example/contexts/v2", sha256: "pinned"}
                    status: suspended
                    validFrom: 2020-01-01
                    validUntil: 2099-12-31T00:00:00Z
                    metadata:
                      openid_credential_issuer: {credential_issuer: "https://acme.example", nested: {free: [form]}}
                    metadataPolicy:
                      oauth_authorization_server: {token_endpoint: {value: "https://acme.example/token"}}
                    attributes: {country: UT, anything: {free: form}}
                  - id: plain
                    name: Plain
                    roles: VERIFIER
                anchors:
                  - id: ca
                    framework: fw
                    domain: mdoc-iaca
                    entity: acme
                    status: REVOKED
                    certificate: |
                %s
                    constraints: {docTypes: [org.iso.18013.5.1.mDL], crlUrls: "https://pki.example/ca.crl", crl: "%s", serviceType: free-form}
                  - domain: credential-issuer
                    certificates: ["%s", "%s"]
                """.formatted(PEM.indent(8), Certificates.toBase64(CA.certificate()), CA_PEM.indent(6),
                java.util.Base64.getEncoder().encodeToString(TestPki.crl(CA).getEncoded()),
                Certificates.toBase64(CA.certificate()), Certificates.toBase64(SIGNER.certificate()));
        var r = load(full);
        assertThat(r.warnings()).isEmpty();
        assertThat(r.entities()).hasSize(2);
        var acme = r.entities().getFirst();
        assertThat(acme.roles()).containsExactlyInAnyOrder(EntityRole.CREDENTIAL_ISSUER, EntityRole.VERIFIER);
        assertThat(acme.display()).singleElement().satisfies(d -> assertThat(d.logoUri()).isEqualTo("https://acme.example/logo.png"));
        assertThat(acme.identifiers()).extracting(i -> i.type()).containsExactly(IdentifierType.URL, IdentifierType.DID);
        assertThat(acme.certificates()).hasSize(2);
        assertThat(acme.authorizations()).hasSize(2);
        assertThat(acme.status()).isEqualTo(EntityStatus.SUSPENDED);
        assertThat(acme.validFrom()).isEqualTo(Instant.parse("2020-01-01T00:00:00Z"));
        assertThat(acme.validUntil()).isEqualTo(Instant.parse("2099-12-31T00:00:00Z"));
        assertThat(acme.metadata()).containsKey("openid_credential_issuer");
        assertThat(acme.metadataPolicy()).containsKey("oauth_authorization_server");
        assertThat(acme.attributes()).containsKeys("country", "anything", "jsonLdContexts");
        assertThat(r.entities().get(1).roles()).containsExactly(EntityRole.VERIFIER);
        assertThat(r.entities().get(1).displayName("en")).isEqualTo("Plain");
        assertThat(r.anchors()).extracting(a -> a.id()).containsExactly("ca", "credential-issuer:" + Certificates.sha256Thumbprint(CA.certificate()),
                "credential-issuer:" + Certificates.sha256Thumbprint(SIGNER.certificate()));
        assertThat(r.anchors().getFirst().status()).isEqualTo(EntityStatus.REVOKED);
        assertThat(r.anchors().getFirst().docTypes()).containsExactly("org.iso.18013.5.1.mDL");
        assertThat(r.anchors().getFirst().crlUrls()).containsExactly("https://pki.example/ca.crl");
    }

    /** An entity with one identifier, written as JSON (which is YAML) so that any value can be written. */
    SourceLoadResult withIdentifier(String type, String value) throws TrustSourceException {
        return load(io.vctrust.trust.core.json.Json.write(Map.of("entities", List.of(Map.of("id", "acme",
                "identifiers", List.of(Map.of("type", type, "value", value)))))));
    }

    @Test
    @SuppressWarnings("unchecked")
    void aHashOrKeyIdentifierIsWrittenInAFormItCanBeComparedIn() throws Exception {
        // X509_SHA256: a digest written in any of the ways the shared list gives reads as base64url; anything else cannot be
        // read, where before it was kept as written and bound no certificate.
        java.nio.file.Path root = java.nio.file.Path.of("").toAbsolutePath();
        while (!java.nio.file.Files.isDirectory(root.resolve("conformance"))) {
            root = root.getParent();
        }
        Map<String, Object> forms = io.vctrust.trust.core.json.Json.parseObject(
                java.nio.file.Files.readAllBytes(root.resolve("conformance/evaluation/identifiers.json")));
        for (Map<String, Object> same : (List<Map<String, Object>>) forms.get("same")) {
            if ("X509_SHA256".equals(same.get("type"))) {
                for (String value : (List<String>) same.get("values")) {
                    assertThat(withIdentifier("X509_SHA256", value).entities().getFirst().identifiers()).as(value)
                            .singleElement().satisfies(i -> assertThat(i.value()).isEqualTo(same.get("key")));
                }
            }
        }
        for (Map<String, Object> unchanged : (List<Map<String, Object>>) forms.get("unchanged")) {
            if ("X509_SHA256".equals(unchanged.get("type"))) {
                for (String value : (List<String>) unchanged.get("values")) {
                    assertThatThrownBy(() -> withIdentifier("X509_SHA256", value)).as("'%s'", value)
                            .hasMessageContaining("identifiers[0]: 'value' is not a SHA-256 digest");
                }
            }
        }
        // X509_SKI: the key identifier's bytes in unpadded base64url, as both evaluators compute it. Hexadecimal without
        // separators cannot be told from base64url, and is read (and matches nothing unless it is that form).
        for (String value : List.of("q3vf", "q3vfAQ", "q3vfAQ8", "1b75f1e2577c439a0ff3fc9bb43dbe939ad3c277", "_-8")) {
            assertThat(withIdentifier("X509_SKI", value).entities().getFirst().identifiers()).as(value)
                    .singleElement().satisfies(i -> assertThat(i.value()).isEqualTo(value));
        }
        for (String value : List.of("", "AB:CD:EF:01", "ab cd ef", "q3vfAQ==", "q3vf+Q", "q3vf/Q", "q3vfA", "q3vfAR", "q3vfAQ9")) {
            assertThatThrownBy(() -> withIdentifier("X509_SKI", value)).as("'%s'", value)
                    .hasMessageContaining("identifiers[0]: 'value' is not a subject key identifier in unpadded base64url");
        }
        // JWK_THUMBPRINT: an RFC 7638 SHA-256 thumbprint in unpadded base64url, 43 characters.
        String thumbprint = "G3Xx4ld8Q5oP8_ybtD2-k5rTwnc4WL1wH376TGb2HSo";
        assertThat(withIdentifier("JWK_THUMBPRINT", thumbprint).entities().getFirst().identifiers()).singleElement()
                .satisfies(i -> assertThat(i.value()).isEqualTo(thumbprint));
        for (String value : List.of("1b75f1e2577c439a0ff3fc9bb43dbe939ad3c2773858bd701f7efa4c66f61d2a", "G3Xx4ld8Q5oP8/ybtD2+k5rTwnc4WL1wH376TGb2HSo=",
                thumbprint + "=", thumbprint.substring(0, 42), thumbprint.substring(0, 42) + "p", "q3vf", "")) {
            assertThatThrownBy(() -> withIdentifier("JWK_THUMBPRINT", value)).as("'%s'", value)
                    .hasMessageContaining("identifiers[0]: 'value' is not a JWK thumbprint");
        }
    }

    @Test
    void aCertificateFetchedFromALocationIsHeldToTheSameRules() throws Exception {
        ctx.http.json("https://pki.example/ca.json", "{\"pem\": " + io.vctrust.trust.core.json.Json.write(CA_PEM) + ", \"other\": 7}");
        ctx.put("https://pki.example/ca.pem", CA_PEM + "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n");
        String located = "anchors:\n  - {domain: credential-issuer, certificateLocation: \"https://pki.example/ca.json\", certificateJsonField: %s}\n";
        assertThat(load(located.formatted("pem")).anchors()).hasSize(1);
        unreadable(located.formatted("other"), "'certificateLocation' field 'other' must be a certificate (PEM or base64 DER), not a number");
        unreadable(located.formatted("[pem]"), "'certificateJsonField' must be text, not a list");
        unreadable("anchors:\n  - {domain: credential-issuer, certificateLocation: \"https://pki.example/ca.pem\"}\n",
                "'certificateLocation' holds something that is not a certificate");
    }

    // Decisions: what the parser used to read as absent kept a restriction from the decision.

    static final TestPki.Issued IACA = TestPki.iaca("CN=Format IACA,C=UT");
    static final TestPki.Issued DS = TestPki.documentSigner("CN=Format DS,C=UT", IACA);

    static String registry(String acme, String constraints) {
        return """
                entities:
                  - id: acme
                    roles: [CREDENTIAL_ISSUER]
                    certificates:
                      - |
                %s
                %s
                anchors:
                  - id: iaca
                    domain: mdoc-iaca
                    certificate: |
                %s
                    constraints: %s
                """.formatted(Certificates.toPem(DS.certificate()).indent(8), acme.indent(4), Certificates.toPem(IACA.certificate()).indent(6), constraints);
    }

    Decision decide(TrustRegistry registry, TrustSourceManager sources, String docType) {
        return new TrustEvaluator(registry, sources, new DidResolver(List.of()), new X509PathValidator(), Clock.systemUTC(), Duration.ofHours(1))
                .evaluate(new TrustQuery(EntityRole.CREDENTIAL_ISSUER,
                        new TrustQuery.Subject(null, List.of(Certificates.toBase64(DS.certificate())), null, null),
                        new TrustQuery.Context("oid4vci", "mso_mdoc", docType, null, null, List.of())), ClientProfile.unrestricted("wallet")).decision();
    }

    TrustSourceManager manager(TrustRegistry registry) {
        return new TrustSourceManager(registry, List.of(new TrustFramework("fw", "Framework", null, null, null)),
                List.of(new StaticTrustSourceFactory().create(new SourceDefinition("list", "static", "fw", null, true, true,
                        Map.of("location", "mem:registry.yaml")), ctx)), Clock.systemUTC());
    }

    @Test
    void aMisspeltStatusDoesNotMakeARevokedPartyActive() {
        ctx.put("mem:registry.yaml", registry("status: REVOKED", "{docTypes: [org.iso.18013.5.1.mDL]}"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry)) {
            sources.start();
            assertThat(decide(registry, sources, "org.iso.18013.5.1.mDL")).isEqualTo(Decision.NOT_TRUSTED);
            // Read as absent, the misspelt member left the entry ACTIVE, and the party was trusted through its IACA.
            ctx.put("mem:registry.yaml", registry("staus: REVOKED", "{docTypes: [org.iso.18013.5.1.mDL]}"));
            assertThat(sources.refresh("list").lastError()).contains("entity 'acme' cannot be read: unknown member 'staus'");
            assertThat(decide(registry, sources, "org.iso.18013.5.1.mDL")).isEqualTo(Decision.NOT_TRUSTED);
        }
        // Loaded for the first time so, the list keeps the service not ready rather than trusting the party.
        var fresh = new TrustRegistry();
        try (var sources = manager(fresh)) {
            sources.start();
            assertThat(sources.ready()).isFalse();
            assertThat(fresh.snapshot().entities()).isEmpty();
        }
    }

    @Test
    void aDoctypeConstraintThatIsNotAListDoesNotLeaveTheAnchorUnconstrained() {
        ctx.put("mem:registry.yaml", registry("status: ACTIVE", "{docTypes: [org.iso.18013.5.1.mDL]}"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry)) {
            sources.start();
            assertThat(decide(registry, sources, "org.iso.18013.5.1.mDL")).isEqualTo(Decision.TRUSTED);
            assertThat(decide(registry, sources, "eu.europa.ec.eudi.pid.1")).isEqualTo(Decision.NOT_TRUSTED);
            // Read as absent, a doctype written without brackets made the IACA an anchor for every doctype.
            ctx.put("mem:registry.yaml", registry("status: ACTIVE", "{docTypes: org.iso.18013.5.1.mDL}"));
            assertThat(sources.refresh("list").lastError()).contains("anchor 'iaca' cannot be read: 'constraints.docTypes' must be a list of doctypes");
            assertThat(decide(registry, sources, "eu.europa.ec.eudi.pid.1")).isEqualTo(Decision.NOT_TRUSTED);
        }
    }

    @Test
    void aDoctypeConstraintWrittenAnotherWayDoesNotLeaveTheAnchorUnconstrained() throws Exception {
        // Other names stay free-form: only a near miss of a member the service reads is refused.
        assertThat(load(anchor("constraints: {docType: x, doctype: x, crls: [x], crlUrl: x, serviceType: x, doc.types: x}")).anchors()).hasSize(1);

        // Read as absent, "doctypes" made the IACA an anchor for every doctype: a PID under it was TRUSTED.
        ctx.put("mem:registry.yaml", registry("status: ACTIVE", "{doctypes: [org.iso.18013.5.1.mDL]}"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry)) {
            sources.start();
            assertThat(decide(registry, sources, "eu.europa.ec.eudi.pid.1")).isNotEqualTo(Decision.TRUSTED);
            assertThat(sources.states().getFirst().lastError()).contains("anchor 'iaca' cannot be read: 'constraints.doctypes' is written another way than 'docTypes'");
            assertThat(sources.ready()).isFalse();
        }
        // Loaded with the constraint first, the edit does not take it away.
        ctx.put("mem:registry.yaml", registry("status: ACTIVE", "{docTypes: [org.iso.18013.5.1.mDL]}"));
        var constrained = new TrustRegistry();
        try (var sources = manager(constrained)) {
            sources.start();
            assertThat(decide(constrained, sources, "eu.europa.ec.eudi.pid.1")).isEqualTo(Decision.NOT_TRUSTED);
            ctx.put("mem:registry.yaml", registry("status: ACTIVE", "{doctypes: [org.iso.18013.5.1.mDL]}"));
            assertThat(sources.refresh("list").lastError()).contains("'constraints.doctypes'");
            assertThat(decide(constrained, sources, "eu.europa.ec.eudi.pid.1")).isEqualTo(Decision.NOT_TRUSTED);
            assertThat(decide(constrained, sources, "org.iso.18013.5.1.mDL")).isEqualTo(Decision.TRUSTED);
        }
    }

    @Test
    void anIdentifierOfTheWrongShapeIsNotDropped() {
        ctx.put("mem:registry.yaml", registry("status: REVOKED", "{}").replace("    certificates:\n", "    identifiers: [7]\n    certificates:\n"));
        var registry = new TrustRegistry();
        try (var sources = manager(registry)) {
            sources.start();
            assertThat(sources.states().getFirst().lastError()).contains("entity 'acme' cannot be read: 'identifiers[0]' must be text or an object");
            assertThat(sources.ready()).isFalse();
        }
    }
}
