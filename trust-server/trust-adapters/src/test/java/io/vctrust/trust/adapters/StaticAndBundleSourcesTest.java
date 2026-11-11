package io.vctrust.trust.adapters;

import io.vctrust.trust.adapters.oid4vci.Oid4vciDiscoverySourceFactory;
import io.vctrust.trust.adapters.statik.StaticTrustSourceFactory;
import io.vctrust.trust.adapters.x509.X509BundleSourceFactory;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StaticAndBundleSourcesTest {

    @Test
    void staticRegistryParsesEntitiesAnchorsAndPolicies() throws Exception {
        var iaca = TestPki.rootCa("CN=IACA,C=UT");
        String yaml = """
                entities:
                  - id: utopia-dmv
                    roles: [CREDENTIAL_ISSUER]
                    name: Utopia DMV
                    identifiers:
                      - {type: URL, value: "https://issuer.example/utopia"}
                      - did:web:issuer.example
                    authorizations:
                      - {format: mso_mdoc, type: org.iso.18013.5.1.mDL}
                      - {format: vc+sd-jwt, type: "urn:eudi:pid:1"}
                    metadataPolicy:
                      oauth_authorization_server:
                        token_endpoint: {default: "https://issuer.example/token"}
                anchors:
                  - domain: mdoc-iaca
                    entity: utopia-dmv
                    constraints: {docTypes: [org.iso.18013.5.1.mDL]}
                    certificate: |
                %s
                """.formatted(Certificates.toPem(iaca.certificate()).indent(6));
        var ctx = new TestContext().put("mem:reg.yaml", yaml);
        var def = new SourceDefinition("s", "static", "utopia", null, true, Map.of("location", "mem:reg.yaml"));
        var r = new StaticTrustSourceFactory().create(def, ctx).load();
        assertThat(r.warnings()).isEmpty();
        var e = r.entities().getFirst();
        assertThat(e.frameworkId()).isEqualTo("utopia");
        assertThat(e.hasRole(EntityRole.CREDENTIAL_ISSUER)).isTrue();
        assertThat(e.identifiers()).extracting(i -> i.type()).contains(IdentifierType.URL, IdentifierType.DID);
        assertThat(e.authorizations()).extracting(a -> a.format()).containsExactly("mso_mdoc", "dc+sd-jwt");
        assertThat(e.metadataPolicy()).containsKey("oauth_authorization_server");
        assertThat(r.anchors()).hasSize(1);
        assertThat(r.anchors().getFirst().docTypes()).containsExactly("org.iso.18013.5.1.mDL");
        assertThat(r.anchors().getFirst().entityId()).isEqualTo("utopia-dmv");
    }

    @Test
    void aDocumentCannotPlaceItsEntriesInAnotherFramework() throws Exception {
        var ca = TestPki.rootCa("CN=Partner CA,C=UT");
        String yaml = """
                entities:
                  - {id: partner, roles: [CREDENTIAL_ISSUER], identifiers: ["https://partner.example"]}
                  - {id: same, framework: sandbox, roles: [CREDENTIAL_ISSUER], identifiers: ["https://same.example"]}
                  - {id: evil, framework: gov, roles: [CREDENTIAL_ISSUER], identifiers: ["https://evil.example"]}
                anchors:
                  - domain: credential-issuer
                    framework: gov
                    certificate: |
                %s
                """.formatted(Certificates.toPem(ca.certificate()).indent(6));
        var def = new SourceDefinition("partner-list", "static", "sandbox", null, true, Map.of("location", "mem:reg.yaml"));
        var r = new StaticTrustSourceFactory().create(def, new TestContext().put("mem:reg.yaml", yaml)).load();
        // The list is configured for the sandbox: what it says about another framework is not loaded at all.
        assertThat(r.entities()).extracting(e -> e.id() + " in " + e.frameworkId()).containsExactly("partner in sandbox", "same in sandbox");
        assertThat(r.anchors()).isEmpty();
        assertThat(r.warnings()).hasSize(2).allMatch(w -> w.contains("names framework 'gov'"));
    }

    @Test
    void aRegistryFetchedFromElsewhereCannotNameFilesOfThisHost() throws Exception {
        var ca = TestPki.rootCa("CN=Partner CA,C=UT");
        String yaml = """
                anchors:
                  - {domain: credential-issuer, certificateLocation: "classpath:etsi/eu-lotl.xml"}
                  - {domain: credential-issuer, certificateLocation: "/etc/hosts"}
                  - {domain: credential-issuer, certificateLocation: "file:///etc/hosts"}
                  - {domain: credential-issuer, certificateLocation: "https://partner.example/ca.pem"}
                """;
        var ctx = new TestContext().put("https://partner.example/registry.yaml", yaml)
                .put("https://partner.example/ca.pem", Certificates.toPem(ca.certificate())).put("mem:local.yaml", yaml);
        var remote = new StaticTrustSourceFactory().create(new SourceDefinition("partner", "static", "sandbox", null, true,
                Map.of("location", "https://partner.example/registry.yaml")), ctx).load();
        assertThat(remote.anchors()).singleElement().satisfies(a -> assertThat(a.certificate()).isEqualTo(ca.certificate()));
        assertThat(remote.warnings()).hasSize(3).allMatch(w -> w.contains("Only an http(s) location"));
    }

    @Test
    void x509BundleFromJsonField() throws Exception {
        var ca = TestPki.rootCa("CN=Animo,C=NL");
        var ctx = new TestContext();
        ctx.http.json("https://playground.example/api/x509", "{\"base64\":\"" + Certificates.toBase64(ca.certificate()) + "\"}");
        Map<String, Object> remote = Map.of("domain", "mdoc-iaca", "certificateLocation", "https://playground.example/api/x509",
                "certificateJsonField", "base64", "docTypes", List.of("org.iso.18013.5.1.mDL"));
        // Whoever answers at a URL must not decide what is trusted: a fetched certificate needs a pinned fingerprint.
        assertThatThrownBy(() -> new X509BundleSourceFactory().create(new SourceDefinition("b", "x509-bundle", "animo", null, true, remote), ctx).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("need sha256 fingerprints");
        var other = TestPki.rootCa("CN=Someone else,C=NL");
        assertThatThrownBy(() -> new X509BundleSourceFactory().create(new SourceDefinition("b", "x509-bundle", "animo", null, true,
                with(remote, "sha256", List.of(Certificates.sha256Thumbprint(other.certificate())))), ctx).load())
                .isInstanceOf(TrustSourceException.class).hasMessageContaining("not among the pinned fingerprints");
        // The fingerprint as openssl prints it (hex with colons) or as base64url.
        String hex = java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(
                java.util.Base64.getUrlDecoder().decode(Certificates.sha256Thumbprint(ca.certificate())));
        var def = new SourceDefinition("b", "x509-bundle", "animo", null, true, with(remote, "sha256", List.of(hex)));
        var r = new X509BundleSourceFactory().create(def, ctx).load();
        assertThat(r.anchors()).singleElement().satisfies(a -> {
            assertThat(a.domain()).isEqualTo(TrustDomain.MDOC_IACA);
            assertThat(a.certificate()).isEqualTo(ca.certificate());
            assertThat(a.docTypes()).containsExactly("org.iso.18013.5.1.mDL");
        });
    }

    @Test
    void oid4vciDiscoveryBuildsIssuerEntities() throws Exception {
        var ctx = new TestContext();
        ctx.http.json("https://issuer.example/.well-known/openid-credential-issuer/t1", """
                {"credential_issuer":"https://issuer.example/t1","credential_endpoint":"https://issuer.example/t1/credential",
                 "display":[{"name":"Tenant One","locale":"en","logo":{"uri":"https://issuer.example/logo.png"}}],
                 "credential_configurations_supported":{
                   "mdl":{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"},
                   "degree":{"format":"ldp_vc","credential_definition":{"@context":["https://www.w3.org/ns/credentials/v2","https://issuer.example/contexts/degree/v1"],"type":["VerifiableCredential","UniversityDegreeCredential"]}}}}""");
        ctx.http.json("https://issuer.example/.well-known/oauth-authorization-server/t1", "{\"issuer\":\"https://issuer.example/t1\"}");
        var def = new SourceDefinition("d", "oid4vci-discovery", "fw", null, true,
                Map.of("issuers", List.of(Map.of("url", "https://issuer.example/t1", "entityId", "tenant-one"))));
        var r = new Oid4vciDiscoverySourceFactory().create(def, ctx).load();
        var e = r.entities().getFirst();
        assertThat(e.id()).isEqualTo("tenant-one");
        assertThat(e.displayName("en")).isEqualTo("Tenant One");
        // What an issuer says about itself describes it and grants nothing.
        assertThat(e.authorizations()).isEmpty();
        assertThat(e.attributes().get("jsonLdContexts")).isEqualTo(List.of("https://www.w3.org/ns/credentials/v2", "https://issuer.example/contexts/degree/v1"));
    }

    private static Map<String, Object> with(Map<String, Object> base, String key, Object value) {
        Map<String, Object> m = new java.util.LinkedHashMap<>(base);
        m.put(key, value);
        return m;
    }
}
