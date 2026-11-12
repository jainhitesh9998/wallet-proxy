package io.vctrust.trust.core.did;

import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.testing.FakeHttp;
import io.vctrust.trust.core.util.Base64Url;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DidDriversTest {

    @Test
    void didKeyEd25519() {
        var r = new DidKeyDriver().resolve(Did.parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.verificationMethod("#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")).isPresent();
        assertThat(r.hasRelationship("assertionMethod",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void didKeyP256AsJwkMatchesSpecVector() {
        // did:key spec test vector for P-256
        var r = new DidKeyDriver(DidKeyDriver.KeyFormat.JSON_WEB_KEY)
                .resolve(Did.parse("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"));
        assertThat(r.isSuccess()).isTrue();
        var vm = r.allVerificationMethods().getFirst();
        var jwk = (Map<String, Object>) vm.get("publicKeyJwk");
        assertThat(jwk.get("x")).isEqualTo("fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI");
        assertThat(jwk.get("y")).isEqualTo("hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU");
    }

    @Test
    void didKeyRejectsUnknownCodec() {
        var r = new DidKeyDriver().resolve(Did.parse("did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7"));
        assertThat(r.isSuccess()).isFalse();
    }

    @Test
    void didJwk() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0\",\"y\":\"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE\"}";
        String did = "did:jwk:" + Base64Url.encode(jwk.getBytes(StandardCharsets.UTF_8));
        var r = new DidJwkDriver().resolve(Did.parse(did));
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.verificationMethod(did + "#0")).isPresent();
        assertThat(r.hasRelationship("assertionMethod", "#0")).isTrue();
        assertThat(r.hasRelationship("keyAgreement", "#0")).isTrue();
    }

    @Test
    void didJwkRejectsPrivateKey() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\",\"d\":\"secret\"}";
        var r = new DidJwkDriver().resolve(Did.parse("did:jwk:" + Base64Url.encode(jwk.getBytes(StandardCharsets.UTF_8))));
        assertThat(r.isSuccess()).isFalse();
        assertThat(r.error()).contains(DidResolutionResult.INVALID_DID);
    }

    @Test
    void didWebUrlMapping() {
        var d = new DidWebDriver(new FakeHttp(), Set.of("localhost"));
        assertThat(d.documentUrl(Did.parse("did:web:example.com")).toString()).isEqualTo("https://example.com/.well-known/did.json");
        assertThat(d.documentUrl(Did.parse("did:web:example.com%3A3000:user:alice")).toString())
                .isEqualTo("https://example.com:3000/user/alice/did.json");
        assertThat(d.documentUrl(Did.parse("did:web:localhost%3A8080")).toString()).isEqualTo("http://localhost:8080/.well-known/did.json");
    }

    @Test
    void didWebNamesAHostAndPlainSegmentsOnly() {
        var d = new DidWebDriver(new FakeHttp(), Set.of());
        // The first part decodes to a host and a port. Anything else would make the DID name some other resource:
        // did:web:victim.example%2Fuploads%2Fx.json%3F would be read from https://victim.example/uploads/x.json?/...
        for (String did : List.of("did:web:victim.example%2Fuploads%2Fx.json%3F", "did:web:user%40victim.example", "did:web:victim.example%23",
                "did:web:victim.example%5Cx", "did:web:victim.example%3A80%3A80", "did:web:victim.example:a%2Fb", "did:web:victim.example:..",
                "did:web:victim.example:%2E%2E", "did:web:victim.example::x", "did:web:victim.example:a%3Fb", "did:web:victim.example:a%20b")) {
            assertThat(d.resolve(Did.parse(did)).error()).as(did).contains(DidResolutionResult.INVALID_DID);
        }
        assertThat(d.documentUrl(Did.parse("did:web:example.com:dept%2Eone:alice")).toString()).isEqualTo("https://example.com/dept.one/alice/did.json");
    }

    @Test
    void aDidHasALengthLimit() {
        // Long enough for a did:jwk of a large RSA key; beyond it nothing is parsed (or echoed back in full).
        assertThat(Did.parse("did:example:" + "a".repeat(Did.MAX_LENGTH - 12)).method()).isEqualTo("example");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> Did.parse("did:example:" + "a".repeat(200_000)))
                .isInstanceOf(Did.InvalidDidException.class).hasMessageContaining("longer than").message().hasSizeLessThan(400);
        assertThat(Did.parse("did:example:a%3Ab:c.d-e_f").methodSpecificId()).isEqualTo("a%3Ab:c.d-e_f");
        for (String bad : List.of("did:example:", "did:example:a:", "did:example:a%3", "did:example:a%zz", "did:example:a b", "did:Example:a", "did::a")) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> Did.parse(bad)).as(bad).isInstanceOf(Did.InvalidDidException.class);
        }
    }

    @Test
    void didWebResolvesAndChecksId() {
        var http = new FakeHttp()
                .json("https://issuer.example/.well-known/did.json", "{\"id\":\"did:web:issuer.example\",\"verificationMethod\":[]}")
                .json("https://evil.example/.well-known/did.json", "{\"id\":\"did:web:other.example\"}");
        var d = new DidWebDriver(http, Set.of());
        assertThat(d.resolve(Did.parse("did:web:issuer.example")).isSuccess()).isTrue();
        var bad = d.resolve(Did.parse("did:web:evil.example"));
        assertThat(bad.error()).contains(DidResolutionResult.INVALID_DID_DOCUMENT);
        assertThat(d.resolve(Did.parse("did:web:missing.example")).error()).contains(DidResolutionResult.NOT_FOUND);
    }

    /** An outbound client that cannot reach anything, as the service's own reports it. */
    static HttpFetcher failing(java.io.IOException e) {
        return request -> {
            throw e;
        };
    }

    @Test
    void didWebTellsAFailureOfItsHostFromAnAnswerAboutTheDid() {
        var http = new FakeHttp()
                .respond("https://failing.example/.well-known/did.json", 500, "text/plain", "oops".getBytes(StandardCharsets.UTF_8))
                .respond("https://busy.example/.well-known/did.json", 429, "text/plain", new byte[0])
                .respond("https://gone.example/.well-known/did.json", 410, "text/plain", new byte[0])
                .respond("https://page.example/.well-known/did.json", 200, "text/html", "<html></html>".getBytes(StandardCharsets.UTF_8))
                .json("https://evil.example/.well-known/did.json", "{\"id\":\"did:web:other.example\"}");
        var d = new DidWebDriver(http, Set.of());
        // Where the DID lives gave no usable answer: an error status other than "not there", or not the DID's document.
        for (String did : List.of("did:web:failing.example", "did:web:busy.example", "did:web:page.example", "did:web:evil.example")) {
            assertThat(d.resolve(Did.parse(did)).upstreamFailed()).as(did).isTrue();
        }
        assertThat(d.resolve(Did.parse("did:web:failing.example")).error()).contains(DidResolutionResult.INTERNAL_ERROR);
        assertThat(d.resolve(Did.parse("did:web:page.example")).error()).contains(DidResolutionResult.INVALID_DID_DOCUMENT);
        assertThat(new DidWebDriver(failing(new java.net.ConnectException("refused")), Set.of()).resolve(Did.parse("did:web:down.example")).upstreamFailed()).isTrue();
        assertThat(new DidWebDriver(failing(new java.net.http.HttpTimeoutException("timed out")), Set.of()).resolve(Did.parse("did:web:slow.example")).upstreamFailed()).isTrue();
        assertThat(new DidWebDriver(failing(new java.net.UnknownHostException("nowhere.example")), Set.of()).resolve(Did.parse("did:web:nowhere.example")).upstreamFailed()).isTrue();
        // Answers about the DID: it is not there, it is not a DID this method reads, or it names a host the service does not ask.
        for (String did : List.of("did:web:missing.example", "did:web:gone.example", "did:web:user%40victim.example")) {
            assertThat(d.resolve(Did.parse(did)).upstreamFailed()).as(did).isFalse();
        }
        var blocked = new DidWebDriver(failing(new HttpFetcher.BlockedException("private address")), Set.of()).resolve(Did.parse("did:web:internal.example"));
        assertThat(blocked.error()).contains(DidResolutionResult.INVALID_DID);
        assertThat(blocked.upstreamFailed()).isFalse();
    }

    @Test
    void registryAndUniversalResolverTellAFailureUpstreamFromAnAnswer() {
        String did = "did:ebsi:z23";
        String registry = "https://registry.example/identifiers/{did}";
        String at = "https://registry.example/identifiers/did%3Aebsi%3Az23";
        var r = new HttpRegistryDidDriver(new FakeHttp().respond(at, 503, "text/plain", new byte[0]), "ebsi", registry);
        assertThat(r.resolve(Did.parse(did)).upstreamFailed()).isTrue();
        assertThat(new HttpRegistryDidDriver(new FakeHttp().respond(at, 200, "text/html", "<html/>".getBytes(StandardCharsets.UTF_8)), "ebsi", registry)
                .resolve(Did.parse(did)).upstreamFailed()).isTrue();
        assertThat(new HttpRegistryDidDriver(new FakeHttp().json(at, "{\"id\":\"did:ebsi:other\"}"), "ebsi", registry).resolve(Did.parse(did)).upstreamFailed()).isTrue();
        assertThat(new HttpRegistryDidDriver(failing(new java.net.ConnectException("refused")), "ebsi", registry).resolve(Did.parse(did)).upstreamFailed()).isTrue();
        var missing = new HttpRegistryDidDriver(new FakeHttp(), "ebsi", registry).resolve(Did.parse(did));
        assertThat(missing.error()).contains(DidResolutionResult.NOT_FOUND);
        assertThat(missing.upstreamFailed()).isFalse();

        String ur = "https://resolver.example/1.0/identifiers/did%3Aexample%3A123";
        java.util.function.Function<FakeHttp, DidResolutionResult> resolve = http ->
                new UniversalResolverDriver(http, java.net.URI.create("https://resolver.example"), Set.of("*")).resolve(Did.parse("did:example:123"));
        java.util.function.Function<String, String> reporting = error -> "{\"didDocument\":null,\"didResolutionMetadata\":{\"error\":\"" + error + "\"}}";
        // The resolver failed, or reports a failure of where the DID lives, or answers with something that is no DID document.
        Map<String, FakeHttp> failures = Map.of(
                "a gateway page", new FakeHttp().respond(ur, 502, "text/html", "<html>Bad Gateway</html>".getBytes(StandardCharsets.UTF_8)),
                "an error of its own", new FakeHttp().respond(ur, 500, "application/json", "{\"message\":\"boom\"}".getBytes(StandardCharsets.UTF_8)),
                "internalError", new FakeHttp().respond(ur, 500, "application/json", reporting.apply("internalError").getBytes(StandardCharsets.UTF_8)),
                "invalidDidDocument", new FakeHttp().respond(ur, 200, "application/json", reporting.apply("invalidDidDocument").getBytes(StandardCharsets.UTF_8)),
                "a code this service does not know", new FakeHttp().respond(ur, 500, "application/json", reporting.apply("someErrorOfItsOwn").getBytes(StandardCharsets.UTF_8)),
                "a document that is not an object", new FakeHttp().json(ur, "{\"didDocument\":\"not a document\",\"didResolutionMetadata\":{}}"),
                "another DID's document", new FakeHttp().json(ur, "{\"didDocument\":{\"id\":\"did:example:other\"},\"didResolutionMetadata\":{}}"));
        failures.forEach((name, http) -> assertThat(resolve.apply(http).upstreamFailed()).as(name).isTrue());
        assertThat(new UniversalResolverDriver(failing(new java.net.ConnectException("refused")), java.net.URI.create("https://resolver.example"), Set.of("*"))
                .resolve(Did.parse("did:example:123")).upstreamFailed()).isTrue();
        // What the resolver says about the DID.
        for (String error : List.of("notFound", "invalidDid", "methodNotSupported")) {
            var answer = resolve.apply(new FakeHttp().respond(ur, 404, "application/json", reporting.apply(error).getBytes(StandardCharsets.UTF_8)));
            assertThat(answer.upstreamFailed()).as(error).isFalse();
            assertThat(DidResolutionResult.httpStatus(answer.error().orElseThrow())).as(error).isNotEqualTo(500);
        }
        var notThere = resolve.apply(new FakeHttp().respond(ur, 404, "application/json", "{\"message\":\"no such DID\"}".getBytes(StandardCharsets.UTF_8)));
        assertThat(notThere.error()).contains(DidResolutionResult.NOT_FOUND);
        assertThat(notThere.upstreamFailed()).isFalse();
    }

    @Test
    void aDriverThatThrowsIsAFailureOfTheServiceNotOfWhereTheDidLives() {
        DidMethodDriver broken = new DidMethodDriver() {
            @Override
            public Set<String> methods() {
                return Set.of("web");
            }

            @Override
            public DidResolutionResult resolve(Did did) {
                throw new IllegalStateException("a bug");
            }
        };
        var r = new DidResolver(List.of(broken)).resolve("did:web:issuer.example");
        assertThat(r.error()).contains(DidResolutionResult.INTERNAL_ERROR);
        assertThat(r.upstreamFailed()).isFalse();
        // The mark is the service's knowledge: it survives added metadata and is not part of the JSON form.
        var marked = DidResolutionResult.upstreamError(DidResolutionResult.INTERNAL_ERROR, "HTTP 500 from https://issuer.example/.well-known/did.json")
                .withResolutionMetadata("cache", Map.of());
        assertThat(marked.upstreamFailed()).isTrue();
        assertThat(marked.errorDetail()).contains("HTTP 500 from https://issuer.example/.well-known/did.json");
        assertThat(marked.toJson()).containsOnlyKeys("@context", "didDocument", "didResolutionMetadata", "didDocumentMetadata");
    }

    @Test
    void resolverDispatchesAndReportsUnsupportedMethods() {
        var resolver = new DidResolver(List.of(new DidKeyDriver(), new DidJwkDriver()));
        assertThat(resolver.resolve("did:example:123").error()).contains(DidResolutionResult.METHOD_NOT_SUPPORTED);
        assertThat(resolver.resolve("not-a-did").error()).contains(DidResolutionResult.INVALID_DID);
        assertThat(resolver.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#frag").isSuccess()).isTrue();
    }

    @Test
    void legacyErrorCodesNormalize() {
        assertThat(DidResolutionResult.normalizeError("notFound")).isEqualTo("NOT_FOUND");
        assertThat(DidResolutionResult.normalizeError(Map.of("type", "https://www.w3.org/ns/did#INVALID_DID"))).isEqualTo("INVALID_DID");
    }
}
