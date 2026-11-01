package io.vctrust.trust.core.did;

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
