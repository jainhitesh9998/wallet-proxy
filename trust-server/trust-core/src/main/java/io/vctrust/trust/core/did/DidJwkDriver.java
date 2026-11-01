package io.vctrust.trust.core.did;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.util.Base64Url;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** did:jwk (https://github.com/quartzjer/did-jwk). The DID document is derived from the embedded JWK. */
public final class DidJwkDriver implements DidMethodDriver {

    @Override
    public Set<String> methods() {
        return Set.of("jwk");
    }

    @Override
    public DidResolutionResult resolve(Did did) {
        Map<String, Object> jwk;
        try {
            jwk = Json.parseObject(Base64Url.decodeLenient(did.methodSpecificId()));
        } catch (RuntimeException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, "did:jwk value is not a base64url JWK");
        }
        if (!(jwk.get("kty") instanceof String)) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, "JWK lacks kty");
        }
        if (jwk.containsKey("d") || jwk.containsKey("p") || jwk.containsKey("k")) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, "did:jwk must not contain private or symmetric key material");
        }
        String id = did.did();
        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("id", id + "#0");
        vm.put("type", "JsonWebKey2020");
        vm.put("controller", id);
        vm.put("publicKeyJwk", jwk);
        Object use = jwk.get("use");
        boolean signing = !"enc".equals(use);
        boolean keyAgreement = !"sig".equals(use) && !"Ed25519".equals(jwk.get("crv"));
        return DidResolutionResult.success(DidDocuments.singleKey(id, List.of("https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"), vm, signing, keyAgreement), Map.of(), Map.of());
    }
}
