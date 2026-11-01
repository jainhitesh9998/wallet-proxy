package io.vctrust.trust.core.did;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builders for the single-key DID documents produced by did:key and did:jwk. */
final class DidDocuments {

    private DidDocuments() {
    }

    static Map<String, Object> singleKey(String did, List<String> contexts, Map<String, Object> vm,
                                         boolean signing, boolean keyAgreement) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", contexts);
        doc.put("id", did);
        doc.put("verificationMethod", List.of(vm));
        String vmId = (String) vm.get("id");
        if (signing) {
            for (String rel : List.of("authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation")) {
                doc.put(rel, new ArrayList<>(List.of(vmId)));
            }
        }
        if (keyAgreement) {
            doc.put("keyAgreement", new ArrayList<>(List.of(vmId)));
        }
        return doc;
    }
}
