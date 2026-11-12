package io.vctrust.trust.core.did;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dispatches DID resolution to method drivers. Native drivers take precedence over wildcard drivers
 * (e.g. a Universal Resolver), so that resolution of well-understood methods never leaves the process.
 */
public class DidResolver {

    private final Map<String, DidMethodDriver> drivers = new LinkedHashMap<>();
    private final List<DidMethodDriver> wildcards = new ArrayList<>();

    public DidResolver(List<DidMethodDriver> drivers) {
        for (DidMethodDriver d : drivers) {
            for (String m : d.methods()) {
                if ("*".equals(m)) {
                    wildcards.add(d);
                } else {
                    this.drivers.putIfAbsent(m, d);
                }
            }
        }
    }

    public DidResolutionResult resolve(String didOrUrl) {
        Did did;
        try {
            did = Did.parse(didOrUrl);
        } catch (Did.InvalidDidException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        }
        DidMethodDriver driver = drivers.get(did.method());
        if (driver == null && !wildcards.isEmpty()) {
            driver = wildcards.getFirst();
        }
        if (driver == null) {
            return DidResolutionResult.error(DidResolutionResult.METHOD_NOT_SUPPORTED,
                    "DID method '" + did.method() + "' is not supported");
        }
        try {
            return driver.resolve(new Did(did.method(), did.methodSpecificId(), null, null, null));
        } catch (RuntimeException e) {
            // A driver that throws failed in this code, not where the DID lives: not an upstream error.
            return DidResolutionResult.error(DidResolutionResult.INTERNAL_ERROR, e.getMessage());
        }
    }

    public Set<String> supportedMethods() {
        Set<String> out = new LinkedHashSet<>(drivers.keySet());
        if (!wildcards.isEmpty()) {
            out.add("*");
        }
        return out;
    }
}
