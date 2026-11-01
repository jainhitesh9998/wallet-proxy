package io.vctrust.trust.core.model;

import java.util.Map;

/**
 * A trust framework / ecosystem (e.g. "EU EUDI pilot", "MOSIP collab", "AAMVA DTS"). Every entity and anchor
 * belongs to exactly one framework; client profiles select which frameworks they accept.
 */
public record TrustFramework(String id, String name, String description, String governanceUri,
                             Map<String, String> attributes) {

    public TrustFramework {
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
