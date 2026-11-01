package io.vctrust.trust.adapters.federation;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * A validated chain {@code [EC(leaf), SS(superior→leaf), ..., EC(trust anchor)]} with the leaf's resolved
 * metadata (policies applied).
 */
public record TrustChain(String subject, String trustAnchor, List<EntityStatement> statements,
                         Map<String, Map<String, Object>> metadata, Instant expiresAt,
                         List<Map<String, Object>> trustMarks) {

    public List<String> jwts() {
        return statements.stream().map(EntityStatement::jwt).toList();
    }
}
