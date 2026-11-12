package io.vctrust.trust.core.spi;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;

import java.util.List;

/**
 * Everything one load of a trust source produced.
 *
 * @param describing the entities only describe parties that other sources list (what an issuer says about itself), and
 *                   vouch for nothing. Such an entry never makes an entity of its own, nor one usable: the registry
 *                   merges what describes (display, JSON-LD contexts and their digests, metadata) into the one entity
 *                   of the source's framework that another source lists and the entry names, and leaves the entry out,
 *                   with a warning, when there is no such entity or more than one. An entry names its entity by its
 *                   identifiers when it has any (the entity that lists one of them), otherwise by its id. A describing
 *                   result has no anchors.
 */
public record SourceLoadResult(List<TrustedEntity> entities, List<TrustAnchor> anchors, ListInfo listInfo,
                               List<String> warnings, boolean describing) {

    public SourceLoadResult {
        entities = entities == null ? List.of() : List.copyOf(entities);
        anchors = anchors == null ? List.of() : List.copyOf(anchors);
        listInfo = listInfo == null ? ListInfo.unsigned() : listInfo;
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
        if (describing && !anchors.isEmpty()) {
            throw new IllegalArgumentException("A source that only describes parties lists no anchors");
        }
    }

    /** A load whose entities list parties (not {@link #describing}). */
    public SourceLoadResult(List<TrustedEntity> entities, List<TrustAnchor> anchors, ListInfo listInfo, List<String> warnings) {
        this(entities, anchors, listInfo, warnings, false);
    }

    /** A load whose entities only describe parties that other sources list ({@link #describing}). */
    public static SourceLoadResult describing(List<TrustedEntity> entities, ListInfo listInfo, List<String> warnings) {
        return new SourceLoadResult(entities, List.of(), listInfo, warnings, true);
    }
}
