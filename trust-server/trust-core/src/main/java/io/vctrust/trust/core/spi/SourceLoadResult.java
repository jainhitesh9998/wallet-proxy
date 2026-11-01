package io.vctrust.trust.core.spi;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;

import java.util.List;

/** Everything one load of a trust source produced. */
public record SourceLoadResult(List<TrustedEntity> entities, List<TrustAnchor> anchors, ListInfo listInfo,
                               List<String> warnings) {

    public SourceLoadResult {
        entities = entities == null ? List.of() : List.copyOf(entities);
        anchors = anchors == null ? List.of() : List.copyOf(anchors);
        listInfo = listInfo == null ? ListInfo.unsigned() : listInfo;
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
