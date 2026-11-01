package io.vctrust.trust.server.managed;

import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** {@code type: managed} — entities and anchors maintained through the admin API. */
public class ManagedSourceFactory implements TrustSourceFactory {

    private final ManagedEntityStore store;

    public ManagedSourceFactory(ManagedEntityStore store) {
        this.store = store;
    }

    @Override
    public String type() {
        return "managed";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            public SourceLoadResult load() {
                Provenance prov = Provenance.of(def.id(), "managed", def.frameworkId(), "admin-api", ctx.clock().instant());
                List<TrustedEntity> entities = new ArrayList<>();
                List<TrustAnchor> anchors = new ArrayList<>();
                List<String> warnings = new ArrayList<>();
                for (Map<String, Object> doc : store.list(ManagedEntityStore.Kind.ENTITY)) {
                    try {
                        entities.add(TrustedEntityParser.entity(doc, def.frameworkId(), prov, ctx.resources()));
                    } catch (Exception e) {
                        warnings.add("Entity " + doc.get("id") + ": " + e.getMessage());
                    }
                }
                for (Map<String, Object> doc : store.list(ManagedEntityStore.Kind.ANCHOR)) {
                    try {
                        anchors.addAll(TrustedEntityParser.anchors(doc, def.frameworkId(), prov, ctx.resources()));
                    } catch (Exception e) {
                        warnings.add("Anchor " + doc.get("id") + ": " + e.getMessage());
                    }
                }
                return new SourceLoadResult(entities, anchors, ListInfo.unsigned(), warnings);
            }
        };
    }
}
