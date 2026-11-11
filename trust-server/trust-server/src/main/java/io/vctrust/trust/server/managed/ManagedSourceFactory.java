package io.vctrust.trust.server.managed;

import io.vctrust.trust.adapters.support.TrustedEntityParser;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.ResourceLoader;
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

            /** Entries are stored with the framework of the managed source they were written for. */
            private boolean ofAnotherManagedSource(Map<String, Object> doc) {
                return doc.get("framework") != null && !String.valueOf(doc.get("framework")).equals(def.frameworkId());
            }

            @Override
            public SourceLoadResult load() {
                Provenance prov = Provenance.of(def.id(), "managed", def.frameworkId(), "admin-api", ctx.clock().instant());
                // Entries arrive through the admin API: what they name is fetched from the web, never read from this host.
                ResourceLoader named = ResourceLoader.remoteOnly(ctx.resources());
                List<TrustedEntity> entities = new ArrayList<>();
                List<TrustAnchor> anchors = new ArrayList<>();
                List<String> warnings = new ArrayList<>();
                for (Map<String, Object> doc : store.list(ManagedEntityStore.Kind.ENTITY)) {
                    if (ofAnotherManagedSource(doc)) {
                        continue;
                    }
                    try {
                        entities.add(TrustedEntityParser.entity(doc, def.frameworkId(), prov, named));
                    } catch (Exception e) {
                        warnings.add("Entity " + doc.get("id") + ": " + e.getMessage());
                    }
                }
                for (Map<String, Object> doc : store.list(ManagedEntityStore.Kind.ANCHOR)) {
                    if (ofAnotherManagedSource(doc)) {
                        continue;
                    }
                    try {
                        anchors.addAll(TrustedEntityParser.anchors(doc, def.frameworkId(), prov, named));
                    } catch (Exception e) {
                        warnings.add("Anchor " + doc.get("id") + ": " + e.getMessage());
                    }
                }
                return new SourceLoadResult(entities, anchors, ListInfo.unsigned(), warnings);
            }
        };
    }
}
