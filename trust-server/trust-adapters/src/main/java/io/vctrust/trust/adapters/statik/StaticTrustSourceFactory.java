package io.vctrust.trust.adapters.statik;

import io.vctrust.trust.adapters.support.AdapterSupport;
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
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code type: static} — entities and anchors maintained in a YAML/JSON document in the service's native
 * format. Properties: {@code location} (classpath:, file: or https:).
 */
public final class StaticTrustSourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "static";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            @SuppressWarnings("unchecked")
            public SourceLoadResult load() throws TrustSourceException {
                String location = def.requireString("location");
                try {
                    Map<String, Object> doc = AdapterSupport.parseYamlOrJson(ctx.resources().load(location));
                    // What a registry fetched from elsewhere names is fetched from the web too, never read from this host.
                    ResourceLoader named = ResourceLoader.isRemote(location) ? ResourceLoader.remoteOnly(ctx.resources()) : ctx.resources();
                    Provenance prov = Provenance.of(def.id(), type(), def.frameworkId(), location, ctx.clock().instant());
                    List<TrustedEntity> entities = new ArrayList<>();
                    List<TrustAnchor> anchors = new ArrayList<>();
                    List<String> warnings = new ArrayList<>();
                    for (Object o : (List<Object>) doc.getOrDefault("entities", List.of())) {
                        try {
                            entities.add(TrustedEntityParser.entity((Map<String, Object>) o, def.frameworkId(), prov, named));
                        } catch (Exception e) {
                            warnings.add("Skipped entity: " + e.getMessage());
                        }
                    }
                    for (Object o : (List<Object>) doc.getOrDefault("anchors", List.of())) {
                        try {
                            anchors.addAll(TrustedEntityParser.anchors((Map<String, Object>) o, def.frameworkId(), prov, named));
                        } catch (Exception e) {
                            warnings.add("Skipped anchor: " + e.getMessage());
                        }
                    }
                    return new SourceLoadResult(entities, anchors, ListInfo.unsigned(), warnings);
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load static registry " + location + ": " + e.getMessage(), e);
                }
            }
        };
    }
}
