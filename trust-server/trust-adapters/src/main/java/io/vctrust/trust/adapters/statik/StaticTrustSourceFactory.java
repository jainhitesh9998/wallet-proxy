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
 * format. Properties: {@code location} (classpath:, file: or https:); optional {@code publicUri}, published as the
 * source of what it loads in place of a location on this host (see {@link AdapterSupport#publishedLocation}).
 * A document with an entry that cannot be read is not loaded at all; the error names the entry.
 */
public final class StaticTrustSourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "static";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        AdapterSupport.publicUri(def); // a bad one is a configuration error, refused before the service starts
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
                    Provenance prov = Provenance.of(def.id(), type(), def.frameworkId(),
                            AdapterSupport.publishedLocation(def, location), ctx.clock().instant());
                    // An entry that cannot be read fails the load, naming it: skipped, a revoked entity would let its
                    // party be trusted through the CA, and an anchor would drop out. The last good content stays.
                    List<TrustedEntity> entities = new ArrayList<>();
                    List<TrustAnchor> anchors = new ArrayList<>();
                    List<Object> listed = (List<Object>) doc.getOrDefault("entities", List.of());
                    for (int i = 0; i < listed.size(); i++) {
                        try {
                            entities.add(TrustedEntityParser.entity(entry(listed.get(i)), def.frameworkId(), prov, named));
                        } catch (Exception e) {
                            throw unreadable(TrustedEntityParser.name("entity", "entities", i, listed.get(i)), e);
                        }
                    }
                    listed = (List<Object>) doc.getOrDefault("anchors", List.of());
                    for (int i = 0; i < listed.size(); i++) {
                        try {
                            anchors.addAll(TrustedEntityParser.anchors(entry(listed.get(i)), def.frameworkId(), prov, named));
                        } catch (Exception e) {
                            throw unreadable(TrustedEntityParser.name("anchor", "anchors", i, listed.get(i)), e);
                        }
                    }
                    return new SourceLoadResult(entities, anchors, ListInfo.unsigned(), List.of());
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load static registry " + location + ": " + e.getMessage(), e);
                }
            }
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> entry(Object o) {
        if (!(o instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException("it is not an object");
        }
        return (Map<String, Object>) m;
    }

    private static IllegalArgumentException unreadable(String name, Exception e) {
        return new IllegalArgumentException(name + " cannot be read: " + e.getMessage(), e);
    }
}
