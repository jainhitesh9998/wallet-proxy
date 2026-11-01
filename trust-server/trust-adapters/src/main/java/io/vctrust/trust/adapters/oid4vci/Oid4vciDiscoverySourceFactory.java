package io.vctrust.trust.adapters.oid4vci;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.IssuerMetadata;
import io.vctrust.trust.core.metadata.IssuerMetadataResolver;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code type: oid4vci-discovery} — builds issuer entities by fetching each configured issuer's OpenID4VCI
 * metadata. Each entry of {@code issuers} is either a URL or {@code {url, entityId, authorizations: bool}};
 * {@code entityId} lets the discovered data merge into an entity defined by another source (e.g. a static
 * entry that carries policy and framework membership).
 */
public final class Oid4vciDiscoverySourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "oid4vci-discovery";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        IssuerMetadataResolver resolver = new IssuerMetadataResolver(ctx.http(), ctx.clock(), Duration.ofMinutes(1),
                Duration.ofDays(1), false);
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            public SourceLoadResult load() throws TrustSourceException {
                List<TrustedEntity> entities = new ArrayList<>();
                List<String> warnings = new ArrayList<>();
                List<Object> issuers = def.list("issuers");
                for (Object o : issuers) {
                    Map<String, Object> spec = o instanceof Map<?, ?> ? Json.object(o) : Map.of("url", String.valueOf(o));
                    String url = Json.string(spec, "url");
                    String entityId = Json.string(spec, "entityId") != null ? Json.string(spec, "entityId") : url;
                    boolean authz = !"false".equals(String.valueOf(spec.getOrDefault("authorizations", "true")));
                    try {
                        IssuerMetadata md = resolver.resolve(url, null);
                        TrustedEntity.Builder b = TrustedEntity.builder(entityId).framework(def.frameworkId())
                                .role(EntityRole.CREDENTIAL_ISSUER)
                                .provenance(Provenance.of(def.id(), type(), def.frameworkId(), url, ctx.clock().instant()));
                        Oid4vciMetadataMapper.enrich(b, md.issuer(), authz);
                        md.authorizationServers().forEach((as, asMd) -> b.attribute("authorizationServer:" + as, Json.string(asMd, "issuer")));
                        md.warnings().forEach(w -> warnings.add(url + ": " + w));
                        entities.add(b.build());
                    } catch (Exception e) {
                        warnings.add(url + ": " + e.getMessage());
                    }
                }
                if (entities.isEmpty() && !issuers.isEmpty()) {
                    throw new TrustSourceException("No issuer metadata could be fetched: " + warnings);
                }
                return new SourceLoadResult(entities, List.of(), ListInfo.unsigned(), warnings);
            }
        };
    }
}
