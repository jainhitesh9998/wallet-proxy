package io.vctrust.trust.adapters.oid4vci;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.IssuerMetadata;
import io.vctrust.trust.core.metadata.IssuerMetadataResolver;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
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
 * {@code type: oid4vci-discovery} — describes issuers from their own OpenID4VCI metadata: display, and the JSON-LD
 * contexts their credential configurations use. Each entry of {@code issuers} is a URL or {@code {url, entityId}}.
 * The description is merged into an entity another source of the framework lists: the one with the id
 * {@code entityId}, or, without it, the one entity that lists the issuer's URL as an identifier
 * ({@link SourceLoadResult#describing}). It never makes an entity of its own: a misspelt {@code entityId}, or an issuer
 * listed under another id, would otherwise be an ACTIVE issuer beside its REVOKED entry. When no such entity is listed,
 * or several list the URL, the description is left out with a warning in the source's state.
 *
 * <p>What an issuer says about itself never authorizes it: authorizations come only from sources an operator or a
 * trusted list vouches for (static, managed, signed lists).
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
                    String entityId = Json.string(spec, "entityId");
                    try {
                        IssuerMetadata md = resolver.resolve(url, null);
                        TrustedEntity.Builder b = TrustedEntity.builder(entityId != null ? entityId : url).framework(def.frameworkId())
                                .role(EntityRole.CREDENTIAL_ISSUER)
                                .provenance(Provenance.of(def.id(), type(), def.frameworkId(), url, ctx.clock().instant()));
                        Oid4vciMetadataMapper.describe(b, md.issuer());
                        md.authorizationServers().forEach((as, asMd) -> b.attribute("authorizationServer:" + as, Json.string(asMd, "issuer")));
                        md.warnings().forEach(w -> warnings.add(url + ": " + w));
                        // A description names the entity it describes by its identifiers, or by its id when it has none:
                        // with entityId, that entity alone; without, the one that lists the issuer's URL.
                        entities.add(entityId != null ? withoutIdentifiers(b.build()) : b.identifier(IdentifierType.URL, url).build());
                    } catch (Exception e) {
                        warnings.add(url + ": " + e.getMessage());
                    }
                }
                if (entities.isEmpty() && !issuers.isEmpty()) {
                    throw new TrustSourceException("No issuer metadata could be fetched: " + warnings);
                }
                return SourceLoadResult.describing(entities, ListInfo.unsigned(), warnings);
            }
        };
    }

    /** The description without identifiers: it names the configured {@code entityId} alone. */
    private static TrustedEntity withoutIdentifiers(TrustedEntity e) {
        return new TrustedEntity(e.id(), e.frameworkId(), e.roles(), List.of(), e.display(), e.authorizations(), e.status(),
                e.validFrom(), e.validUntil(), e.certificates(), e.metadata(), e.metadataPolicy(), e.attributes(), e.provenance());
    }
}
