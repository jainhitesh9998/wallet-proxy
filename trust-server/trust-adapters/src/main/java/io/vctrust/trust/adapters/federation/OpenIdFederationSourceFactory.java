package io.vctrust.trust.adapters.federation;

import com.nimbusds.jose.jwk.JWKSet;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@code type: openid-federation} — OpenID Federation 1.0. Properties: {@code trustAnchor} (entity id),
 * {@code trustAnchorJwks} (inline JWKS JSON) or {@code trustAnchorJwksLocation} — pinned out of band;
 * {@code crawl} (enumerate via list endpoints, default true), {@code maxDepth} (default 3),
 * {@code maxEntities} (default 500). Supports on-demand resolution of entity ids not found by crawling.
 */
public final class OpenIdFederationSourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "openid-federation";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        return new FederationSource(def, ctx);
    }

    static final class FederationSource implements TrustSource, OnDemandResolver {
        private final SourceDefinition def;
        private final SourceContext ctx;
        private final String trustAnchor;
        private final Map<String, CachedEntity> cache = new ConcurrentHashMap<>();
        private volatile FederationResolver resolver;

        record CachedEntity(TrustedEntity entity, Instant expires) {
        }

        FederationSource(SourceDefinition def, SourceContext ctx) {
            this.def = def;
            this.ctx = ctx;
            this.trustAnchor = def.requireString("trustAnchor");
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        private FederationResolver resolver() throws TrustSourceException {
            if (resolver == null) {
                try {
                    String inline = def.string("trustAnchorJwks");
                    String jwks = inline != null ? inline
                            : new String(ctx.resources().load(def.requireString("trustAnchorJwksLocation")), StandardCharsets.UTF_8);
                    resolver = new FederationResolver(ctx.http(), ctx.clock(), trustAnchor, JWKSet.parse(jwks),
                            def.integer("maxDepth", 3));
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load pinned trust anchor keys: " + e.getMessage(), e);
                }
            }
            return resolver;
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
            FederationResolver r = resolver();
            List<TrustedEntity> entities = new ArrayList<>();
            List<String> warnings = new ArrayList<>();
            EntityStatement ta;
            try {
                ta = r.entityConfiguration(trustAnchor);
                r.validate(List.of(ta));
            } catch (FederationException e) {
                throw new TrustSourceException("Trust anchor " + trustAnchor + ": " + e.getMessage());
            }
            if (def.bool("crawl", true)) {
                int max = def.integer("maxEntities", 500);
                record Node(EntityStatement superiorEc, List<EntityStatement> chainAbove, int depth) {
                }
                Deque<Node> queue = new ArrayDeque<>();
                queue.add(new Node(ta, List.of(ta), 0));
                Set<String> seen = new LinkedHashSet<>(Set.of(trustAnchor));
                while (!queue.isEmpty() && entities.size() < max) {
                    Node n = queue.poll();
                    List<String> subs;
                    try {
                        subs = r.listSubordinates(n.superiorEc());
                    } catch (FederationException e) {
                        warnings.add(n.superiorEc().sub() + ": " + e.getMessage());
                        continue;
                    }
                    for (String sub : subs) {
                        if (!seen.add(sub) || entities.size() >= max) continue;
                        try {
                            EntityStatement ss = r.subordinateStatement(n.superiorEc(), sub);
                            EntityStatement ec = r.entityConfiguration(sub);
                            List<EntityStatement> chain = new ArrayList<>();
                            chain.add(ec);
                            chain.add(ss);
                            chain.addAll(n.chainAbove());
                            TrustChain tc = r.validate(chain);
                            TrustedEntity e = toEntity(tc);
                            if (!e.roles().isEmpty()) {
                                entities.add(e);
                            }
                            if (ec.federationEntity().get("federation_list_endpoint") != null && n.depth() + 1 < def.integer("maxDepth", 3)) {
                                List<EntityStatement> above = new ArrayList<>();
                                above.add(ss);
                                above.addAll(n.chainAbove());
                                queue.add(new Node(ec, above, n.depth() + 1));
                            }
                        } catch (FederationException e) {
                            warnings.add(sub + ": " + e.getMessage());
                        }
                    }
                }
            }
            Map<String, Object> details = Map.of("trustAnchor", trustAnchor, "entities", entities.size());
            return new SourceLoadResult(entities, List.of(), new ListInfo(trustAnchor, null, ctx.clock().instant(), null,
                    ListInfo.SignatureStatus.VERIFIED, details), warnings);
        }

        @Override
        public boolean canResolve(Identifier identifier) {
            return (identifier.type() == IdentifierType.FEDERATION_ENTITY || identifier.type() == IdentifierType.URL)
                    && identifier.value().startsWith("https://");
        }

        @Override
        public Optional<TrustedEntity> resolve(Identifier identifier) throws TrustSourceException {
            CachedEntity c = cache.get(identifier.value());
            Instant now = ctx.clock().instant();
            if (c != null && c.expires().isAfter(now)) {
                return Optional.ofNullable(c.entity());
            }
            try {
                TrustChain tc = resolver().resolve(identifier.value());
                TrustedEntity e = toEntity(tc);
                cache.put(identifier.value(), new CachedEntity(e, tc.expiresAt()));
                return Optional.of(e);
            } catch (FederationException e) {
                cache.put(identifier.value(), new CachedEntity(null, now.plusSeconds(300)));
                return Optional.empty();
            }
        }

        TrustedEntity toEntity(TrustChain tc) {
            TrustedEntity.Builder b = TrustedEntity.builder("oidf:" + tc.subject()).framework(def.frameworkId())
                    .identifier(IdentifierType.FEDERATION_ENTITY, tc.subject())
                    .identifier(IdentifierType.URL, tc.subject())
                    .provenance(new Provenance(def.id(), "openid-federation", def.frameworkId(), trustAnchor, ctx.clock().instant(),
                            Map.of("trustChain", tc.jwts())))
                    .validUntil(tc.expiresAt())
                    .attribute("trustAnchor", tc.trustAnchor())
                    .attribute("trustMarks", tc.trustMarks());
            tc.metadata().forEach(b::metadata);
            for (String type : tc.metadata().keySet()) {
                switch (type) {
                    case "openid_credential_issuer" -> {
                        b.role(EntityRole.CREDENTIAL_ISSUER);
                        Oid4vciMetadataMapper.enrich(b, tc.metadata().get(type), true);
                    }
                    case "openid_credential_verifier", "openid_relying_party" -> {
                        b.role(EntityRole.VERIFIER);
                        b.identifier(IdentifierType.CLIENT_ID, "openid_federation:" + tc.subject());
                    }
                    case "openid_wallet_provider" -> b.role(EntityRole.WALLET_PROVIDER);
                    case "oauth_authorization_server", "openid_provider" -> b.role(EntityRole.AUTHORIZATION_SERVER);
                    default -> {
                    }
                }
            }
            Map<String, Object> fe = tc.metadata().get("federation_entity");
            if (fe != null && Json.string(fe, "organization_name") != null && !b.hasDisplay()) {
                b.display(new LocalizedDisplay("en", Json.string(fe, "organization_name"), null, Json.string(fe, "logo_uri")));
            }
            return b.build();
        }
    }
}
