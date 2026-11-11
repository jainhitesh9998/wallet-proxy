package io.vctrust.trust.adapters.ebsi;

import com.nimbusds.jose.JWSObject;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import io.vctrust.trust.core.util.ExpiringMap;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * {@code type: ebsi-tir} — EBSI Trusted Issuers Registry v5. Properties: {@code baseUrl} (default the pilot
 * network), {@code crawl} (default false — on-demand lookups by DID only), {@code maxIssuers} (default 100),
 * {@code pageSize}.
 *
 * <p>Each issuer's attributes carry an accreditation VC (JWT) with {@code issuerType} RootTAO / TAO / TI /
 * Revoked; the VC's {@code accreditedFor[].types} become credential authorizations.
 */
public final class EbsiTirSourceFactory implements TrustSourceFactory {

    static final String DEFAULT_BASE = "https://api-pilot.ebsi.eu/trusted-issuers-registry/v5";

    @Override
    public String type() {
        return "ebsi-tir";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        return new EbsiSource(def, ctx);
    }

    static final Duration ON_DEMAND_TTL = Duration.ofMinutes(10);
    static final Duration ON_DEMAND_NEGATIVE_TTL = Duration.ofMinutes(1);
    static final int ON_DEMAND_MAX_ENTRIES = 5_000;

    static final class EbsiSource implements TrustSource, OnDemandResolver {
        private final SourceDefinition def;
        private final SourceContext ctx;
        private final String base;
        /** On-demand answers: an issuer is re-asked after a few minutes, so a revocation in the registry takes effect. */
        private final ExpiringMap<String, Optional<TrustedEntity>> cache;

        EbsiSource(SourceDefinition def, SourceContext ctx) {
            this.def = def;
            this.ctx = ctx;
            String b = def.string("baseUrl");
            this.base = (b == null ? DEFAULT_BASE : b).replaceAll("/+$", "");
            this.cache = new ExpiringMap<>(ON_DEMAND_MAX_ENTRIES, ctx.clock());
        }

        @Override
        public SourceDefinition definition() {
            return def;
        }

        @Override
        public SourceLoadResult load() throws TrustSourceException {
            List<TrustedEntity> entities = new ArrayList<>();
            List<String> warnings = new ArrayList<>();
            int total = 0;
            if (def.bool("crawl", false)) {
                int max = def.integer("maxIssuers", 100);
                String next = base + "/issuers?page[size]=" + def.integer("pageSize", 50);
                try {
                    while (next != null && entities.size() < max) {
                        Map<String, Object> page = json(next);
                        if (page.get("total") instanceof Number n) total = n.intValue();
                        for (Object o : Json.array(page.get("items")) == null ? List.of() : Json.array(page.get("items"))) {
                            if (entities.size() >= max) break;
                            String did = Json.string(Json.object(o), "did");
                            try {
                                fetchIssuer(did).ifPresent(entities::add);
                            } catch (Exception e) {
                                warnings.add(did + ": " + e.getMessage());
                            }
                        }
                        Map<String, Object> links = Json.object(page.get("links"));
                        String n = links == null ? null : Json.string(links, "next");
                        next = n == null || n.equals(next) ? null : n;
                    }
                } catch (IOException e) {
                    throw new TrustSourceException("EBSI TIR listing failed: " + e.getMessage(), e);
                }
            }
            return new SourceLoadResult(entities, List.of(), new ListInfo(base, null, ctx.clock().instant(), null,
                    ListInfo.SignatureStatus.NOT_SIGNED, Map.of("registryTotal", total)), warnings);
        }

        @Override
        public boolean canResolve(Identifier identifier) {
            return identifier.type() == IdentifierType.DID && identifier.value().startsWith("did:ebsi:");
        }

        @Override
        public Optional<TrustedEntity> resolve(Identifier identifier) throws TrustSourceException {
            Optional<Optional<TrustedEntity>> cached = cache.get(identifier.value());
            if (cached.isPresent()) {
                return cached.get();
            }
            try {
                Optional<TrustedEntity> issuer = fetchIssuer(identifier.value());
                cache.put(identifier.value(), issuer, ctx.clock().instant().plus(issuer.isPresent() ? ON_DEMAND_TTL : ON_DEMAND_NEGATIVE_TTL));
                return issuer;
            } catch (IOException e) {
                throw new TrustSourceException("EBSI lookup failed: " + e.getMessage(), e);
            }
        }

        Optional<TrustedEntity> fetchIssuer(String did) throws IOException {
            String url = base + "/issuers/" + URLEncoder.encode(did, StandardCharsets.UTF_8) + "?version=deprecated";
            HttpFetcher.Response r = ctx.http().execute(HttpFetcher.Request.get(URI.create(url), "application/json"));
            if (r.status() == 404) {
                return Optional.empty();
            }
            if (!r.isSuccess()) {
                throw new HttpFetcher.HttpStatusException(URI.create(url), r.status());
            }
            Map<String, Object> issuer = Json.parseObject(r.body());
            TrustedEntity.Builder b = TrustedEntity.builder("ebsi:" + did).framework(def.frameworkId())
                    .identifier(IdentifierType.DID, did)
                    .provenance(Provenance.of(def.id(), "ebsi-tir", def.frameworkId(), url, ctx.clock().instant()));
            Set<String> types = new LinkedHashSet<>();
            boolean anyActive = false;
            Object attrs = issuer.get("attributes");
            for (Object a : Json.array(attrs) == null ? List.of() : Json.array(attrs)) {
                Map<String, Object> am = Json.object(a);
                String issuerType = Json.string(am, "issuerType");
                types.add(issuerType);
                if (!"Revoked".equals(issuerType)) {
                    anyActive = true;
                }
                if (am.get("tao") != null) b.attribute("tao", am.get("tao"));
                if (am.get("rootTao") != null) b.attribute("rootTao", am.get("rootTao"));
                String body = Json.string(am, "body");
                if (body != null) {
                    accreditedTypes(body).forEach(t -> b.authorization(CredentialAuthorization.of(null, t)));
                }
            }
            if (types.contains("TI") || types.contains("TAO") || types.contains("RootTAO")) {
                b.role(EntityRole.CREDENTIAL_ISSUER);
            }
            if (types.contains("TAO") || types.contains("RootTAO")) {
                b.role(EntityRole.ACCREDITATION_AUTHORITY);
            }
            if (types.isEmpty()) {
                b.role(EntityRole.OTHER);
            }
            b.status(anyActive ? EntityStatus.ACTIVE : EntityStatus.REVOKED);
            b.attribute("issuerTypes", List.copyOf(types));
            return Optional.of(b.build());
        }

        /** Types from an accreditation VC-JWT's {@code credentialSubject.accreditedFor[].types}. */
        static List<String> accreditedTypes(String vcJwt) {
            try {
                Map<String, Object> claims = JWSObject.parse(vcJwt).getPayload().toJSONObject();
                Map<String, Object> vc = Json.object(claims.get("vc")) != null ? Json.object(claims.get("vc")) : claims;
                Map<String, Object> subject = Json.object(vc.get("credentialSubject"));
                List<String> out = new ArrayList<>();
                for (Object af : subject == null || Json.array(subject.get("accreditedFor")) == null ? List.of() : Json.array(subject.get("accreditedFor"))) {
                    Json.strings(Json.object(af).get("types")).stream()
                            .filter(t -> !"VerifiableCredential".equals(t) && !"VerifiableAttestation".equals(t))
                            .forEach(out::add);
                }
                return out;
            } catch (Exception e) {
                return List.of();
            }
        }

        private Map<String, Object> json(String url) throws IOException {
            return Json.parseObject(ctx.http().fetchOk(HttpFetcher.Request.get(URI.create(url), "application/json")).body());
        }
    }
}
