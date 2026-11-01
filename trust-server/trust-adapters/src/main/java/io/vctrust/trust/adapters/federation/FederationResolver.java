package io.vctrust.trust.adapters.federation;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.metadata.MetadataPolicy;
import io.vctrust.trust.core.metadata.WellKnown;
import io.vctrust.trust.core.spi.HttpFetcher;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves and validates OpenID Federation 1.0 trust chains (§10) bottom-up from a leaf, towards a configured
 * Trust Anchor whose keys are pinned out of band.
 */
public class FederationResolver {

    private final HttpFetcher http;
    private final Clock clock;
    private final String trustAnchor;
    private final JWKSet trustAnchorKeys;
    private final int maxDepth;

    public FederationResolver(HttpFetcher http, Clock clock, String trustAnchor, JWKSet trustAnchorKeys, int maxDepth) {
        this.http = http;
        this.clock = clock;
        this.trustAnchor = trustAnchor;
        this.trustAnchorKeys = trustAnchorKeys;
        this.maxDepth = maxDepth;
    }

    public EntityStatement entityConfiguration(String entityId) throws FederationException {
        URI url = WellKnown.appended(entityId, WellKnown.OPENID_FEDERATION);
        EntityStatement ec = EntityStatement.parse(get(url, "application/entity-statement+jwt"));
        if (!entityId.equals(ec.iss()) || !entityId.equals(ec.sub())) {
            throw new FederationException("invalid_trust_chain", "Entity configuration iss/sub do not equal " + entityId);
        }
        ec.verify(ec.jwks(), clock.instant());
        return ec;
    }

    public EntityStatement subordinateStatement(EntityStatement superior, String sub) throws FederationException {
        String fetch = Json.string(superior.federationEntity(), "federation_fetch_endpoint");
        if (fetch == null) {
            throw new FederationException("invalid_trust_chain", superior.sub() + " has no federation_fetch_endpoint");
        }
        String sep = fetch.contains("?") ? "&" : "?";
        EntityStatement ss = EntityStatement.parse(get(URI.create(fetch + sep + "sub=" + URLEncoder.encode(sub, StandardCharsets.UTF_8)),
                "application/entity-statement+jwt"));
        if (!superior.sub().equals(ss.iss()) || !sub.equals(ss.sub())) {
            throw new FederationException("invalid_trust_chain", "Subordinate statement iss/sub mismatch for " + sub);
        }
        ss.verify(superior.jwks(), clock.instant());
        return ss;
    }

    public List<String> listSubordinates(EntityStatement ec) throws FederationException {
        String list = Json.string(ec.federationEntity(), "federation_list_endpoint");
        if (list == null) {
            return List.of();
        }
        try {
            HttpFetcher.Response r = http.fetchOk(HttpFetcher.Request.get(URI.create(list), "application/json"));
            return Json.strings(Json.MAPPER.readValue(r.body(), List.class));
        } catch (IOException e) {
            throw new FederationException("temporarily_unavailable", "List endpoint failed: " + e.getMessage());
        }
    }

    /** Resolves the leaf's chain up to the trust anchor (depth-first over authority_hints). */
    public TrustChain resolve(String leafId) throws FederationException {
        EntityStatement leaf = entityConfiguration(leafId);
        List<EntityStatement> path = new ArrayList<>();
        path.add(leaf);
        TrustChain chain = climb(leaf, path, 0);
        if (chain == null) {
            throw new FederationException("invalid_trust_chain", "No trust chain from " + leafId + " to " + trustAnchor);
        }
        return chain;
    }

    /** Builds the chain for a subordinate already reached top-down (statements below the TA in hand). */
    public TrustChain validate(List<EntityStatement> statements) throws FederationException {
        Instant now = clock.instant();
        EntityStatement ta = statements.getLast();
        if (!trustAnchor.equals(ta.sub()) || !ta.isSelfSigned()) {
            throw new FederationException("invalid_trust_anchor", "Chain does not end at " + trustAnchor);
        }
        ta.verify(trustAnchorKeys, now);
        for (int j = 0; j < statements.size() - 1; j++) {
            EntityStatement es = statements.get(j);
            EntityStatement next = statements.get(j + 1);
            if (!es.iss().equals(next.sub())) {
                throw new FederationException("invalid_trust_chain", "Chain break between " + es.iss() + " and " + next.sub());
            }
            es.verify(next.jwks(), now);
        }
        checkConstraints(statements);
        EntityStatement leaf = statements.getFirst();
        Map<String, Map<String, Object>> metadata = resolveMetadata(statements);
        Instant exp = statements.stream().map(EntityStatement::exp).min(Instant::compareTo).orElse(now);
        return new TrustChain(leaf.sub(), trustAnchor, List.copyOf(statements), metadata, exp, verifyTrustMarks(leaf, ta));
    }

    private TrustChain climb(EntityStatement current, List<EntityStatement> path, int depth) throws FederationException {
        if (depth > maxDepth) {
            return null;
        }
        FederationException last = null;
        for (String hint : current.authorityHints()) {
            try {
                EntityStatement superiorEc = hint.equals(trustAnchor) && depth == 0 && false ? null : entityConfiguration(hint);
                EntityStatement ss = subordinateStatement(superiorEc, current.sub());
                List<EntityStatement> next = new ArrayList<>(path);
                next.add(ss);
                if (hint.equals(trustAnchor)) {
                    next.add(superiorEc);
                    return validate(next);
                }
                TrustChain c = climb(superiorEc, next, depth + 1);
                if (c != null) {
                    return c;
                }
            } catch (FederationException e) {
                last = e;
            }
        }
        if (last != null && depth == 0) {
            throw last;
        }
        return null;
    }

    /** Applies superior metadata, then merged metadata policies from the TA downwards (§6.1.4). */
    static Map<String, Map<String, Object>> resolveMetadata(List<EntityStatement> statements) throws FederationException {
        EntityStatement leaf = statements.getFirst();
        Map<String, Map<String, Object>> md = new LinkedHashMap<>();
        leaf.metadata().forEach((k, v) -> md.put(k, new LinkedHashMap<>(Json.object(v))));
        if (statements.size() > 1) {
            statements.get(1).metadata().forEach((type, v) ->
                    md.computeIfAbsent(type, t -> new LinkedHashMap<>()).putAll(Json.object(v)));
        }
        Map<String, Map<String, Object>> merged = new LinkedHashMap<>();
        for (int j = statements.size() - 2; j >= 1; j--) {
            Map<String, Object> policy = statements.get(j).metadataPolicy();
            for (Map.Entry<String, Object> e : policy.entrySet()) {
                try {
                    merged.put(e.getKey(), MetadataPolicy.merge(merged.get(e.getKey()), Json.object(e.getValue())));
                } catch (MetadataPolicy.PolicyException ex) {
                    throw new FederationException("invalid_metadata", "Policy merge failed for " + e.getKey() + ": " + ex.getMessage());
                }
            }
        }
        for (Map.Entry<String, Map<String, Object>> p : merged.entrySet()) {
            if (!md.containsKey(p.getKey())) {
                continue;
            }
            try {
                md.put(p.getKey(), MetadataPolicy.apply(md.get(p.getKey()), p.getValue()));
            } catch (MetadataPolicy.PolicyException ex) {
                throw new FederationException("invalid_metadata", p.getKey() + " metadata violates policy: " + ex.getMessage());
            }
        }
        return md;
    }

    private static void checkConstraints(List<EntityStatement> statements) throws FederationException {
        for (int j = 1; j < statements.size() - 1; j++) {
            Map<String, Object> c = Json.object(statements.get(j).claims().get("constraints"));
            if (c == null) {
                continue;
            }
            if (c.get("max_path_length") instanceof Number max && (j - 1) > max.intValue()) {
                throw new FederationException("invalid_trust_chain", "max_path_length exceeded");
            }
            List<String> allowed = Json.strings(c.get("allowed_entity_types"));
            if (!allowed.isEmpty()) {
                for (String type : statements.getFirst().metadata().keySet()) {
                    if (!"federation_entity".equals(type) && !allowed.contains(type)) {
                        throw new FederationException("invalid_trust_chain", "Entity type " + type + " not allowed by constraints");
                    }
                }
            }
        }
    }

    /** Verifies trust marks in the leaf configuration whose issuer is accredited by the trust anchor. */
    private List<Map<String, Object>> verifyTrustMarks(EntityStatement leaf, EntityStatement ta) {
        List<Map<String, Object>> out = new ArrayList<>();
        Map<String, Object> issuers = Json.object(ta.claims().get("trust_mark_issuers"));
        List<Object> marks = Json.array(leaf.claims().get("trust_marks"));
        if (marks == null) {
            return out;
        }
        for (Object o : marks) {
            Map<String, Object> m = Json.object(o);
            if (m == null) continue;
            String type = Json.string(m, "trust_mark_type");
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("trust_mark_type", type);
            boolean verified = false;
            try {
                JWSObject tm = JWSObject.parse(Json.string(m, "trust_mark"));
                Map<String, Object> c = tm.getPayload().toJSONObject();
                String iss = Json.string(c, "iss");
                result.put("issuer", iss);
                List<String> allowed = issuers == null ? null : Json.strings(issuers.get(type));
                boolean accredited = allowed != null && (allowed.isEmpty() || allowed.contains(iss));
                if (accredited && leaf.sub().equals(c.get("sub")) && type != null && type.equals(c.get("trust_mark_type"))) {
                    EntityStatement issuerEc = iss.equals(ta.sub()) ? ta : entityConfiguration(iss);
                    JWK key = issuerEc.jwks().getKeyByKeyId(tm.getHeader().getKeyID());
                    verified = key instanceof AsymmetricJWK a
                            && tm.verify(new DefaultJWSVerifierFactory().createJWSVerifier(tm.getHeader(), a.toPublicKey()));
                }
            } catch (Exception e) {
                result.put("error", e.getMessage());
            }
            result.put("verified", verified);
            out.add(result);
        }
        return out;
    }

    private String get(URI url, String accept) throws FederationException {
        try {
            HttpFetcher.Response r = http.execute(HttpFetcher.Request.get(url, accept));
            if (r.status() == 404) {
                throw new FederationException("not_found", "HTTP 404 from " + url);
            }
            if (!r.isSuccess()) {
                throw new FederationException("temporarily_unavailable", "HTTP " + r.status() + " from " + url);
            }
            return r.bodyAsString();
        } catch (IOException e) {
            throw new FederationException("temporarily_unavailable", "Fetching " + url + " failed: " + e.getMessage());
        }
    }
}
