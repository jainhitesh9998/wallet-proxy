package io.vctrust.trust.server.service;

import io.vctrust.trust.core.evaluation.Decision;
import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.server.api.ApiException;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * ToIP Trust Registry Query Protocol v2.0 binding. {@code authority_id} names a framework (by id or governance
 * URI); {@code action} maps to a role ({@code issue}, {@code verify}/{@code request}, {@code provide-wallet});
 * {@code resource} is a credential type, optionally prefixed with a format ({@code mso_mdoc:org.iso.18013.5.1.mDL}).
 */
public class TrqpService {

    private final TrustRegistry registry;
    private final TrustEvaluator evaluator;
    private final Clock clock;

    public TrqpService(TrustRegistry registry, TrustEvaluator evaluator, Clock clock) {
        this.registry = registry;
        this.evaluator = evaluator;
        this.clock = clock;
    }

    public Map<String, Object> authorization(Map<String, Object> req, ClientProfile client) {
        String entityId = required(req, "entity_id");
        String authorityId = required(req, "authority_id");
        String action = required(req, "action");
        String resource = required(req, "resource");
        Map<String, Object> context = req.get("context") instanceof Map<?, ?> m ? castMap(m) : Map.of();
        TrustFramework fw = framework(authorityId)
                .orElseThrow(() -> ApiException.notFound("Unknown authority_id " + authorityId));
        if (!client.accepts(fw.id())) {
            throw ApiException.notFound("Unknown authority_id " + authorityId);
        }
        EntityRole role = switch (action.toLowerCase(Locale.ROOT)) {
            case "issue", "issuer" -> EntityRole.CREDENTIAL_ISSUER;
            case "verify", "request", "verifier" -> EntityRole.VERIFIER;
            case "provide-wallet", "wallet" -> EntityRole.WALLET_PROVIDER;
            default -> throw ApiException.notFound("Unknown action " + action);
        };
        String format = null;
        String type = resource;
        int colon = resource.indexOf(':');
        if (colon > 0 && Set.of("mso_mdoc", "dc+sd-jwt", "vc+sd-jwt", "ldp_vc", "jwt_vc_json", "jwt_vc_json-ld")
                .contains(resource.substring(0, colon))) {
            format = resource.substring(0, colon);
            type = resource.substring(colon + 1);
        }
        if ("*".equals(type)) {
            type = null;
        }
        Instant time = context.get("time") instanceof String t ? Instant.parse(t) : null;
        ClientProfile scoped = new ClientProfile(client.clientId(), client.name(), Set.of(fw.id()),
                client.strictAuthorization(), client.allowUnregisteredMetadata(), client.admin(), client.requireRevocationStatus());
        TrustDecision d = evaluator.evaluate(new TrustQuery(role, new TrustQuery.Subject(entityId, null, null, null),
                new TrustQuery.Context("trqp", format, type, time, null, null)), scoped);
        Map<String, Object> out = response(entityId, authorityId, action, resource, context, time);
        out.put("authorized", d.decision() == Decision.TRUSTED);
        out.put("message", d.summary());
        return out;
    }

    public Map<String, Object> recognition(Map<String, Object> req, ClientProfile client) {
        String entityId = required(req, "entity_id");
        String authorityId = required(req, "authority_id");
        String action = required(req, "action");
        String resource = required(req, "resource");
        Map<String, Object> context = req.get("context") instanceof Map<?, ?> m ? castMap(m) : Map.of();
        TrustFramework fw = framework(authorityId)
                .orElseThrow(() -> ApiException.notFound("Unknown authority_id " + authorityId));
        Optional<TrustFramework> other = framework(entityId);
        String recognizes = fw.attributes().getOrDefault("recognizes", "");
        boolean recognized = other.map(o -> o.id().equals(fw.id())
                || List.of(recognizes.split("\\s*,\\s*")).contains(o.id())).orElse(false)
                || List.of(recognizes.split("\\s*,\\s*")).contains(entityId);
        Instant time = context.get("time") instanceof String t ? Instant.parse(t) : null;
        Map<String, Object> out = response(entityId, authorityId, action, resource, context, time);
        out.put("recognized", recognized);
        out.put("message", recognized ? "Authority recognizes " + entityId : "No recognition recorded");
        return out;
    }

    private Map<String, Object> response(String entityId, String authorityId, String action, String resource,
                                         Map<String, Object> context, Instant time) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entity_id", entityId);
        out.put("authority_id", authorityId);
        out.put("action", action);
        out.put("resource", resource);
        if (time != null) {
            out.put("time_requested", time.toString());
        }
        out.put("time_evaluated", clock.instant().toString());
        if (!context.isEmpty()) {
            out.put("context", context);
        }
        return out;
    }

    private Optional<TrustFramework> framework(String authorityId) {
        return registry.snapshot().frameworks().stream()
                .filter(f -> f.id().equals(authorityId) || authorityId.equals(f.governanceUri()))
                .findFirst();
    }

    private static String required(Map<String, Object> req, String key) {
        Object v = req.get(key);
        if (!(v instanceof String s) || s.isBlank()) {
            throw ApiException.badRequest("invalid_request", "Missing required field " + key);
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> m) {
        return (Map<String, Object>) m;
    }
}
