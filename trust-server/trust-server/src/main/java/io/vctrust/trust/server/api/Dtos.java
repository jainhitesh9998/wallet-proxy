package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.evaluation.TrustQuery;
import io.vctrust.trust.core.model.EntityRole;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Request / response bodies of the native API (camelCase JSON). */
public final class Dtos {

    private Dtos() {
    }

    public record EvaluateRequest(String role, Subject subject, Context context) {
        public TrustQuery toQuery() {
            Subject s = subject == null ? new Subject(null, null, null, null) : subject;
            Context c = context == null ? new Context(null, null, null, null, null, null, null) : context;
            return new TrustQuery(parseRole(role), new TrustQuery.Subject(s.identifier(), s.x5c(), s.jwk(), s.kid()),
                    new TrustQuery.Context(c.protocol(), c.credentialFormat(), c.credentialType(), c.time(), c.responseUri(),
                            c.trustedAuthorities() == null ? List.of() : c.trustedAuthorities().stream()
                                    .map(t -> new TrustQuery.TrustedAuthority(t.type(), t.values())).toList(),
                            c.credentialTypes()));
        }
    }

    public record Subject(String identifier, List<String> x5c, Map<String, Object> jwk, String kid) {
    }

    public record Context(String protocol, String credentialFormat, String credentialType, Instant time,
                          String responseUri, List<TrustedAuthority> trustedAuthorities, List<String> credentialTypes) {
    }

    public record TrustedAuthority(String type, List<String> values) {
    }

    public record BatchEvaluateRequest(List<EvaluateRequest> queries) {
    }

    public record X509ValidateRequest(List<String> chain, String domain, Instant time, String expectedDnsName,
                                      String docType, String framework) {
    }

    public record Page<T>(List<T> items, int total, int page, int size, long registryVersion) {
    }

    public record EntityDetail(EntityView entity, Map<String, Map<String, Object>> metadata,
                               Map<String, Map<String, Object>> metadataPolicy, List<Map<String, Object>> anchors) {
    }

    public static EntityRole parseRole(String role) {
        if (role == null || role.isBlank()) {
            return null;
        }
        return switch (role.trim().toLowerCase(Locale.ROOT).replace('-', '_')) {
            case "issuer", "credential_issuer" -> EntityRole.CREDENTIAL_ISSUER;
            case "verifier", "relying_party", "rp" -> EntityRole.VERIFIER;
            case "wallet", "wallet_provider" -> EntityRole.WALLET_PROVIDER;
            case "authorization_server", "as" -> EntityRole.AUTHORIZATION_SERVER;
            case "accreditation_authority" -> EntityRole.ACCREDITATION_AUTHORITY;
            case "status_list_provider" -> EntityRole.STATUS_LIST_PROVIDER;
            default -> EntityRole.valueOf(role.trim().toUpperCase(Locale.ROOT));
        };
    }
}
