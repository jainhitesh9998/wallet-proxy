package io.vctrust.trust.core.metadata;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.TrustedEntity;

import java.util.List;
import java.util.Map;

/** Derives normalized entity data from OpenID4VCI issuer metadata. */
public final class Oid4vciMetadataMapper {

    private Oid4vciMetadataMapper() {
    }

    /** Entity attribute: the JSON-LD context URLs the party's credentials use (declared in its metadata, or curated). */
    public static final String CONTEXTS = "jsonLdContexts";
    /** Entity attribute: context URL to the SHA-256 (base64url) an operator pinned for it. */
    public static final String CONTEXT_DIGESTS = "jsonLdContextDigests";

    /**
     * Adds what the issuer's metadata says about the issuer: role, identifier, display (when none is curated) and the
     * JSON-LD contexts of its credential configurations. Never authorizations: those are not the issuer's to grant.
     */
    public static TrustedEntity.Builder describe(TrustedEntity.Builder b, Map<String, Object> md) {
        String issuer = Json.string(md, "credential_issuer");
        b.role(EntityRole.CREDENTIAL_ISSUER);
        if (issuer != null) {
            b.identifier(IdentifierType.URL, issuer);
        }
        if (!b.hasDisplay() && md.get("display") instanceof List<?> displays) {
            for (Object d : displays) {
                Map<String, Object> dm = Json.object(d);
                if (dm != null && Json.string(dm, "name") != null) {
                    Map<String, Object> logo = Json.object(dm.get("logo"));
                    b.display(new LocalizedDisplay(Json.string(dm, "locale"), Json.string(dm, "name"),
                            Json.string(dm, "description"), logo == null ? null : Json.string(logo, "uri")));
                }
            }
        }
        List<String> contexts = contexts(md);
        if (!contexts.isEmpty()) {
            b.attribute(CONTEXTS, contexts);
        }
        return b;
    }

    /** The https JSON-LD context URLs of the issuer's credential configurations (ldp_vc, jwt_vc_json-ld), in first-seen order. */
    public static List<String> contexts(Map<String, Object> md) {
        Map<String, Object> configs = Json.object(md.get("credential_configurations_supported"));
        if (configs == null) {
            return List.of();
        }
        return configs.values().stream().map(Json::object).filter(java.util.Objects::nonNull)
                .map(c -> Json.object(c.get("credential_definition"))).filter(java.util.Objects::nonNull)
                .flatMap(def -> def.get("@context") instanceof List<?> l ? l.stream() : java.util.stream.Stream.empty())
                .filter(String.class::isInstance).map(String.class::cast).filter(u -> u.startsWith("https://") || u.startsWith("http://"))
                .distinct().limit(MAX_CONTEXTS).toList();
    }

    /** The contexts taken from one issuer's metadata: the issuer chooses them, and each is something the service fetches. */
    public static final int MAX_CONTEXTS = 20;

    /**
     * One authorization per credential configuration: format plus doctype / vct / most specific VC type. Only for
     * metadata that an authority vouches for (resolved through an OpenID Federation trust chain), never for metadata
     * fetched from the issuer alone.
     */
    public static List<CredentialAuthorization> authorizations(Map<String, Object> md) {
        Map<String, Object> configs = Json.object(md.get("credential_configurations_supported"));
        if (configs == null) {
            return List.of();
        }
        return configs.values().stream()
                .map(Json::object)
                .filter(java.util.Objects::nonNull)
                .map(c -> CredentialAuthorization.of(CredentialFormats.canonical(Json.string(c, "format")), typeOf(c)))
                .distinct()
                .toList();
    }

    public static String typeOf(Map<String, Object> config) {
        String format = CredentialFormats.canonical(Json.string(config, "format"));
        if (CredentialFormats.MSO_MDOC.equals(format)) {
            return Json.string(config, "doctype");
        }
        if (CredentialFormats.SD_JWT_VC.equals(format)) {
            return Json.string(config, "vct");
        }
        Map<String, Object> def = Json.object(config.get("credential_definition"));
        if (def != null) {
            List<String> types = Json.strings(def.get("type"));
            return types.stream().filter(t -> !"VerifiableCredential".equals(t)).findFirst()
                    .orElse(types.isEmpty() ? null : types.getFirst());
        }
        return null;
    }
}
