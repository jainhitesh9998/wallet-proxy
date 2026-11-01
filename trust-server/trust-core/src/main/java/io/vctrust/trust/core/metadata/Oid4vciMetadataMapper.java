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

    /** Adds role, identifier, display and per-configuration authorizations to the builder. */
    public static TrustedEntity.Builder enrich(TrustedEntity.Builder b, Map<String, Object> md, boolean addAuthorizations) {
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
                    String logoUri = logo == null ? null : Json.string(logo, "uri") != null ? Json.string(logo, "uri") : Json.string(logo, "url");
                    b.display(new LocalizedDisplay(Json.string(dm, "locale"), Json.string(dm, "name"),
                            Json.string(dm, "description"), logoUri));
                }
            }
        }
        if (addAuthorizations) {
            for (CredentialAuthorization a : authorizations(md)) {
                b.authorization(a);
            }
        }
        b.metadata("openid_credential_issuer", md);
        return b;
    }

    /** One authorization per credential configuration: format plus doctype / vct / most specific VC type. */
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
