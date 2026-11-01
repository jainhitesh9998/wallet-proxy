package io.vctrust.trust.core.model;

import java.util.Map;
import java.util.Set;

/** Credential format identifiers (OpenID4VCI 1.0 Appendix A) and their legacy aliases. */
public final class CredentialFormats {

    public static final String LDP_VC = "ldp_vc";
    public static final String JWT_VC_JSON = "jwt_vc_json";
    public static final String JWT_VC_JSON_LD = "jwt_vc_json-ld";
    public static final String MSO_MDOC = "mso_mdoc";
    public static final String SD_JWT_VC = "dc+sd-jwt";
    /** Pre-final identifier for SD-JWT VC, still emitted by some issuers. */
    public static final String SD_JWT_VC_LEGACY = "vc+sd-jwt";

    private static final Map<String, String> CANONICAL = Map.of(SD_JWT_VC_LEGACY, SD_JWT_VC);

    public static final Set<String> ALL = Set.of(LDP_VC, JWT_VC_JSON, JWT_VC_JSON_LD, MSO_MDOC, SD_JWT_VC);

    private CredentialFormats() {
    }

    public static String canonical(String format) {
        return format == null ? null : CANONICAL.getOrDefault(format, format);
    }

    public static boolean sameFormat(String a, String b) {
        return canonical(a).equals(canonical(b));
    }

    public static boolean isW3c(String format) {
        String f = canonical(format);
        return LDP_VC.equals(f) || JWT_VC_JSON.equals(f) || JWT_VC_JSON_LD.equals(f);
    }
}
