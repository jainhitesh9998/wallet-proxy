package io.vctrust.trust.server.service;

import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.cbor.CBORMapper;
import io.vctrust.trust.core.json.Json;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Tells a credential status list from anything else, by its shape: an IETF Token Status List (a JWT or a CWT with a
 * {@code status_list} claim), or a W3C status list credential (a credential whose subject has an {@code encodedList},
 * as JSON, as a JWT, or enveloped). The relay passes on nothing else; whether a list is genuine is for the wallet,
 * which verifies its signature.
 */
final class StatusLists {

    private static final CBORMapper CBOR = CBORMapper.builder().build();
    /** CWT claim key of the status list (Token Status List, §5.2). */
    private static final String STATUS_LIST_CLAIM = "65533";

    private StatusLists() {
    }

    static boolean isStatusList(byte[] body) {
        try {
            int at = 0;
            while (at < body.length && (body[at] == ' ' || body[at] == '\n' || body[at] == '\r' || body[at] == '\t')) {
                at++;
            }
            if (at == body.length) {
                return false;
            }
            if (body[at] == '{') {
                return credential(Json.parseObject(body));
            }
            if (body[at] == 'e') {
                return jwt(new String(body, StandardCharsets.US_ASCII).trim());
            }
            return cwt(body);
        } catch (Exception e) {
            return false;
        }
    }

    /** A compact JWS whose payload is a Token Status List, or a status list credential (VCDM 2.0, or 1.1 under {@code vc}). */
    private static boolean jwt(String compact) {
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3) {
            return false;
        }
        Map<String, Object> claims = Json.parseObject(Base64.getUrlDecoder().decode(parts[1]));
        if (claims.get("status_list") instanceof Map<?, ?> list) {
            return list.get("lst") instanceof String;
        }
        return credential(claims) || (claims.get("vc") instanceof Map<?, ?> vc && credential(vc));
    }

    private static boolean credential(Map<?, ?> credential) {
        Object subject = credential.get("credentialSubject");
        if (subject instanceof Map<?, ?> s) {
            return s.get("encodedList") instanceof String;
        }
        if (subject instanceof List<?> subjects) {
            return subjects.stream().anyMatch(s -> s instanceof Map<?, ?> m && m.get("encodedList") instanceof String);
        }
        // VCDM 2.0 §4.13: a credential secured as a JWT, carried in a data: URL
        if (credential.get("id") instanceof String id && id.startsWith("data:") && id.indexOf(',') > 0) {
            return jwt(id.substring(id.indexOf(',') + 1));
        }
        return false;
    }

    /** A COSE_Sign1 whose payload is a CWT with the status list claim. */
    private static boolean cwt(byte[] body) {
        JsonNode sign1 = CBOR.readTree(body);
        if (sign1 == null || !sign1.isArray() || sign1.size() != 4 || !sign1.get(2).isBinary()) {
            return false;
        }
        JsonNode claims = CBOR.readTree(sign1.get(2).binaryValue());
        return claims != null && claims.path(STATUS_LIST_CLAIM).has("lst");
    }
}
