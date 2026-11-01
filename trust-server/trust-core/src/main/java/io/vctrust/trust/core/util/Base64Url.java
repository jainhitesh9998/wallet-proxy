package io.vctrust.trust.core.util;

import java.util.Base64;

/** Base64url (no padding) helpers. */
public final class Base64Url {
    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** Decodes base64url or standard base64, with or without padding. */
    public static byte[] decodeLenient(String s) {
        String t = s.trim().replace('+', '-').replace('/', '_').replace("=", "");
        return Base64.getUrlDecoder().decode(t);
    }
}
