package io.vctrust.trust.core.did;

import java.util.regex.Pattern;

/**
 * A parsed DID or DID URL (W3C DID Core §3). Only the parts needed for resolution and dereferencing are
 * modelled.
 */
public record Did(String method, String methodSpecificId, String path, String query, String fragment) {

    /** Longer than any DID in use (a did:jwk of a large RSA key is about a thousand characters); client libraries apply the same limit. */
    public static final int MAX_LENGTH = 4096;

    private static final Pattern METHOD = Pattern.compile("[a-z0-9]+");

    public static Did parse(String didUrl) {
        if (didUrl == null || !didUrl.startsWith("did:")) {
            throw new InvalidDidException("Not a DID: " + abbreviated(didUrl));
        }
        if (didUrl.length() > MAX_LENGTH) {
            throw new InvalidDidException("DID URL longer than " + MAX_LENGTH + " characters: " + abbreviated(didUrl));
        }
        String rest = didUrl.substring(4);
        String fragment = null;
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            fragment = rest.substring(hash + 1);
            rest = rest.substring(0, hash);
        }
        String query = null;
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        String path = null;
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            path = rest.substring(slash);
            rest = rest.substring(0, slash);
        }
        int colon = rest.indexOf(':');
        if (colon <= 0) {
            throw new InvalidDidException("Missing DID method: " + abbreviated(didUrl));
        }
        String method = rest.substring(0, colon);
        String msi = rest.substring(colon + 1);
        if (!METHOD.matcher(method).matches() || !isMethodSpecificId(msi)) {
            throw new InvalidDidException("Malformed DID: " + abbreviated(didUrl));
        }
        return new Did(method, msi, path, query, fragment);
    }

    /** DID Core §3.1: idchars (letters, digits, {@code . - _}, percent-encoded bytes) and colons, not ending in a colon. */
    private static boolean isMethodSpecificId(String msi) {
        if (msi.isEmpty() || msi.charAt(msi.length() - 1) == ':') {
            return false;
        }
        for (int i = 0; i < msi.length(); i++) {
            char c = msi.charAt(i);
            if (c == '%') {
                if (i + 2 >= msi.length() || !isHex(msi.charAt(i + 1)) || !isHex(msi.charAt(i + 2))) {
                    return false;
                }
                i += 2;
            } else if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':')) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHex(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    /** What is quoted back in an error: never the whole of an arbitrarily long input. */
    private static String abbreviated(String s) {
        return s == null || s.length() <= 120 ? s : s.substring(0, 120) + "… (" + s.length() + " characters)";
    }

    /** The DID itself, without path, query or fragment. */
    public String did() {
        return "did:" + method + ":" + methodSpecificId;
    }

    public static final class InvalidDidException extends IllegalArgumentException {
        public InvalidDidException(String message) {
            super(message);
        }
    }
}
