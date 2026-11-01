package io.vctrust.trust.core.did;

import java.util.regex.Pattern;

/**
 * A parsed DID or DID URL (W3C DID Core §3). Only the parts needed for resolution and dereferencing are
 * modelled.
 */
public record Did(String method, String methodSpecificId, String path, String query, String fragment) {

    private static final Pattern METHOD = Pattern.compile("[a-z0-9]+");
    private static final Pattern MSI = Pattern.compile("([A-Za-z0-9._\\-]|%[0-9A-Fa-f]{2}|:)*([A-Za-z0-9._\\-]|%[0-9A-Fa-f]{2})");

    public static Did parse(String didUrl) {
        if (didUrl == null || !didUrl.startsWith("did:")) {
            throw new InvalidDidException("Not a DID: " + didUrl);
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
            throw new InvalidDidException("Missing DID method: " + didUrl);
        }
        String method = rest.substring(0, colon);
        String msi = rest.substring(colon + 1);
        if (!METHOD.matcher(method).matches() || msi.isEmpty() || !MSI.matcher(msi).matches()) {
            throw new InvalidDidException("Malformed DID: " + didUrl);
        }
        return new Did(method, msi, path, query, fragment);
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
