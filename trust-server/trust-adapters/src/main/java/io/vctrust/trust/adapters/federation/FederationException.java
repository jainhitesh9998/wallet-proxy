package io.vctrust.trust.adapters.federation;

/** OpenID Federation error with its error code ({@code invalid_trust_chain}, {@code not_found}, ...). */
public class FederationException extends Exception {
    private final String code;

    public FederationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
