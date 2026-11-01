package io.vctrust.trust.core.metadata;

/** Raised when metadata cannot be fetched or fails validation. {@code code} is a stable machine code. */
public class MetadataException extends Exception {
    private final String code;

    public MetadataException(String code, String message) {
        super(message);
        this.code = code;
    }

    public MetadataException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
