package io.vctrust.trust.core.spi;

public class TrustSourceException extends Exception {
    public TrustSourceException(String message) {
        super(message);
    }

    public TrustSourceException(String message, Throwable cause) {
        super(message, cause);
    }
}
