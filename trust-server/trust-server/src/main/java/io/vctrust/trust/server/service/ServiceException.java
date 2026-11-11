package io.vctrust.trust.server.service;

/**
 * A use case refusing a request or failing at it: a stable machine code, and the kind of failure. How a kind is
 * shown to a caller (an HTTP status, for the REST API) is decided where the answer is rendered.
 */
public class ServiceException extends RuntimeException {

    public enum Kind {
        INVALID_REQUEST,
        FORBIDDEN,
        NOT_FOUND,
        /** Understood, but what the request refers to cannot be used. */
        UNPROCESSABLE,
        /** The party asked on the caller's behalf could not be reached, or answered with something unusable. */
        UPSTREAM_FAILED,
        /** The service cannot answer yet. */
        UNAVAILABLE
    }

    private final Kind kind;
    private final String code;

    public ServiceException(Kind kind, String code, String message) {
        super(message);
        this.kind = kind;
        this.code = code;
    }

    public Kind kind() {
        return kind;
    }

    public String code() {
        return code;
    }

    public static ServiceException invalidRequest(String code, String message) {
        return new ServiceException(Kind.INVALID_REQUEST, code, message);
    }

    public static ServiceException forbidden(String message) {
        return new ServiceException(Kind.FORBIDDEN, "forbidden", message);
    }

    public static ServiceException notFound(String message) {
        return new ServiceException(Kind.NOT_FOUND, "not_found", message);
    }

    public static ServiceException upstreamFailed(String code, String message) {
        return new ServiceException(Kind.UPSTREAM_FAILED, code, message);
    }
}
