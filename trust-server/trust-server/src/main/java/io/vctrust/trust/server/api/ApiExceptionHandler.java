package io.vctrust.trust.server.api;

import io.vctrust.trust.core.spi.HttpFetcher.BlockedException;
import io.vctrust.trust.server.service.ServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;

/**
 * Maps exceptions to RFC 9457 problem details with a {@code code} extension member; the one place where a use
 * case's failure becomes an HTTP status. Errors are always {@code application/problem+json}, whatever the request
 * accepted (a CRL or status list request accepts only the binary type, which would otherwise leave the error
 * without a body).
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    static ProblemDetail problem(HttpStatus status, String code, String detail) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(status, detail);
        p.setType(URI.create("https://vctrust.io/problems/" + code));
        p.setTitle(code);
        p.setProperty("code", code);
        return p;
    }

    static ResponseEntity<Object> respond(ProblemDetail p) {
        return ResponseEntity.status(p.getStatus()).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(p);
    }

    static HttpStatus status(ServiceException.Kind kind) {
        return switch (kind) {
            case INVALID_REQUEST -> HttpStatus.BAD_REQUEST;
            case FORBIDDEN -> HttpStatus.FORBIDDEN;
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case UNPROCESSABLE -> HttpStatus.UNPROCESSABLE_CONTENT;
            case UPSTREAM_FAILED -> HttpStatus.BAD_GATEWAY;
            case UNAVAILABLE -> HttpStatus.SERVICE_UNAVAILABLE;
        };
    }

    @ExceptionHandler(ServiceException.class)
    ResponseEntity<Object> service(ServiceException e) {
        return respond(problem(status(e.kind()), e.code(), e.getMessage()));
    }

    @ExceptionHandler(BlockedException.class)
    ResponseEntity<Object> blocked(BlockedException e) {
        return respond(problem(HttpStatus.BAD_REQUEST, "url_not_allowed", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Object> invalid(Exception e) {
        return respond(problem(HttpStatus.BAD_REQUEST, "invalid_request", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> unexpected(Exception e) {
        log.error("Unhandled error", e);
        return respond(problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal_error", "Internal error"));
    }

    /**
     * A body that cannot be read. When the reason is a member of the wrong type ({@link Dtos.WrongType}), the answer
     * names the member, as an invalid request does; otherwise Spring's answer, which names nothing of the service.
     */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatusCode status,
                                                                  WebRequest request) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof Dtos.WrongType wrong) {
                return respond(problem(HttpStatus.BAD_REQUEST, "invalid_request", wrong.getMessage()));
            }
        }
        return super.handleHttpMessageNotReadable(ex, headers, status, request);
    }

    /** Spring MVC's own errors (missing parameter, wrong method, ...): problem+json as well. */
    @Override
    protected ResponseEntity<Object> createResponseEntity(Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        HttpHeaders h = new HttpHeaders();
        h.putAll(headers);
        if (body instanceof ProblemDetail) {
            h.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        }
        return new ResponseEntity<>(body, h, statusCode);
    }
}
