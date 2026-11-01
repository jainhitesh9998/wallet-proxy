package io.vctrust.trust.server.api;

import io.vctrust.trust.server.http.SafeHttpFetcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;

/**
 * Maps exceptions to RFC 9457 problem details with a {@code code} extension member. Errors are always
 * {@code application/problem+json}, whatever the request accepted (a CRL or status list request accepts only the
 * binary type, which would otherwise leave the error without a body).
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

    @ExceptionHandler(ApiException.class)
    ResponseEntity<Object> api(ApiException e) {
        return respond(problem(e.status(), e.code(), e.getMessage()));
    }

    @ExceptionHandler(SafeHttpFetcher.BlockedRequestException.class)
    ResponseEntity<Object> blocked(SafeHttpFetcher.BlockedRequestException e) {
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
