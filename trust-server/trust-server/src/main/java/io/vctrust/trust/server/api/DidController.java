package io.vctrust.trust.server.api;

import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.DidService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import tools.jackson.databind.json.JsonMapper;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * DID resolution proxy. {@code /api/v1/did/{did}} returns the W3C resolution result; {@code /1.0/identifiers/{did}}
 * follows the Universal Resolver / DID Resolution HTTP binding, including {@code Accept}-driven representation.
 * The DID is read from the raw request path so that {@code %3A} in did:web stays intact.
 */
@RestController
public class DidController {

    private final DidService dids;
    private final ResponseSigner signer;
    private final JsonMapper mapper;

    public DidController(DidService dids, ResponseSigner signer, JsonMapper mapper) {
        this.dids = dids;
        this.signer = signer;
        this.mapper = mapper;
    }

    @GetMapping("/api/v1/did/**")
    public ResponseEntity<Object> resolve(ClientProfile client, HttpServletRequest req) {
        DidResolutionResult r = dids.resolve(didFromPath(req, "/api/v1/did/"));
        String err = r.error().orElse(null);
        return signer.respond(req, client, "trust-did-resolution+jwt", r.toJson(),
                ResponseEntity.status(DidResolutionResult.httpStatus(err)).cacheControl(cacheControl(r)));
    }

    @GetMapping("/1.0/identifiers/**")
    public ResponseEntity<Object> universal(ClientProfile client, HttpServletRequest req) {
        DidResolutionResult r = dids.resolve(didFromPath(req, "/1.0/identifiers/"));
        String err = r.error().orElse(null);
        String accept = req.getHeader("Accept") == null ? "" : req.getHeader("Accept");
        boolean documentOnly = (accept.contains("application/did") && !accept.contains("application/did-resolution"))
                || accept.contains("application/did+ld+json") || accept.contains("application/did+json");
        // Bodies are serialized here: application/did-resolution is not a +json type known to the converters.
        if (documentOnly && r.isSuccess()) {
            return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/did+ld+json"))
                    .cacheControl(cacheControl(r)).body(mapper.writeValueAsString(r.didDocument()));
        }
        return ResponseEntity.status(DidResolutionResult.httpStatus(err))
                .contentType(MediaType.parseMediaType("application/did-resolution"))
                .cacheControl(cacheControl(r)).body(mapper.writeValueAsString(r.toJson()));
    }

    static String didFromPath(HttpServletRequest req, String prefix) {
        String raw = req.getRequestURI();
        int i = raw.indexOf(prefix);
        if (i < 0) {
            throw ApiException.badRequest("invalid_request", "Missing DID");
        }
        String did = raw.substring(i + prefix.length());
        if (did.startsWith("did%3A") || did.startsWith("did%3a")) {
            did = URLDecoder.decode(did, StandardCharsets.UTF_8);
        }
        return did;
    }

    private static CacheControl cacheControl(DidResolutionResult r) {
        if (!r.isSuccess()) {
            return CacheControl.maxAge(Duration.ofSeconds(30));
        }
        Object cache = r.didResolutionMetadata().get("cache");
        if (cache instanceof Map<?, ?> m && m.get("expiresAt") instanceof String exp) {
            long secs = Math.max(0, Duration.between(java.time.Instant.now(), java.time.Instant.parse(exp)).toSeconds());
            return CacheControl.maxAge(Duration.ofSeconds(secs)).cachePrivate();
        }
        return CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate();
    }

    static HttpStatus status(String code) {
        return HttpStatus.valueOf(DidResolutionResult.httpStatus(code));
    }
}
