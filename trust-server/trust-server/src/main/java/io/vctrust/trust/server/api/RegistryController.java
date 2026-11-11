package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.RegistryQueryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/** Browsing the normalized registry: frameworks, entities, issuers, verifiers, identifier lookup. */
@RestController
@RequestMapping("/api/v1")
public class RegistryController {

    private final RegistryQueryService registry;
    private final ResponseSigner signer;

    public RegistryController(RegistryQueryService registry, ResponseSigner signer) {
        this.registry = registry;
        this.signer = signer;
    }

    @GetMapping("/frameworks")
    public ResponseEntity<Object> frameworks(ClientProfile client, HttpServletRequest req) {
        return respond(req, client, registry.frameworks(client));
    }

    @GetMapping("/issuers")
    public ResponseEntity<Object> issuers(ClientProfile client, HttpServletRequest req,
                                          @RequestParam(required = false) String framework,
                                          @RequestParam(required = false) String format,
                                          @RequestParam(required = false) String type,
                                          @RequestParam(required = false) String q,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "100") int size) {
        return respond(req, client, registry.issuers(client, framework, format, type, q, page, size));
    }

    @GetMapping("/verifiers")
    public ResponseEntity<Object> verifiers(ClientProfile client, HttpServletRequest req,
                                            @RequestParam(required = false) String framework,
                                            @RequestParam(required = false) String q,
                                            @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "100") int size) {
        return respond(req, client, registry.verifiers(client, framework, q, page, size));
    }

    @GetMapping("/entities/lookup")
    public ResponseEntity<Object> lookup(ClientProfile client, HttpServletRequest req, @RequestParam String identifier,
                                         @RequestParam(required = false) String type,
                                         @RequestParam(defaultValue = "false") boolean onDemand) {
        return respond(req, client, registry.lookup(client, identifier, type, onDemand));
    }

    private ResponseEntity<Object> respond(HttpServletRequest req, ClientProfile client, RegistryQueryService.Answer<?> answer) {
        if (!answer.cacheable()) {
            return signer.respond(req, client, "trust-registry+jwt", answer.body(),
                    ResponseEntity.ok().cacheControl(CacheControl.noStore()));
        }
        String etag = answer.etag(req.getRequestURI(), req.getQueryString(), ResponseSigner.wantsJwt(req));
        String inm = req.getHeader("If-None-Match");
        if (etag.equals(inm)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build();
        }
        return signer.respond(req, client, "trust-registry+jwt", answer.body(),
                ResponseEntity.ok().eTag(etag).cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate()));
    }
}
