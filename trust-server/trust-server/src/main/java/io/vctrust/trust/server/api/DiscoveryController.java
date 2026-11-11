package io.vctrust.trust.server.api;

import io.vctrust.trust.server.service.ServiceDescription;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/** Service discovery document and the JWKS clients pin. */
@RestController
public class DiscoveryController {

    private final ServiceDescription description;

    public DiscoveryController(ServiceDescription description) {
        this.description = description;
    }

    @GetMapping(value = "/.well-known/trust-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> discovery() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5))).body(description.document());
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/jwk-set+json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofHours(1))).body(description.jwks());
    }
}
