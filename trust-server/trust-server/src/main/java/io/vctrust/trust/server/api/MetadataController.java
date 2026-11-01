package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.MetadataService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/** OpenID4VCI issuer metadata proxy. */
@RestController
@RequestMapping("/api/v1/issuers")
public class MetadataController {

    private final MetadataService metadata;
    private final ResponseSigner signer;

    public MetadataController(MetadataService metadata, ResponseSigner signer) {
        this.metadata = metadata;
        this.signer = signer;
    }

    @GetMapping("/metadata")
    public ResponseEntity<Object> issuerMetadata(ClientProfile client, HttpServletRequest req,
                                                 @RequestParam("credential_issuer") String credentialIssuer) {
        MetadataService.IssuerMetadataEnvelope env = metadata.issuer(credentialIssuer, client);
        return signer.respond(req, client, "trust-metadata+jwt", env, ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(metadata.maxAgeSeconds(env))).cachePrivate())
                .header("X-Trust-Decision", env.trust().decision().name())
                .header("X-Trust-Source", env.stale() ? "cache-stale" : "trust-service"));
    }
}
