package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.EntityView;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.x509.CertificateProfile;
import io.vctrust.trust.core.x509.CertificateProfiles;
import io.vctrust.trust.core.x509.Certificates;
import io.vctrust.trust.core.x509.PathValidationResult;
import io.vctrust.trust.core.x509.RevocationChecker;
import io.vctrust.trust.core.x509.X509PathValidator;
import io.vctrust.trust.server.config.TrustJacksonModule;
import io.vctrust.trust.server.config.TrustProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** X.509 path validation against a trust domain, and anchor export. */
@RestController
@RequestMapping("/api/v1/x509")
public class X509Controller {

    private final TrustRegistry registry;
    private final X509PathValidator validator;
    private final ResponseSigner signer;
    private final RevocationChecker revocation;

    public X509Controller(TrustRegistry registry, X509PathValidator validator, ResponseSigner signer,
                          RevocationChecker revocation, TrustProperties props) {
        this.registry = registry;
        this.validator = validator;
        this.signer = signer;
        this.revocation = props.getRevocation().isEnabled() ? revocation : null;
    }

    @PostMapping("/validate")
    public ResponseEntity<Object> validate(ClientProfile client, HttpServletRequest req, @RequestBody Dtos.X509ValidateRequest body) {
        if (body.chain() == null || body.chain().isEmpty() || body.domain() == null) {
            throw ApiException.badRequest("invalid_request", "chain and domain are required");
        }
        TrustDomain domain = TrustDomain.of(body.domain());
        RegistrySnapshot snap = registry.snapshot();
        List<TrustAnchor> anchors = snap.anchors(domain).stream()
                .filter(a -> client.accepts(a.frameworkId()))
                .filter(a -> body.framework() == null || body.framework().equals(a.frameworkId()))
                .toList();
        PathValidationResult r = validator.validate(Certificates.fromBase64List(body.chain()), anchors,
                new X509PathValidator.Options(body.time(), CertificateProfiles.forDomain(domain),
                        new CertificateProfile.ProfileContext(body.expectedDnsName(), body.docType()), null)
                        .withRevocation(revocation, client.requireRevocationStatus()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("domain", domain.name());
        out.put("result", r);
        if (r.valid() && r.anchor() != null && r.anchor().entityId() != null) {
            snap.entity(r.anchor().entityId()).filter(e -> client.accepts(e.frameworkId()))
                    .ifPresent(e -> out.put("entity", EntityView.of(e)));
        }
        return signer.respond(req, client, "trust-x509+jwt", out, ResponseEntity.ok().cacheControl(CacheControl.noStore()));
    }

    @GetMapping("/anchors")
    public ResponseEntity<Object> anchors(ClientProfile client, HttpServletRequest req,
                                          @RequestParam(required = false) String domain,
                                          @RequestParam(required = false) String framework,
                                          @RequestParam(defaultValue = "json") String format) {
        RegistrySnapshot snap = registry.snapshot();
        List<TrustAnchor> list = (domain == null ? snap.allAnchors().stream() : snap.anchors(TrustDomain.of(domain)).stream())
                .filter(a -> client.accepts(a.frameworkId()))
                .filter(a -> framework == null || framework.equals(a.frameworkId()))
                .toList();
        if ("pem".equalsIgnoreCase(format)) {
            String pem = list.stream().map(a -> Certificates.toPem(a.certificate())).collect(Collectors.joining());
            return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/pem-certificate-chain"))
                    .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5))).eTag(snap.etag()).body(pem);
        }
        return signer.respond(req, client, "trust-anchors+jwt", list.stream().map(TrustJacksonModule::anchorView).toList(),
                ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate()).eTag(snap.etag()));
    }
}
