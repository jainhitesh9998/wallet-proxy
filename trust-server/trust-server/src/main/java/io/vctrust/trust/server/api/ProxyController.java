package io.vctrust.trust.server.api;

import io.vctrust.trust.core.did.DidResolutionResult;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.CrlRelay;
import io.vctrust.trust.server.service.DidService;
import io.vctrust.trust.server.service.MetadataService;
import io.vctrust.trust.server.service.StatusListRelay;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * The proxy: what a wallet would otherwise fetch from each counterparty, fetched, checked and cached here.
 *
 * <ul>
 * <li>{@code issuer-metadata} and {@code did}: documents that carry no signature of their own. With
 *     {@code Accept: application/jwt} the answer is signed by the service key, so a client verifies it like a
 *     snapshot.</li>
 * <li>{@code crl} and {@code status-list}: objects signed by their issuer, passed through byte for byte; the client
 *     verifies them, so the proxy need not be trusted for them.</li>
 * </ul>
 *
 * Every call tells the service which party a client is dealing with; clients that must not reveal that fetch from
 * the party directly, which is also what they do when the proxy is unavailable.
 */
@RestController
@RequestMapping("/api/v1/proxy")
public class ProxyController {

    static final MediaType PKIX_CRL = MediaType.parseMediaType("application/pkix-crl");

    private final MetadataService metadata;
    private final DidService dids;
    private final CrlRelay crls;
    private final StatusListRelay statusLists;
    private final ResponseSigner signer;

    public ProxyController(MetadataService metadata, DidService dids, CrlRelay crls, StatusListRelay statusLists,
                           ResponseSigner signer) {
        this.metadata = metadata;
        this.dids = dids;
        this.crls = crls;
        this.statusLists = statusLists;
        this.signer = signer;
    }

    /** OpenID4VCI issuer and authorization server metadata, validated, with the registry's metadata policy applied. */
    @GetMapping("/issuer-metadata")
    public ResponseEntity<Object> issuerMetadata(ClientProfile client, HttpServletRequest req, @RequestParam String issuer) {
        MetadataService.IssuerMetadataEnvelope env = metadata.issuer(issuer, client);
        return signer.respond(req, client, "trust-metadata+jwt", env, ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(metadata.maxAgeSeconds(env))).cachePrivate())
                .header("X-Trust-Source", env.stale() ? "cache-stale" : "trust-service"));
    }

    /** DID resolution: {@code /api/v1/proxy/did/did:web:issuer.example}; the result has the W3C DID Resolution shape. */
    @GetMapping("/did/**")
    public ResponseEntity<Object> did(ClientProfile client, HttpServletRequest req) {
        String raw = req.getRequestURI();
        String did = raw.substring(raw.indexOf("/proxy/did/") + "/proxy/did/".length());
        DidService.Answer a = dids.resolveFromPath(did);
        DidResolutionResult r = a.result();
        CacheControl cache = CacheControl.maxAge(a.maxAge());
        return signer.respond(req, client, "trust-did-resolution+jwt", r.toJson(),
                ResponseEntity.status(DidResolutionResult.httpStatus(r.error().orElse(null)))
                        .cacheControl(r.isSuccess() ? cache.cachePrivate() : cache));
    }

    /** The CRL at {@code url}, unmodified. */
    @GetMapping("/crl")
    public ResponseEntity<byte[]> crl(ClientProfile client, @RequestParam String url) {
        CrlRelay.Relayed r = crls.relay(url);
        return ResponseEntity.ok().contentType(PKIX_CRL).cacheControl(CacheControl.maxAge(r.maxAge())).body(r.der());
    }

    /** The status list at {@code uri}, byte for byte, with its content type. */
    @GetMapping("/status-list")
    public ResponseEntity<byte[]> statusList(ClientProfile client, HttpServletRequest req, @RequestParam String uri) {
        StatusListRelay.Relayed r = statusLists.fetch(uri, req.getHeader("Accept"));
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(r.contentType()))
                .cacheControl(CacheControl.maxAge(r.maxAge()).cachePrivate()).body(r.body());
    }
}
