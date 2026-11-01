package io.vctrust.trust.adapters.support;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.x509.CertificateProfiles;
import io.vctrust.trust.core.x509.PathValidationResult;
import io.vctrust.trust.core.x509.X509PathValidator;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Validates the signer of a list (TL, LoTE, VICAL) against certificates pinned in the source definition
 * ({@code signerCertificates}: inline PEM list, or {@code signerCertificateLocation}). A signer is accepted
 * if it is pinned directly or chains to a pinned certificate.
 */
public final class SignerVerification {

    private final List<X509Certificate> pinned;

    private SignerVerification(List<X509Certificate> pinned) {
        this.pinned = pinned;
    }

    public static SignerVerification from(SourceDefinition def, ResourceLoader loader) throws IOException {
        List<X509Certificate> certs = new ArrayList<>();
        for (String s : def.strings("signerCertificates")) {
            certs.addAll(AdapterSupport.parseCertificateText(s));
        }
        if (def.string("signerCertificateLocation") != null) {
            certs.addAll(AdapterSupport.certificates(Map.of("certificateLocation", def.string("signerCertificateLocation")), loader));
        }
        return new SignerVerification(certs);
    }

    public static SignerVerification of(List<X509Certificate> pinned) {
        return new SignerVerification(List.copyOf(pinned));
    }

    public boolean configured() {
        return !pinned.isEmpty();
    }

    public List<X509Certificate> pinned() {
        return pinned;
    }

    /** True if the chain (leaf first) is pinned or validates to a pinned certificate at {@code time}. */
    public PathValidationResult validate(List<X509Certificate> chain, Instant time) {
        List<TrustAnchor> anchors = pinned.stream()
                .map(c -> new TrustAnchor(null, TrustDomain.LIST_SIGNER, c, null, null, null, null, null)).toList();
        return new X509PathValidator().validate(chain, anchors, X509PathValidator.Options.at(time, CertificateProfiles.NONE));
    }
}
