package io.vctrust.trust.adapters.x509;

import io.vctrust.trust.adapters.support.AdapterSupport;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;

import io.vctrust.trust.core.x509.Certificates;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code type: x509-bundle} — trust anchors from a PEM/DER bundle or a JSON document holding a base64
 * certificate. Properties: {@code domain}, {@code certificateLocation}, optional {@code certificateJsonField},
 * optional {@code entity} to link anchors to a registry entity, optional {@code docTypes}, {@code sha256}: the
 * fingerprints the certificates must have, and optional {@code publicUri} (see {@link AdapterSupport#publishedLocation}).
 *
 * <p>A certificate fetched over the network becomes a trust anchor only when it matches a pinned fingerprint: without
 * the pin, whoever answers at that URL decides what is trusted. {@code allowUnpinned: true} accepts that for a
 * sandbox.
 */
public final class X509BundleSourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "x509-bundle";
    }

    /** A SHA-256 fingerprint as base64url, from base64url or from hex with or without colons (as openssl prints it). */
    static String fingerprint(String pin) {
        String hex = pin.replace(":", "").trim();
        if (hex.matches("(?i)[0-9a-f]{64}")) {
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.HexFormat.of().parseHex(hex));
        }
        return pin.trim();
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        AdapterSupport.publicUri(def); // a bad one is a configuration error, refused before the service starts
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            public SourceLoadResult load() throws TrustSourceException {
                TrustDomain domain = TrustDomain.of(def.requireString("domain"));
                try {
                    List<X509Certificate> certs = AdapterSupport.certificates(def.properties(), ctx.resources());
                    checkPins(certs);
                    Provenance prov = Provenance.of(def.id(), type(), def.frameworkId(),
                            AdapterSupport.publishedLocation(def, def.string("certificateLocation")), ctx.clock().instant());
                    Map<String, Object> constraints = def.list("docTypes").isEmpty() ? Map.of()
                            : Map.of("docTypes", def.strings("docTypes"));
                    List<TrustAnchor> anchors = new ArrayList<>();
                    for (X509Certificate c : certs) {
                        anchors.add(new TrustAnchor(null, domain, c, def.frameworkId(), def.string("entity"), null,
                                constraints, prov));
                    }
                    return new SourceLoadResult(List.of(), anchors, ListInfo.unsigned(), List.of());
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load certificate bundle: " + e.getMessage(), e);
                }
            }

            private void checkPins(List<X509Certificate> certs) {
                List<String> pins = def.strings("sha256").stream().map(X509BundleSourceFactory::fingerprint).toList();
                String location = String.valueOf(def.string("certificateLocation"));
                boolean remote = location.startsWith("https://") || location.startsWith("http://");
                if (pins.isEmpty()) {
                    if (remote && !def.bool("allowUnpinned", false)) {
                        throw new IllegalArgumentException("certificates from " + location + " need sha256 fingerprints (or allowUnpinned: true)");
                    }
                    return;
                }
                for (X509Certificate c : certs) {
                    if (!pins.contains(Certificates.sha256Thumbprint(c))) {
                        throw new IllegalArgumentException("certificate " + c.getSubjectX500Principal().getName()
                                + " (" + Certificates.sha256Thumbprint(c) + ") is not among the pinned fingerprints");
                    }
                }
            }
        };
    }
}
