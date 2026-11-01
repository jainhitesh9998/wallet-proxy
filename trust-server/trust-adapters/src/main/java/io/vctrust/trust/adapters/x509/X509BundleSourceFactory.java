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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code type: x509-bundle} — trust anchors from a PEM/DER bundle or a JSON document holding a base64
 * certificate. Properties: {@code domain}, {@code certificateLocation}, optional {@code certificateJsonField},
 * optional {@code entity} to link anchors to a registry entity, optional {@code docTypes}.
 */
public final class X509BundleSourceFactory implements TrustSourceFactory {

    @Override
    public String type() {
        return "x509-bundle";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
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
                    Provenance prov = Provenance.of(def.id(), type(), def.frameworkId(),
                            def.string("certificateLocation"), ctx.clock().instant());
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
        };
    }
}
