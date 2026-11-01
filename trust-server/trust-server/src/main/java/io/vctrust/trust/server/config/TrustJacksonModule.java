package io.vctrust.trust.server.config;

import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.x509.CertificateSummary;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.module.SimpleModule;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/** JSON representations of certificate-bearing core types. */
public class TrustJacksonModule extends SimpleModule {

    public TrustJacksonModule() {
        super("vc-trust");
        addSerializer(X509Certificate.class, new ValueSerializer<>() {
            @Override
            public void serialize(X509Certificate value, JsonGenerator gen, SerializationContext ctxt) {
                ctxt.writeValue(gen, CertificateSummary.of(value));
            }
        });
        addSerializer(TrustDomain.class, new ValueSerializer<>() {
            @Override
            public void serialize(TrustDomain value, JsonGenerator gen, SerializationContext ctxt) {
                gen.writeString(value.name());
            }
        });
        addSerializer(TrustAnchor.class, new ValueSerializer<>() {
            @Override
            public void serialize(TrustAnchor value, JsonGenerator gen, SerializationContext ctxt) {
                ctxt.writeValue(gen, anchorView(value));
            }
        });
    }

    public static Map<String, Object> anchorView(TrustAnchor a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.id());
        m.put("domain", a.domain().name());
        m.put("frameworkId", a.frameworkId());
        m.put("entityId", a.entityId());
        m.put("status", a.status());
        m.put("constraints", io.vctrust.trust.server.service.SnapshotService.publicConstraints(a));
        m.put("certificate", CertificateSummary.of(a.certificate()));
        if (a.provenance() != null) {
            m.put("source", a.provenance().sourceId());
            m.put("sourceType", a.provenance().sourceType());
        }
        return m;
    }
}
