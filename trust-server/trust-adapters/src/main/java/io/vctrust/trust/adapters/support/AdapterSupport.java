package io.vctrust.trust.adapters.support;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.x509.Certificates;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Helpers shared by adapters: document parsing and flexible certificate inputs. */
public final class AdapterSupport {

    private static final ObjectMapper YAML = YAMLMapper.builder().build();

    private AdapterSupport() {
    }

    /** Parses a YAML or JSON document into a map (JSON is a YAML subset). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseYamlOrJson(byte[] data) {
        Object v = YAML.readValue(data, Object.class);
        if (!(v instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException("Document root must be an object");
        }
        return (Map<String, Object>) m;
    }

    /**
     * Resolves certificates from any of: an inline PEM / base64 string ({@code certificate}), a list of those
     * ({@code certificates}), or a location ({@code certificateLocation}) optionally holding JSON from which
     * {@code certificateJsonField} is read (e.g. {@code base64}).
     */
    public static List<X509Certificate> certificates(Map<String, Object> spec, ResourceLoader loader) throws IOException {
        List<X509Certificate> out = new ArrayList<>();
        Object inline = spec.get("certificate");
        if (inline instanceof String s) {
            out.addAll(parseCertificateText(s));
        }
        if (spec.get("certificates") instanceof List<?> list) {
            for (Object o : list) {
                out.addAll(parseCertificateText(String.valueOf(o)));
            }
        }
        String location = Json.string(spec, "certificateLocation");
        if (location != null) {
            byte[] data = loader.load(location);
            String field = Json.string(spec, "certificateJsonField");
            if (field != null) {
                Map<String, Object> json = Json.parseObject(data);
                Object v = json.get(field);
                if (v == null) {
                    throw new IOException("Field '" + field + "' not found in " + location);
                }
                out.addAll(parseCertificateText(String.valueOf(v)));
            } else {
                out.addAll(Certificates.fromPemBundle(data));
            }
        }
        return out;
    }

    public static List<X509Certificate> parseCertificateText(String text) {
        String t = text.trim();
        if (t.contains("-----BEGIN")) {
            return Certificates.fromPemBundle(t.getBytes(StandardCharsets.US_ASCII));
        }
        return List.of(Certificates.fromBase64(t.replaceAll("\\s", "")));
    }

    public static Instant instant(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Instant i) {
            return i;
        }
        if (v instanceof java.util.Date d) {
            return d.toInstant();
        }
        if (v instanceof Number n) {
            return Instant.ofEpochSecond(n.longValue());
        }
        String s = String.valueOf(v).trim();
        if (s.length() == 10) {
            return LocalDate.parse(s).atStartOfDay().toInstant(ZoneOffset.UTC);
        }
        return Instant.parse(s);
    }
}
