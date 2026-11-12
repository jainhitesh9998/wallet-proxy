package io.vctrust.trust.adapters.support;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.x509.Certificates;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Helpers shared by adapters: document parsing, flexible certificate inputs, and the location a source publishes. */
public final class AdapterSupport {

    /** Source property: the URI under which a list is publicly known, for a source that loads a local copy of it. */
    public static final String PUBLIC_URI = "publicUri";

    private static final ObjectMapper YAML = YAMLMapper.builder().build();

    private AdapterSupport() {
    }

    /**
     * What a source publishes as the location of its list: {@code Provenance.sourceUri}, and the {@code trustedListUri}
     * of its anchors and entities. Clients receive it, and match a DCQL {@code trusted_authorities} entry of type
     * {@code etsi_tl} against it.
     *
     * <p>The source's {@code publicUri} when it has one; otherwise the location itself when it is a web location; and
     * otherwise nothing (null). A file or classpath resource of the service's own host is never published: it would
     * tell every client where the service keeps its files, and means nothing to them.
     *
     * @param location where the source loads the list from
     */
    public static String publishedLocation(SourceDefinition def, String location) {
        String publicUri = publicUri(def);
        return publicUri != null ? publicUri : publishedLocation(location);
    }

    /**
     * A list's own location as it is published, for a list no {@code publicUri} speaks for (also one a list of lists
     * points to): a web location, or nothing (null).
     *
     * <p>A web location is published without user information, query and fragment: that is where a credential for
     * fetching a list is put ({@code https://user:secret@host/list}, {@code ?token=...}), and what is published goes
     * to every client. A location without them is published exactly as written. One that cannot be read as a URL is
     * not published.
     */
    public static String publishedLocation(String location) {
        if (!ResourceLoader.isRemote(location)) {
            return null;
        }
        try {
            URI uri = new URI(location);
            if (uri.getRawUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null) {
                return location;
            }
            String authority = uri.getRawAuthority();
            if (authority == null) {
                return null;
            }
            return uri.getScheme() + "://" + authority.substring(authority.lastIndexOf('@') + 1)
                    + (uri.getRawPath() == null ? "" : uri.getRawPath());
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /**
     * The source's {@code publicUri}, null when it has none. A value that is not an http(s) URL with a host is a
     * configuration error: an adapter that publishes its location calls this when the source is created, so that the
     * service does not start with it.
     */
    public static String publicUri(SourceDefinition def) {
        Object value = def.properties().get(PUBLIC_URI);
        if (value == null) {
            return null;
        }
        String uri = String.valueOf(value);
        if (!isWebUrl(uri)) {
            throw new IllegalArgumentException("Source '" + def.id() + "' (" + def.type() + "): " + PUBLIC_URI
                    + " must be an http(s) URL, not " + Json.write(uri));
        }
        return uri;
    }

    private static boolean isWebUrl(String uri) {
        if (!ResourceLoader.isRemote(uri)) {
            return false;
        }
        try {
            String host = new URI(uri).getHost();
            return host != null && !host.isEmpty();
        } catch (URISyntaxException e) {
            return false;
        }
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
