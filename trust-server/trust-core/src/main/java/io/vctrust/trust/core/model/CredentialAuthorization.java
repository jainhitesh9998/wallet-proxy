package io.vctrust.trust.core.model;

import java.util.Map;
import java.util.Objects;

/**
 * What an entity is authorized to issue (issuers) or request (verifiers).
 *
 * <p>{@code type} is format specific: an mdoc doctype, an SD-JWT VC {@code vct}, or a W3C VC type name.
 * A {@code null} format or type acts as a wildcard.
 */
public record CredentialAuthorization(String format, String type, Map<String, Object> constraints) {

    public CredentialAuthorization {
        constraints = constraints == null ? Map.of() : Map.copyOf(constraints);
    }

    public static CredentialAuthorization of(String format, String type) {
        return new CredentialAuthorization(format, type, Map.of());
    }

    /** True if this authorization covers the given format and type. Format aliases are honoured. */
    public boolean covers(String requestedFormat, String requestedType) {
        boolean formatOk = format == null || requestedFormat == null
                || CredentialFormats.sameFormat(format, requestedFormat);
        boolean typeOk = type == null || requestedType == null || Objects.equals(type, requestedType);
        return formatOk && typeOk;
    }
}
