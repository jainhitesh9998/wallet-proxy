package io.vctrust.trust.core.did;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * W3C DID Resolution result: {@code didDocument}, {@code didResolutionMetadata}, {@code didDocumentMetadata}.
 * Documents are kept as generic JSON maps so that any DID method's extensions survive the proxy unchanged.
 *
 * <p>{@code upstreamFailed} is what the resolution metadata cannot say: the resolution failed because no usable answer
 * could be had from where the DID lives (its host, its registry, a universal resolver), which was unreachable, timed
 * out, answered with an HTTP error other than "not there", or with something that is not the DID's document. Such a
 * failure says nothing about the DID. Only the code that asked knows this, so it is set there ({@link #upstreamError});
 * an answer about the DID (not found, invalid, method not supported) and a failure of this code itself leave it false.
 * It is not part of the JSON form.
 */
public record DidResolutionResult(Map<String, Object> didDocument, Map<String, Object> didResolutionMetadata,
                                  Map<String, Object> didDocumentMetadata, boolean upstreamFailed) {

    public static final String CONTEXT = "https://w3id.org/did-resolution/v1";

    /** DID Resolution error codes (W3C DID Resolution, RFC 9457 problem types under {@link #ERROR_TYPE_BASE}). */
    public static final String INVALID_DID = "INVALID_DID";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String METHOD_NOT_SUPPORTED = "METHOD_NOT_SUPPORTED";
    public static final String REPRESENTATION_NOT_SUPPORTED = "REPRESENTATION_NOT_SUPPORTED";
    public static final String INTERNAL_ERROR = "INTERNAL_ERROR";
    public static final String INVALID_DID_DOCUMENT = "INVALID_DID_DOCUMENT";
    public static final String ERROR_TYPE_BASE = "https://www.w3.org/ns/did#";

    private static final Map<String, String> LEGACY = Map.of(
            "invalidDid", INVALID_DID, "notFound", NOT_FOUND, "methodNotSupported", METHOD_NOT_SUPPORTED,
            "representationNotSupported", REPRESENTATION_NOT_SUPPORTED, "internalError", INTERNAL_ERROR,
            "invalidDidDocument", INVALID_DID_DOCUMENT);

    public DidResolutionResult {
        didResolutionMetadata = didResolutionMetadata == null ? Map.of() : didResolutionMetadata;
        didDocumentMetadata = didDocumentMetadata == null ? Map.of() : didDocumentMetadata;
    }

    public DidResolutionResult(Map<String, Object> didDocument, Map<String, Object> didResolutionMetadata,
                               Map<String, Object> didDocumentMetadata) {
        this(didDocument, didResolutionMetadata, didDocumentMetadata, false);
    }

    public static DidResolutionResult success(Map<String, Object> doc, Map<String, Object> resolutionMetadata,
                                              Map<String, Object> documentMetadata) {
        Map<String, Object> rm = new LinkedHashMap<>();
        rm.put("contentType", "application/did+ld+json");
        rm.putAll(resolutionMetadata == null ? Map.of() : resolutionMetadata);
        return new DidResolutionResult(doc, rm, documentMetadata);
    }

    public static DidResolutionResult error(String code, String message) {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("type", ERROR_TYPE_BASE + code);
        problem.put("title", code);
        if (message != null) {
            problem.put("detail", message);
        }
        Map<String, Object> rm = new LinkedHashMap<>();
        rm.put("error", problem);
        return new DidResolutionResult(null, rm, Map.of());
    }

    /**
     * An error because where the DID lives gave no usable answer ({@link #upstreamFailed}): {@code code} is what the
     * resolution metadata reports, {@link #INTERNAL_ERROR} for no answer, {@link #INVALID_DID_DOCUMENT} for one that is
     * not the DID's document.
     */
    public static DidResolutionResult upstreamError(String code, String message) {
        DidResolutionResult r = error(code, message);
        return new DidResolutionResult(null, r.didResolutionMetadata(), r.didDocumentMetadata(), true);
    }

    /** The error code (e.g. {@code NOT_FOUND}); accepts both RFC 9457 objects and legacy camelCase strings. */
    public Optional<String> error() {
        return Optional.ofNullable(normalizeError(didResolutionMetadata.get("error")));
    }

    /** The error's {@code detail}, when it has one. */
    public Optional<String> errorDetail() {
        return didResolutionMetadata.get("error") instanceof Map<?, ?> m && m.get("detail") instanceof String d ? Optional.of(d) : Optional.empty();
    }

    public static String normalizeError(Object error) {
        if (error == null) {
            return null;
        }
        String code;
        if (error instanceof Map<?, ?> m) {
            Object type = m.get("type");
            code = type == null ? String.valueOf(m.get("title")) : String.valueOf(type);
        } else {
            code = String.valueOf(error);
        }
        if (code.startsWith(ERROR_TYPE_BASE)) {
            code = code.substring(ERROR_TYPE_BASE.length());
        }
        return LEGACY.getOrDefault(code, code);
    }

    /** HTTP status for an error code per the DID Resolution HTTP binding. */
    public static int httpStatus(String code) {
        if (code == null) {
            return 200;
        }
        return switch (code) {
            case INVALID_DID, "INVALID_DID_URL", "INVALID_OPTIONS" -> 400;
            case NOT_FOUND -> 404;
            case REPRESENTATION_NOT_SUPPORTED -> 406;
            case METHOD_NOT_SUPPORTED, "FEATURE_NOT_SUPPORTED" -> 501;
            default -> 500;
        };
    }

    public boolean isSuccess() {
        return didDocument != null && error().isEmpty();
    }

    /** Full result object including {@code @context}, ready to serialize. */
    public Map<String, Object> toJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("@context", CONTEXT);
        out.put("didDocument", didDocument);
        out.put("didResolutionMetadata", didResolutionMetadata);
        out.put("didDocumentMetadata", didDocumentMetadata);
        return out;
    }

    public DidResolutionResult withResolutionMetadata(String key, Object value) {
        Map<String, Object> rm = new LinkedHashMap<>(didResolutionMetadata);
        rm.put(key, value);
        return new DidResolutionResult(didDocument, rm, didDocumentMetadata, upstreamFailed);
    }

    /**
     * Dereferences a verification method by DID URL or relative fragment ({@code #key-1}) and returns it,
     * searching {@code verificationMethod} and embedded methods in verification relationships.
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> verificationMethod(String didUrl) {
        if (didDocument == null) {
            return Optional.empty();
        }
        String docId = (String) didDocument.get("id");
        String target = absolute(docId, didUrl);
        for (Map<String, Object> vm : allVerificationMethods()) {
            if (Objects.equals(absolute(docId, (String) vm.get("id")), target)) {
                return Optional.of(vm);
            }
        }
        return Optional.empty();
    }

    /** True if the verification method is referenced (or embedded) in the given relationship. */
    @SuppressWarnings("unchecked")
    public boolean hasRelationship(String relationship, String didUrl) {
        if (didDocument == null) {
            return false;
        }
        String docId = (String) didDocument.get("id");
        String target = absolute(docId, didUrl);
        Object rel = didDocument.get(relationship);
        if (!(rel instanceof List<?> list)) {
            return false;
        }
        for (Object entry : list) {
            String ref = entry instanceof String s ? s
                    : entry instanceof Map<?, ?> m ? (String) ((Map<String, Object>) m).get("id") : null;
            if (ref != null && Objects.equals(absolute(docId, ref), target)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> allVerificationMethods() {
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        if (didDocument == null) {
            return out;
        }
        if (didDocument.get("verificationMethod") instanceof List<?> vms) {
            vms.stream().filter(Map.class::isInstance).forEach(v -> out.add((Map<String, Object>) v));
        }
        for (String rel : List.of("authentication", "assertionMethod", "keyAgreement", "capabilityInvocation",
                "capabilityDelegation")) {
            if (didDocument.get(rel) instanceof List<?> l) {
                l.stream().filter(Map.class::isInstance).forEach(v -> out.add((Map<String, Object>) v));
            }
        }
        return out;
    }

    static String absolute(String docId, String ref) {
        if (ref == null) {
            return null;
        }
        return ref.startsWith("#") && docId != null ? docId + ref : ref;
    }
}
