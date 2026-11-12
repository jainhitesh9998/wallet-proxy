package io.vctrust.trust.core.did;

import java.util.Set;

/**
 * Resolves DIDs of one or more methods. Drivers must not throw for expected failures; return an error result, made
 * with {@link DidResolutionResult#upstreamError} when where the DID lives gave no usable answer, so that the failure is
 * not taken for an answer about the DID or for a failure of the service.
 */
public interface DidMethodDriver {

    /** Methods handled, without the {@code did:} prefix. {@code "*"} means any method (used by delegating drivers). */
    Set<String> methods();

    DidResolutionResult resolve(Did did);
}
