package io.vctrust.trust.core.did;

import java.util.Set;

/** Resolves DIDs of one or more methods. Drivers must not throw for expected failures; return an error result. */
public interface DidMethodDriver {

    /** Methods handled, without the {@code did:} prefix. {@code "*"} means any method (used by delegating drivers). */
    Set<String> methods();

    DidResolutionResult resolve(Did did);
}
