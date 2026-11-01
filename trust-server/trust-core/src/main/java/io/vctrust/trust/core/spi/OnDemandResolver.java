package io.vctrust.trust.core.spi;

import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustedEntity;

import java.util.Optional;

/**
 * Optional capability of a {@link TrustSource} whose registry is too large or too dynamic to enumerate
 * (OpenID Federation, EBSI TIR): resolves a single identifier when the pre-loaded index has no match.
 */
public interface OnDemandResolver {

    /** True if this resolver can possibly answer for the identifier (cheap check, no I/O). */
    boolean canResolve(Identifier identifier);

    Optional<TrustedEntity> resolve(Identifier identifier) throws TrustSourceException;
}
