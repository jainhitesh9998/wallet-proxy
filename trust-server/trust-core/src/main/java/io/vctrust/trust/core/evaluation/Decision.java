package io.vctrust.trust.core.evaluation;

/**
 * Three-valued trust outcome. {@link #UNKNOWN} means "no applicable trust information", which clients must
 * not treat as trusted; {@link #NOT_TRUSTED} means trust information exists and contradicts the subject.
 */
public enum Decision { TRUSTED, NOT_TRUSTED, UNKNOWN }
