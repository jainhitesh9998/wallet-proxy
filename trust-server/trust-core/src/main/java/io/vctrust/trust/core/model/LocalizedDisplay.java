package io.vctrust.trust.core.model;

/** Human-readable display information for an entity, per locale (mirrors OpenID4VCI {@code display}). */
public record LocalizedDisplay(String locale, String name, String description, String logoUri) {

    public static LocalizedDisplay of(String locale, String name) {
        return new LocalizedDisplay(locale, name, null, null);
    }
}
