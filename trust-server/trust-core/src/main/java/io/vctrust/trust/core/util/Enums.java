package io.vctrust.trust.core.util;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/** Reads enum constants from input, with an error that names the accepted values and nothing about the code. */
public final class Enums {

    private Enums() {
    }

    /**
     * @param what what the value is, for the error ("role", "identifier type")
     * @throws IllegalArgumentException when {@code value} names no constant; the message quotes at most 40 characters of it
     */
    public static <E extends Enum<E>> E parse(Class<E> type, String value, String what) {
        String name = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        for (E constant : type.getEnumConstants()) {
            if (constant.name().equals(name)) {
                return constant;
            }
        }
        String shown = value == null ? "null" : value.length() <= 40 ? value : value.substring(0, 40) + "…";
        throw new IllegalArgumentException("Unknown " + what + " '" + shown + "'; one of "
                + Arrays.stream(type.getEnumConstants()).map(Enum::name).collect(Collectors.joining(", ")));
    }
}
