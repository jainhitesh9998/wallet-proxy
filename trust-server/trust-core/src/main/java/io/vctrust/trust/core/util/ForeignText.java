package io.vctrust.trust.core.util;

/**
 * Text that did not come from the operator (what a list says, a location it names, a remote server's answer, an
 * identifier in a request), made fit to be written to a log line or a source's state. Every control, format, line
 * separator and paragraph separator character (Unicode categories Cc, Cf, Zl, Zp), and any half of a surrogate pair
 * that stands alone, is written as a backslash, {@code u} and four hexadecimal digits (as a Java or JSON string escapes
 * it); and the text is cut at {@link #MAX_LENGTH} characters, the cut marked with {@link #CUT}. A line break in a list
 * then cannot start a log line of its own, a right-to-left override cannot make one location read as another, and a
 * list cannot fill the log with one message.
 */
public final class ForeignText {

    /** The most characters of escaped text kept: plenty for a message. */
    public static final int MAX_LENGTH = 500;

    /** What follows text that was cut. */
    public static final String CUT = "…[cut]";

    private ForeignText() {
    }

    /** {@code text} escaped and cut as described above; null for null. */
    public static String escape(String text) {
        if (text == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(Math.min(text.length(), MAX_LENGTH) + CUT.length());
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            int n = Character.charCount(cp);
            String unit = escaped(cp) ? units(text, i, n) : text.substring(i, i + n);
            // An escape or a surrogate pair is kept whole or not at all.
            if (out.length() + unit.length() > MAX_LENGTH) {
                return out.append(CUT).toString();
            }
            out.append(unit);
            i += n;
        }
        return out.toString();
    }

    private static boolean escaped(int codePoint) {
        return switch (Character.getType(codePoint)) {
            case Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR, Character.SURROGATE -> true;
            default -> false;
        };
    }

    /** Each UTF-16 unit of {@code text[i, i + n)} as a backslash, {@code u} and four upper-case hexadecimal digits. */
    private static String units(String text, int i, int n) {
        StringBuilder b = new StringBuilder(6 * n);
        for (int j = i; j < i + n; j++) {
            b.append(String.format("\\u%04X", (int) text.charAt(j)));
        }
        return b.toString();
    }
}
