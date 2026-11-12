package io.vctrust.trust.core.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ForeignTextTest {

    @Test
    void writesControlFormatAndSeparatorCharactersAsEscapes() {
        // Cc: line breaks, tab, NUL, DEL, NEL.
        assertThat(ForeignText.escape("a\nb\r\nc\td\0e\u007Ff\u0085")).isEqualTo("a\\u000Ab\\u000D\\u000Ac\\u0009d\\u0000e\\u007Ff\\u0085");
        // Cf: a right-to-left override, a zero-width space, a byte order mark, and a format character outside the BMP
        // (LANGUAGE TAG, U+E0001), written as its two UTF-16 units.
        assertThat(ForeignText.escape("https://evil.example/‮gpj.exe")).isEqualTo("https://evil.example/\\u202Egpj.exe");
        assertThat(ForeignText.escape("a​b﻿c" + new String(Character.toChars(0xE0001))))
                .isEqualTo("a\\u200Bb\\uFEFFc\\uDB40\\uDC01");
        // Zl and Zp.
        assertThat(ForeignText.escape("one two three")).isEqualTo("one\\u2028two\\u2029three");
        // Half of a surrogate pair standing alone.
        assertThat(ForeignText.escape("x\uD800y\uDC00")).isEqualTo("x\\uD800y\\uDC00");
    }

    @Test
    void leavesOtherTextAsItIs() {
        String text = "Müller, 東京, a no-break space, 😀, \\u000A and \"quotes\"";
        assertThat(ForeignText.escape(text)).isEqualTo(text);
        assertThat(ForeignText.escape("")).isEmpty();
        assertThat(ForeignText.escape(null)).isNull();
    }

    @Test
    void cutsAtFiveHundredCharactersAndSaysSo() {
        String exactly = "a".repeat(ForeignText.MAX_LENGTH);
        assertThat(ForeignText.escape(exactly)).isEqualTo(exactly);
        assertThat(ForeignText.escape(exactly + "b")).isEqualTo(exactly + "…[cut]");
        assertThat(ForeignText.escape("x".repeat(10_000))).hasSize(ForeignText.MAX_LENGTH + ForeignText.CUT.length()).endsWith(ForeignText.CUT);
        // What is counted is the escaped text; an escape is kept whole or not at all.
        assertThat(ForeignText.escape("a".repeat(497) + "\n")).isEqualTo("a".repeat(497) + "…[cut]");
        assertThat(ForeignText.escape("a".repeat(494) + "\n")).isEqualTo("a".repeat(494) + "\\u000A");
        assertThat(ForeignText.escape("\n".repeat(200))).isEqualTo("\\u000A".repeat(83) + "…[cut]");
        // So is a surrogate pair.
        assertThat(ForeignText.escape("a".repeat(499) + "😀")).isEqualTo("a".repeat(499) + "…[cut]");
    }
}
