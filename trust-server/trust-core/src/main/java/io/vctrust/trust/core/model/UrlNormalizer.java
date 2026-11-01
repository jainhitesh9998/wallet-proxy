package io.vctrust.trust.core.model;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The URL identifier key both sides index by: an http(s) URL as the WHATWG URL Standard parses it, which is what the
 * client compares with (browsers, Node, Expo's URL on React Native), reduced to scheme, host, port, path and query.
 * Lower-case scheme and host (IDN hosts in punycode, IPv4 and IPv6 hosts in canonical form), no userinfo, no default
 * port, dot segments resolved, characters outside the path / query sets percent-encoded, one trailing slash stripped,
 * no fragment and no empty query. Path case is preserved (paths are case sensitive). Other schemes and URLs the parser
 * rejects are returned unchanged.
 *
 * <p>Domains map as Expo's parser does on the device (UTS #46 nontransitional, approximated: default ignorables
 * removed, NFKC, lower case, punycode); the full UTS #46 tables only matter for scripts no issuer URL uses. The same
 * vectors run against both parsers: test-ecosystem/vectors/url-identifiers.json. One known difference: Expo's parser
 * accepts a leading zero in an IPv6 literal's embedded IPv4 part ({@code [::01.2.3.4]}), which the standard rejects.
 */
final class UrlNormalizer {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();
    /** Path percent-encode set beyond C0 controls and non-ASCII. */
    private static final String PATH_SET = " \"#<>?^`{}";
    /** Special-query percent-encode set beyond C0 controls and non-ASCII. */
    private static final String QUERY_SET = " \"#<>'";
    private static final String FORBIDDEN_DOMAIN = " #%/:<>?@[\\]^|";
    /** Default_Ignorable_Code_Point (Unicode 15), removed from domains; ZWNJ and ZWJ are kept. */
    private static final int[] IGNORABLE = {0xAD, 0xAD, 0x34F, 0x34F, 0x61C, 0x61C, 0x115F, 0x1160, 0x17B4, 0x17B5,
            0x180B, 0x180F, 0x200B, 0x200B, 0x200E, 0x200F, 0x202A, 0x202E, 0x2060, 0x206F, 0x3164, 0x3164, 0xFE00, 0xFE0F,
            0xFEFF, 0xFEFF, 0xFFA0, 0xFFA0, 0xFFF0, 0xFFF8, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0xE0000, 0xE0FFF};
    /** UTS #46 mappings case folding misses, as Expo's parser applies them (sigma variants are mapped separately). */
    private static final int[] SPECIAL_FROM = {7296, 7297, 7298, 7299, 7300, 7301, 7302, 7303, 7304, 42958, 42962, 42964, 42993};
    private static final String[] SPECIAL_TO = {"в", "д", "о", "с", "т", "т", "ъ", "ѣ", "ꙋ", "꟏", "ꟓ", "ꟕ", "s"};

    private UrlNormalizer() {
    }

    /** An http(s) URL as parsed: scheme, host (canonical), port (-1 for the default) and what follows the authority. */
    private record Url(String scheme, String host, int port, String rest) {
    }

    static String normalize(String value) {
        Url u = parse(value);
        if (u == null) {
            return value;
        }
        String rest = u.rest();
        int hash = rest.indexOf('#');
        String beforeHash = hash < 0 ? rest : rest.substring(0, hash);
        int question = beforeHash.indexOf('?');
        String pathText = question < 0 ? beforeHash : beforeHash.substring(0, question);
        String query = question < 0 ? "" : beforeHash.substring(question + 1);

        StringBuilder out = new StringBuilder(u.scheme()).append("://").append(u.host());
        if (u.port() != -1) {
            out.append(':').append(u.port());
        }
        String path = path(pathText.isEmpty() ? "" : pathText.substring(1));
        out.append(path.endsWith("/") ? path.substring(0, path.length() - 1) : path);
        if (!query.isEmpty()) {
            out.append('?').append(encode(query, QUERY_SET));
        }
        return out.toString();
    }

    /** The host of an http(s) URL as the WHATWG parser reads it (WHATWG {@code hostname}); null when it rejects the URL. */
    static String hostOf(String value) {
        Url u = parse(value);
        return u == null ? null : u.host();
    }

    private static Url parse(String value) {
        String s = withoutLoneSurrogates(value.trim()).replaceAll("[\t\n\r]", "");
        int colon = s.indexOf(':');
        if (colon <= 0) {
            return null;
        }
        String scheme = s.substring(0, colon).toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            return null;
        }
        // Special schemes: any run of slashes or backslashes precedes the authority.
        int start = colon + 1;
        while (start < s.length() && (s.charAt(start) == '/' || s.charAt(start) == '\\')) {
            start++;
        }
        int end = start;
        while (end < s.length() && "/\\?#".indexOf(s.charAt(end)) < 0) {
            end++;
        }
        String authority = s.substring(start, end);
        String hostPort = authority.substring(authority.lastIndexOf('@') + 1);
        int portColon = -1;
        boolean bracket = false;
        for (int i = 0; i < hostPort.length() && portColon < 0; i++) {
            char c = hostPort.charAt(i);
            if (c == '[') {
                bracket = true;
            } else if (c == ']') {
                bracket = false;
            } else if (c == ':' && !bracket) {
                portColon = i;
            }
        }
        String hostText = portColon < 0 ? hostPort : hostPort.substring(0, portColon);
        String portText = portColon < 0 ? "" : hostPort.substring(portColon + 1);
        if (hostText.isEmpty()) {
            return null;
        }
        int port = -1;
        if (!portText.isEmpty()) {
            if (!portText.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return null;
            }
            String digits = portText.replaceFirst("^0+(?=.)", "");
            if (digits.length() > 5 || (port = Integer.parseInt(digits)) > 65535) {
                return null;
            }
            if (port == (scheme.equals("https") ? 443 : 80)) {
                port = -1;
            }
        }
        String host = host(hostText);
        return host == null ? null : new Url(scheme, host, port, s.substring(end));
    }

    /** Path segments split on '/' and '\', percent-encoded, with "." and ".." (also as %2e) resolved. */
    private static String path(String text) {
        String[] parts = text.split("[/\\\\]", -1);
        List<String> segments = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) {
            boolean last = i == parts.length - 1;
            String segment = encode(parts[i], PATH_SET);
            String lower = segment.toLowerCase(Locale.ROOT);
            if (lower.equals("..") || lower.equals(".%2e") || lower.equals("%2e.") || lower.equals("%2e%2e")) {
                if (!segments.isEmpty()) {
                    segments.removeLast();
                }
                if (last) {
                    segments.add("");
                }
            } else if (lower.equals(".") || lower.equals("%2e")) {
                if (last) {
                    segments.add("");
                }
            } else {
                segments.add(segment);
            }
        }
        return "/" + String.join("/", segments);
    }

    private static String host(String text) {
        if (text.startsWith("[")) {
            return text.endsWith("]") ? ipv6(text.substring(1, text.length() - 1)) : null;
        }
        String ascii = domainToAscii(percentDecode(text));
        if (ascii == null || ascii.chars().anyMatch(c -> c < 0x20 || c == 0x7F || FORBIDDEN_DOMAIN.indexOf(c) >= 0)) {
            return null;
        }
        return endsInANumber(ascii) ? ipv4(ascii) : ascii;
    }

    private static String domainToAscii(String domain) {
        if (domain.chars().allMatch(c -> c < 0x80)) {
            return domain.isEmpty() ? null : domain.toLowerCase(Locale.ROOT);
        }
        StringBuilder mapped = new StringBuilder();
        for (int cp : domain.codePoints().toArray()) {
            int type = Character.getType(cp);
            if (type == Character.UNASSIGNED || type == Character.PRIVATE_USE || type == Character.SURROGATE
                    || (cp & 0xFFFE) == 0xFFFE || (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp >= 0x80 && cp <= 0x9F) || cp == 0xFFFD) {
                return null;
            }
            // Characters that fold into a dot (U+2024, U+2488 ...) are disallowed, except the four full stops.
            if (cp != '.' && cp != 0x3002 && cp != 0xFF0E && cp != 0xFF61
                    && Normalizer.normalize(Character.toString(cp), Normalizer.Form.NFKC).indexOf('.') >= 0) {
                return null;
            }
            if (cp != 0x200C && cp != 0x200D && inRanges(IGNORABLE, cp)) {
                continue;
            }
            mapped.append(mapCodePoint(cp));
        }
        String folded = Normalizer.normalize(mapped, Normalizer.Form.NFKC).replaceAll("[。．｡]", ".")
                .toLowerCase(Locale.ROOT);
        String[] labels = folded.split("\\.", -1);
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if (label.isEmpty() || label.chars().allMatch(c -> c < 0x80)) {
                continue;
            }
            int first = Character.getType(label.codePointAt(0));
            if (first == Character.NON_SPACING_MARK || first == Character.ENCLOSING_MARK
                    || first == Character.COMBINING_SPACING_MARK || label.startsWith("xn--") || !validJoiners(label)) {
                return null;
            }
            labels[i] = "xn--" + punycode(label);
        }
        String out = String.join(".", labels);
        return out.isEmpty() ? null : out;
    }

    /** IDNA CheckJoiners, approximated: ZWNJ and ZWJ only right after a virama. */
    private static boolean validJoiners(String label) {
        int[] cps = label.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            if ((cps[i] == 0x200C || cps[i] == 0x200D)
                    && (i == 0 || Character.getName(cps[i - 1]) == null || !Character.getName(cps[i - 1]).contains("VIRAMA"))) {
                return false;
            }
        }
        return true;
    }

    private static String mapCodePoint(int cp) {
        if (cp == 931 || cp == 1010 || cp == 120531 || cp == 120589 || cp == 120647 || cp == 120705 || cp == 120763) {
            return "σ";
        }
        if (cp >= 5112 && cp <= 5117) {
            return Character.toString(cp - 8);
        }
        if (cp >= 43888 && cp <= 43967) {
            return Character.toString(cp - 38864);
        }
        if (cp >= 93856 && cp <= 93880) {
            return Character.toString(cp + 27);
        }
        if (cp == 837 || cp == 890 || (cp >= 8064 && cp <= 8111) || (cp >= 8114 && cp <= 8188)) {
            String nfd = Normalizer.normalize(Character.toString(cp), Normalizer.Form.NFD).replace("ͅ", "ι");
            return Normalizer.normalize(nfd, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        }
        for (int i = 0; i < SPECIAL_FROM.length; i++) {
            if (SPECIAL_FROM[i] == cp) {
                return SPECIAL_TO[i];
            }
        }
        return Character.toString(cp);
    }

    /** RFC 3492 encoding of one label (without the xn-- prefix). */
    static String punycode(String label) {
        int[] cps = label.codePoints().toArray();
        StringBuilder out = new StringBuilder();
        for (int cp : cps) {
            if (cp < 0x80) {
                out.append((char) cp);
            }
        }
        int basic = out.length();
        int handled = basic;
        if (basic > 0) {
            out.append('-');
        }
        int n = 128;
        int delta = 0;
        int bias = 72;
        while (handled < cps.length) {
            int m = Integer.MAX_VALUE;
            for (int cp : cps) {
                if (cp >= n && cp < m) {
                    m = cp;
                }
            }
            delta += (m - n) * (handled + 1);
            n = m;
            for (int cp : cps) {
                if (cp < n) {
                    delta++;
                } else if (cp == n) {
                    int q = delta;
                    for (int k = 36; ; k += 36) {
                        int t = k <= bias ? 1 : Math.min(k - bias, 26);
                        if (q < t) {
                            break;
                        }
                        out.append(digit(t + (q - t) % (36 - t)));
                        q = (q - t) / (36 - t);
                    }
                    out.append(digit(q));
                    bias = adapt(delta, handled + 1, handled == basic);
                    delta = 0;
                    handled++;
                }
            }
            delta++;
            n++;
        }
        return out.toString();
    }

    private static int adapt(int delta, int points, boolean first) {
        delta = first ? delta / 700 : delta / 2;
        delta += delta / points;
        int k = 0;
        while (delta > 455) {
            delta /= 35;
            k += 36;
        }
        return k + 36 * delta / (delta + 38);
    }

    private static char digit(int d) {
        return (char) (d < 26 ? 'a' + d : '0' + d - 26);
    }

    /** The WHATWG "ends in a number" check: such a host must parse as IPv4. */
    private static boolean endsInANumber(String host) {
        List<String> parts = new ArrayList<>(List.of(host.split("\\.", -1)));
        if (parts.getLast().isEmpty()) {
            if (parts.size() == 1) {
                return false;
            }
            parts.removeLast();
        }
        String last = parts.getLast();
        return (!last.isEmpty() && last.chars().allMatch(c -> c >= '0' && c <= '9')) || ipv4Number(last) >= 0;
    }

    private static String ipv4(String host) {
        List<String> parts = new ArrayList<>(List.of(host.split("\\.", -1)));
        if (parts.getLast().isEmpty() && parts.size() > 1) {
            parts.removeLast();
        }
        if (parts.size() > 4) {
            return null;
        }
        long[] numbers = new long[parts.size()];
        for (int i = 0; i < numbers.length; i++) {
            numbers[i] = ipv4Number(parts.get(i));
            if (numbers[i] < 0 || (i < numbers.length - 1 && numbers[i] > 255)) {
                return null;
            }
        }
        long address = numbers[numbers.length - 1];
        if (address >= 1L << (8 * (5 - numbers.length))) {
            return null;
        }
        for (int i = 0; i < numbers.length - 1; i++) {
            address += numbers[i] << (8 * (3 - i));
        }
        return (address >> 24 & 255) + "." + (address >> 16 & 255) + "." + (address >> 8 & 255) + "." + (address & 255);
    }

    /** One IPv4 part: decimal, 0x-hex or 0-octal; -1 when it is not a number. Large values are capped (they fail later). */
    private static long ipv4Number(String part) {
        if (part.isEmpty()) {
            return -1;
        }
        int radix = 10;
        if (part.length() >= 2 && (part.startsWith("0x") || part.startsWith("0X"))) {
            radix = 16;
            part = part.substring(2);
        } else if (part.length() >= 2 && part.charAt(0) == '0') {
            radix = 8;
            part = part.substring(1);
        }
        if (part.isEmpty()) {
            return 0;
        }
        final int r = radix;
        if (!part.chars().allMatch(c -> Character.digit(c, r) >= 0 && c < 0x80)) {
            return -1;
        }
        return new BigInteger(part, radix).min(BigInteger.ONE.shiftLeft(40)).longValue();
    }

    /** Canonical IPv6 text: lower-case hex, no leading zeros, the first longest run of two or more zero pieces as "::". */
    private static String ipv6(String text) {
        if (text.isEmpty() || !text.chars().allMatch(c -> Character.digit(c, 16) >= 0 && c < 0x80 || c == ':' || c == '.')) {
            return null;
        }
        if (text.indexOf('.') >= 0) {
            // An embedded IPv4 address: four decimal parts up to 255, no leading zeros (stricter than InetAddress).
            String[] parts = text.substring(text.lastIndexOf(':') + 1).split("\\.", -1);
            if (parts.length != 4) {
                return null;
            }
            for (String p : parts) {
                if (p.isEmpty() || p.length() > 3 || (p.length() > 1 && p.charAt(0) == '0')
                        || !p.chars().allMatch(c -> c >= '0' && c <= '9') || Integer.parseInt(p) > 255) {
                    return null;
                }
            }
        }
        byte[] b;
        try {
            b = InetAddress.getByName("[" + text + "]").getAddress(); // a literal: never a DNS lookup
        } catch (UnknownHostException e) {
            return null;
        }
        if (b.length == 4) { // Java returns IPv4-mapped addresses as IPv4
            byte[] mapped = new byte[16];
            mapped[10] = (byte) 0xFF;
            mapped[11] = (byte) 0xFF;
            System.arraycopy(b, 0, mapped, 12, 4);
            b = mapped;
        }
        int[] pieces = new int[8];
        for (int i = 0; i < 8; i++) {
            pieces[i] = (b[2 * i] & 255) << 8 | (b[2 * i + 1] & 255);
        }
        int compress = -1;
        int longest = 1;
        for (int i = 0; i < 8; ) {
            int j = i;
            while (j < 8 && pieces[j] == 0) {
                j++;
            }
            if (j - i > longest) {
                compress = i;
                longest = j - i;
            }
            i = Math.max(j, i + 1);
        }
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < 8; i++) {
            if (i == compress) {
                out.append(i == 0 ? "::" : ":");
                i += longest - 1;
                continue;
            }
            out.append(Integer.toHexString(pieces[i]));
            if (i < 7) {
                out.append(':');
            }
        }
        return out.append(']').toString();
    }

    private static String encode(String s, String set) {
        StringBuilder out = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if (c < 0x20 || c > 0x7E || set.indexOf(c) >= 0) {
                out.append('%').append(HEX[c >> 4]).append(HEX[c & 15]);
            } else {
                out.append((char) c);
            }
        }
        return out.toString();
    }

    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[in.length];
        int n = 0;
        for (int i = 0; i < in.length; i++) {
            if (in[i] == '%' && i + 2 < in.length && Character.digit(in[i + 1], 16) >= 0 && Character.digit(in[i + 2], 16) >= 0) {
                out[n++] = (byte) (Character.digit(in[i + 1], 16) << 4 | Character.digit(in[i + 2], 16));
                i += 2;
            } else {
                out[n++] = in[i];
            }
        }
        return new String(out, 0, n, StandardCharsets.UTF_8);
    }

    private static String withoutLoneSurrogates(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> out.appendCodePoint(Character.isSurrogate((char) cp) && cp <= 0xFFFF ? 0xFFFD : cp));
        return out.toString();
    }

    private static boolean inRanges(int[] ranges, int cp) {
        for (int i = 0; i < ranges.length; i += 2) {
            if (cp >= ranges[i] && cp <= ranges[i + 1]) {
                return true;
            }
        }
        return false;
    }
}
