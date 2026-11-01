package io.vctrust.trust.core.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

/** Multibase (base58btc 'z' and base64url 'u') and unsigned-varint multicodec helpers. */
public final class Multibase {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    private Multibase() {
    }

    public static byte[] decode(String multibase) {
        if (multibase == null || multibase.isEmpty()) {
            throw new IllegalArgumentException("Empty multibase value");
        }
        char prefix = multibase.charAt(0);
        String body = multibase.substring(1);
        return switch (prefix) {
            case 'z' -> base58Decode(body);
            case 'u' -> Base64Url.decodeLenient(body);
            default -> throw new IllegalArgumentException("Unsupported multibase prefix '" + prefix + "'");
        };
    }

    public static String encodeBase58Btc(byte[] data) {
        return "z" + base58Encode(data);
    }

    public static byte[] base58Decode(String s) {
        BigInteger num = BigInteger.ZERO;
        for (char c : s.toCharArray()) {
            int digit = ALPHABET.indexOf(c);
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character '" + c + "'");
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = num.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') {
            zeros++;
        }
        if (num.signum() == 0) {
            return new byte[zeros];
        }
        byte[] out = new byte[zeros + bytes.length];
        System.arraycopy(bytes, 0, out, zeros, bytes.length);
        return out;
    }

    public static String base58Encode(byte[] data) {
        BigInteger num = new BigInteger(1, data);
        StringBuilder sb = new StringBuilder();
        while (num.signum() > 0) {
            BigInteger[] qr = num.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            num = qr[0];
        }
        for (byte b : data) {
            if (b != 0) {
                break;
            }
            sb.append('1');
        }
        return sb.reverse().toString();
    }

    /** Result of reading a multicodec varint prefix. */
    public record Prefixed(long codec, byte[] payload) {
    }

    public static Prefixed readVarint(byte[] data) {
        long value = 0;
        int shift = 0;
        int i = 0;
        while (i < data.length) {
            int b = data[i++] & 0xff;
            value |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) {
                return new Prefixed(value, Arrays.copyOfRange(data, i, data.length));
            }
            shift += 7;
            if (shift > 63) {
                break;
            }
        }
        throw new IllegalArgumentException("Invalid multicodec varint");
    }

    public static byte[] writeVarint(long codec, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long v = codec;
        while ((v & ~0x7fL) != 0) {
            out.write((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        out.write((int) v);
        out.writeBytes(payload);
        return out.toByteArray();
    }
}
