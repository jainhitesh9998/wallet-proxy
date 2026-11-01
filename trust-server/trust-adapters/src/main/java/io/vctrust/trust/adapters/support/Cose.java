package io.vctrust.trust.adapters.support;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

/** Minimal COSE_Sign1 verification (RFC 9052 §4.4) for list signatures. */
public final class Cose {

    private Cose() {
    }

    /** Verifies a COSE_Sign1 signature over an attached payload with no external AAD. */
    public static boolean verifySign1(int alg, byte[] protectedHeader, byte[] payload, byte[] signature, PublicKey key) {
        try {
            String jca = switch (alg) {
                case -7, -9 -> "SHA256withECDSAinP1363Format";
                case -35, -51 -> "SHA384withECDSAinP1363Format";
                case -36, -52 -> "SHA512withECDSAinP1363Format";
                case -8, -19 -> "Ed25519";
                default -> throw new IllegalArgumentException("Unsupported COSE alg " + alg);
            };
            Signature s = Signature.getInstance(jca);
            s.initVerify(key);
            s.update(sigStructure(protectedHeader, payload));
            return s.verify(signature);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
    }

    /** {@code ["Signature1", protected, h'', payload]} in deterministic CBOR. */
    public static byte[] sigStructure(byte[] protectedHeader, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x84);
        byte[] ctx = "Signature1".getBytes(StandardCharsets.US_ASCII);
        head(out, 3, ctx.length);
        out.writeBytes(ctx);
        head(out, 2, protectedHeader.length);
        out.writeBytes(protectedHeader);
        head(out, 2, 0);
        head(out, 2, payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    static void head(ByteArrayOutputStream out, int major, long len) {
        int mt = major << 5;
        if (len < 24) {
            out.write(mt | (int) len);
        } else if (len < 0x100) {
            out.write(mt | 24);
            out.write((int) len);
        } else if (len < 0x10000) {
            out.write(mt | 25);
            out.write((int) (len >> 8));
            out.write((int) len);
        } else {
            out.write(mt | 26);
            for (int s = 24; s >= 0; s -= 8) {
                out.write((int) (len >> s));
            }
        }
    }
}
