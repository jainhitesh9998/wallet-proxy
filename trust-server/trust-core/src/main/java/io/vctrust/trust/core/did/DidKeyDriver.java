package io.vctrust.trust.core.did;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.util.Multibase;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * did:key (W3C CCG did:key v0.7). Supports Ed25519, X25519, P-256, P-384, secp256k1 and EBSI's
 * {@code jwk_jcs-pub}. Verification methods use {@code Multikey}; EC keys additionally carry no JWK unless
 * {@code jwk} format is requested.
 */
public final class DidKeyDriver implements DidMethodDriver {

    public enum KeyFormat { MULTIKEY, JSON_WEB_KEY }

    static final long ED25519 = 0xed;
    static final long X25519 = 0xec;
    static final long P256 = 0x1200;
    static final long P384 = 0x1201;
    static final long SECP256K1 = 0xe7;
    static final long JWK_JCS = 0xeb51;

    private final KeyFormat format;

    public DidKeyDriver() {
        this(KeyFormat.MULTIKEY);
    }

    public DidKeyDriver(KeyFormat format) {
        this.format = format;
    }

    @Override
    public Set<String> methods() {
        return Set.of("key");
    }

    @Override
    public DidResolutionResult resolve(Did did) {
        String mb = did.methodSpecificId();
        String id = did.did();
        if (!mb.startsWith("z")) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, "did:key must be base58btc multibase");
        }
        Multibase.Prefixed p;
        try {
            p = Multibase.readVarint(Multibase.decode(mb));
        } catch (IllegalArgumentException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, e.getMessage());
        }
        String vmId = id + "#" + mb;
        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("id", vmId);
        vm.put("controller", id);
        boolean signing = true;
        boolean keyAgreement = false;
        try {
            if (p.codec() == JWK_JCS) {
                Map<String, Object> jwk = Json.parseObject(p.payload());
                vm.put("id", id + "#0");
                vm.put("type", "JsonWebKey2020");
                vm.put("publicKeyJwk", jwk);
                return DidResolutionResult.success(DidDocuments.singleKey(id, List.of("https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/suites/jws-2020/v1"), vm, true, false), Map.of(), Map.of());
            }
            int expectedLen = switch ((int) p.codec()) {
                case (int) ED25519, (int) X25519 -> 32;
                case (int) P256, (int) SECP256K1 -> 33;
                case (int) P384 -> 49;
                default -> -1;
            };
            if (expectedLen < 0) {
                return DidResolutionResult.error(DidResolutionResult.INVALID_DID,
                        "Unsupported did:key multicodec 0x" + Long.toHexString(p.codec()));
            }
            if (p.payload().length != expectedLen) {
                return DidResolutionResult.error(DidResolutionResult.INVALID_DID,
                        "Unexpected key length " + p.payload().length + " for codec 0x" + Long.toHexString(p.codec()));
            }
            if (p.codec() == X25519) {
                signing = false;
                keyAgreement = true;
            }
            if (format == KeyFormat.JSON_WEB_KEY && p.codec() != X25519) {
                vm.put("type", "JsonWebKey2020");
                vm.put("publicKeyJwk", toJwk(p.codec(), p.payload()));
            } else {
                vm.put("type", "Multikey");
                vm.put("publicKeyMultibase", mb);
            }
        } catch (RuntimeException e) {
            return DidResolutionResult.error(DidResolutionResult.INVALID_DID, "Invalid public key: " + e.getMessage());
        }
        return DidResolutionResult.success(DidDocuments.singleKey(id, List.of("https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"), vm, signing, keyAgreement), Map.of(), Map.of());
    }

    /** Converts a multicodec public key to a JWK (decompressing EC points). */
    public static Map<String, Object> toJwk(long codec, byte[] key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        if (codec == ED25519) {
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", Base64Url.encode(key));
            return jwk;
        }
        String curve = codec == P256 ? "secp256r1" : codec == P384 ? "secp384r1" : "secp256k1";
        String crv = codec == P256 ? "P-256" : codec == P384 ? "P-384" : "secp256k1";
        X9ECParameters params = CustomNamedCurves.getByName(curve);
        ECPoint point = params.getCurve().decodePoint(key).normalize();
        int size = (params.getCurve().getFieldSize() + 7) / 8;
        jwk.put("kty", "EC");
        jwk.put("crv", crv);
        jwk.put("x", Base64Url.encode(fixed(point.getAffineXCoord().toBigInteger(), size)));
        jwk.put("y", Base64Url.encode(fixed(point.getAffineYCoord().toBigInteger(), size)));
        return jwk;
    }

    private static byte[] fixed(BigInteger v, int size) {
        byte[] b = v.toByteArray();
        if (b.length == size) {
            return b;
        }
        byte[] out = new byte[size];
        if (b.length > size) {
            System.arraycopy(b, b.length - size, out, 0, size);
        } else {
            System.arraycopy(b, 0, out, size - b.length, b.length);
        }
        return out;
    }

    static byte[] strip(byte[] b) {
        return b.length > 0 && b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }
}
