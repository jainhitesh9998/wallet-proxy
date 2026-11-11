/** Signature verification for JOSE, COSE and X.509 algorithm identifiers. */
import { ed25519 } from '@noble/curves/ed25519.js';
import { digest, type HashName } from './hash.js';
import { CURVES, type EcCurve, type PublicKey } from './keys.js';
import { verifyPkcs1, verifyPss } from './rsa.js';

export type JoseAlg = 'ES256' | 'ES384' | 'ES512' | 'ES256K' | 'EdDSA' | 'Ed25519' | 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512';

const HASH: Record<JoseAlg, HashName | null> = {
  ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512', ES256K: 'SHA-256', EdDSA: null, Ed25519: null,
  RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512', PS256: 'SHA-256', PS384: 'SHA-384', PS512: 'SHA-512',
};

/** COSE algorithm → JOSE equivalent (RFC 9053, RFC 9864 fully-specified ES256 = -9). */
export function coseAlgToJose(alg: number): JoseAlg {
  switch (alg) {
    case -7: case -9: return 'ES256';
    case -35: case -51: return 'ES384';
    case -36: case -52: return 'ES512';
    case -47: return 'ES256K';
    case -8: case -19: return 'EdDSA';
    case -37: return 'PS256';
    case -38: return 'PS384';
    case -39: return 'PS512';
    case -257: return 'RS256';
    case -258: return 'RS384';
    case -259: return 'RS512';
    default: throw new Error(`Unsupported COSE algorithm ${alg}`);
  }
}

export function isSupportedJoseAlg(alg: string): alg is JoseAlg {
  return typeof alg === 'string' && Object.prototype.hasOwnProperty.call(HASH, alg);
}

/** The one curve of each JOSE / COSE ECDSA algorithm (RFC 7518 section 3.4, RFC 8812, RFC 9864). */
const JOSE_CURVE: Partial<Record<JoseAlg, EcCurve>> = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521', ES256K: 'secp256k1' };

/**
 * Verifies {@code sig} over {@code data}. ECDSA signatures are raw r||s for JOSE/COSE ({@code format: 'raw'})
 * and DER for X.509 ({@code 'der'}).
 *
 * The algorithm must fit the key. In JOSE and COSE ({@code 'raw'}) an ECDSA algorithm names its curve: ES256 verifies
 * only with a P-256 key, ES384 with P-384, ES512 with P-521, ES256K with secp256k1. An X.509 signature algorithm
 * ({@code 'der'}) names only the hash, so there the curve is the key's. EdDSA needs an Ed25519 key, RS and PS
 * algorithms an RSA key of at least 2048 bits with a sane exponent.
 */
export function verifySignature(alg: JoseAlg, key: PublicKey, data: Uint8Array, sig: Uint8Array,
                                format: 'raw' | 'der' = 'raw'): boolean {
  try {
    if (!isSupportedJoseAlg(alg)) return false;
    if (alg === 'EdDSA' || alg === 'Ed25519') {
      return key.kty === 'OKP' && key.crv === 'Ed25519' && ed25519.verify(sig, data, key.x);
    }
    const hash = HASH[alg];
    if (!hash) return false;
    if (alg.startsWith('ES')) {
      if (key.kty !== 'EC') return false;
      if (format !== 'der' && JOSE_CURVE[alg] !== key.crv) return false;
      const curve = CURVES[key.crv];
      return curve.verify(sig, digest(hash, data), key.point, { prehash: false, lowS: false, format: format === 'der' ? 'der' : 'compact' });
    }
    if (key.kty !== 'RSA') return false;
    return alg.startsWith('PS') ? verifyPss(key, hash, data, sig) : verifyPkcs1(key, hash, data, sig);
  } catch {
    return false;
  }
}
