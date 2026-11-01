/** Public key model shared by JOSE, COSE, X.509 and DID code paths. */
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode, base64UrlEncode, bigIntToBytes, bytesToBigInt, concatBytes, utf8Encode } from '../util/bytes.js';
import { sha256 } from './hash.js';

export type EcCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';

export type PublicKey =
  | { kty: 'EC'; crv: EcCurve; point: Uint8Array }
  | { kty: 'OKP'; crv: 'Ed25519'; x: Uint8Array }
  | { kty: 'RSA'; n: bigint; e: bigint };

export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [k: string]: unknown;
}

export const CURVES = { 'P-256': p256, 'P-384': p384, 'P-521': p521, secp256k1 } as const;

const COORD = { 'P-256': 32, 'P-384': 48, 'P-521': 66, secp256k1: 32 } as const;

/** Decompresses / validates an EC point and returns the uncompressed encoding. */
export function ecPoint(crv: EcCurve, bytes: Uint8Array): Uint8Array {
  return CURVES[crv].Point.fromBytes(bytes).toBytes(false);
}

export function publicKeyFromJwk(jwk: Jwk): PublicKey {
  if (jwk.kty === 'EC') {
    const crv = jwk.crv as EcCurve;
    if (!(crv in COORD)) throw new Error(`Unsupported EC curve ${jwk.crv}`);
    const x = base64UrlDecode(jwk.x ?? '');
    const y = base64UrlDecode(jwk.y ?? '');
    return { kty: 'EC', crv, point: ecPoint(crv, concatBytes(Uint8Array.of(4), x, y)) };
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return { kty: 'OKP', crv: 'Ed25519', x: base64UrlDecode(jwk.x ?? '') };
  }
  if (jwk.kty === 'RSA') {
    return { kty: 'RSA', n: bytesToBigInt(base64UrlDecode(jwk.n ?? '')), e: bytesToBigInt(base64UrlDecode(jwk.e ?? '')) };
  }
  throw new Error(`Unsupported JWK kty/crv ${jwk.kty}/${jwk.crv}`);
}

export function publicKeyToJwk(key: PublicKey): Jwk {
  if (key.kty === 'EC') {
    const n = COORD[key.crv];
    return { kty: 'EC', crv: key.crv, x: base64UrlEncode(key.point.subarray(1, 1 + n)), y: base64UrlEncode(key.point.subarray(1 + n)) };
  }
  if (key.kty === 'OKP') return { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(key.x) };
  const nBytes = bigIntToBytes(key.n, Math.ceil(key.n.toString(16).length / 2));
  const eBytes = bigIntToBytes(key.e, Math.ceil(key.e.toString(16).length / 2));
  return { kty: 'RSA', n: base64UrlEncode(nBytes), e: base64UrlEncode(eBytes) };
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export function jwkThumbprint(jwk: Jwk): string {
  return base64UrlEncode(jwkThumbprintBytes(jwk));
}

export function jwkThumbprintBytes(jwk: Jwk): Uint8Array {
  let members: Record<string, unknown>;
  if (jwk.kty === 'EC') members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  else if (jwk.kty === 'OKP') members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  else if (jwk.kty === 'RSA') members = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  else throw new Error(`Unsupported kty ${jwk.kty}`);
  return sha256(utf8Encode(JSON.stringify(members)));
}

/** Removes private members from a JWK. */
export function publicJwk(jwk: Jwk): Jwk {
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...rest } = jwk as Jwk & Record<string, unknown>;
  return rest as Jwk;
}
