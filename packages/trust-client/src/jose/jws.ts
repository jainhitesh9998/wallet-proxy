/** Compact JWS decoding and verification. */
import { base64UrlDecode, utf8Decode, utf8Encode } from '../util/bytes.js';
import { isSupportedJoseAlg, verifySignature } from '../crypto/verify.js';
import { publicKeyFromJwk, type Jwk, type PublicKey } from '../crypto/keys.js';

export interface DecodedJws<P = Record<string, unknown>> {
  header: Record<string, unknown>;
  payload: P;
  signingInput: Uint8Array;
  signature: Uint8Array;
  compact: string;
}

export function decodeJws<P = Record<string, unknown>>(compact: string): DecodedJws<P> {
  const parts = compact.trim().split('.');
  if (parts.length !== 3) throw new Error('Not a compact JWS');
  const [h, p, s] = parts as [string, string, string];
  const header = JSON.parse(utf8Decode(base64UrlDecode(h))) as Record<string, unknown>;
  let payload: P;
  try {
    payload = JSON.parse(utf8Decode(base64UrlDecode(p))) as P;
  } catch {
    payload = utf8Decode(base64UrlDecode(p)) as unknown as P;
  }
  return { header, payload, signingInput: utf8Encode(`${h}.${p}`), signature: base64UrlDecode(s), compact: compact.trim() };
}

/** Verifies a decoded JWS with a public key. {@code alg: none} and unknown algorithms are rejected. */
export function verifyJws(jws: DecodedJws<unknown>, key: PublicKey | Jwk): boolean {
  const alg = String(jws.header.alg ?? '');
  if (!isSupportedJoseAlg(alg)) return false;
  return verifySignature(alg, toPublicKey(key), jws.signingInput, jws.signature, 'raw');
}

/** Accepts either a parsed {@link PublicKey} or a JWK. */
export function toPublicKey(key: PublicKey | Jwk): PublicKey {
  if ('point' in key && key.point instanceof Uint8Array) return key as PublicKey;
  if (key.kty === 'OKP' && (key as { x?: unknown }).x instanceof Uint8Array) return key as PublicKey;
  if (key.kty === 'RSA' && typeof (key as { n?: unknown }).n === 'bigint') return key as PublicKey;
  return publicKeyFromJwk(key as Jwk);
}

/** {@code x5c} header values as DER bytes. */
export function x5cFromHeader(header: Record<string, unknown>): Uint8Array[] {
  const x5c = header.x5c;
  if (!Array.isArray(x5c)) return [];
  return x5c.map((c) => base64UrlDecode(String(c)));
}
