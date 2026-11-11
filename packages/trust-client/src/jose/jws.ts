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
  if (header === null || typeof header !== 'object' || Array.isArray(header)) throw new Error('JWS header is not a JSON object');
  let payload: P;
  try {
    payload = JSON.parse(utf8Decode(base64UrlDecode(p))) as P;
  } catch {
    payload = utf8Decode(base64UrlDecode(p)) as unknown as P;
  }
  return { header, payload, signingInput: utf8Encode(`${h}.${p}`), signature: base64UrlDecode(s), compact: compact.trim() };
}

export interface VerifyJwsOptions {
  /**
   * Extension header parameters the caller itself processes, and which the JWS may therefore list in {@code crit}.
   * This library implements none (not RFC 7797 {@code b64} either), so by default any {@code crit} is refused.
   */
  understoodCritical?: readonly string[];
}

/**
 * Why the {@code crit} header parameter makes a JWS unacceptable, or null (RFC 7515 section 4.1.11): every name it
 * lists must be an extension the recipient understands and processes, and must be present in the header.
 */
export function criticalHeaderProblem(header: Record<string, unknown>, understood: readonly string[] = []): string | null {
  if (!Object.prototype.hasOwnProperty.call(header, 'crit')) return null;
  const crit = header.crit;
  if (!Array.isArray(crit) || crit.length === 0 || crit.some((n) => typeof n !== 'string' || n === '')) {
    return 'crit must be a non-empty array of header parameter names';
  }
  for (const name of crit as string[]) {
    if (!understood.includes(name)) return `critical header parameter ${name} is not understood`;
    if (!Object.prototype.hasOwnProperty.call(header, name)) return `critical header parameter ${name} is not in the header`;
  }
  return new Set(crit).size === crit.length ? null : 'crit lists a header parameter twice';
}

/**
 * Verifies a decoded JWS with a public key. Rejected: {@code alg: none} and unknown algorithms, an algorithm that
 * does not fit the key's type and curve (ES256 needs a P-256 key, and so on), and a {@code crit} header that lists
 * anything the caller did not declare as understood.
 */
export function verifyJws(jws: DecodedJws<unknown>, key: PublicKey | Jwk, opts: VerifyJwsOptions = {}): boolean {
  const alg = jws.header.alg;
  if (typeof alg !== 'string' || !isSupportedJoseAlg(alg)) return false;
  if (criticalHeaderProblem(jws.header, opts.understoodCritical) !== null) return false;
  let publicKey: PublicKey;
  try {
    publicKey = toPublicKey(key);
  } catch {
    return false;
  }
  return verifySignature(alg, publicKey, jws.signingInput, jws.signature, 'raw');
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
