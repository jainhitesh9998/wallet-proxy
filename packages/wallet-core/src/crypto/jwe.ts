/** Compact JWE with ECDH-ES (direct key agreement, RFC 7518 §4.6) and A128GCM / A256GCM. */
import { p256 } from '@noble/curves/nist.js';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { Jwk } from '@vctrust/trust-client';
import { bytes, publicKeyFromJwk, publicKeyToJwk } from '@vctrust/trust-client/primitives';

export type JweEnc = 'A128GCM' | 'A256GCM';

function u32(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function lengthPrefixed(data: Uint8Array): Uint8Array {
  return bytes.concatBytes(u32(data.length), data);
}

/** Concat KDF (NIST SP 800-56A) as profiled by RFC 7518 §4.6.2, single round (key ≤ 256 bits). */
export function concatKdf(z: Uint8Array, enc: JweEnc, apu?: Uint8Array, apv?: Uint8Array): Uint8Array {
  const keyBits = enc === 'A128GCM' ? 128 : 256;
  const otherInfo = bytes.concatBytes(lengthPrefixed(bytes.utf8Encode(enc)), lengthPrefixed(apu ?? new Uint8Array()), lengthPrefixed(apv ?? new Uint8Array()), u32(keyBits));
  return sha256(bytes.concatBytes(u32(1), z, otherInfo)).subarray(0, keyBits / 8);
}

export function encryptJwe(plaintext: Uint8Array, recipient: Jwk, enc: JweEnc = 'A128GCM', extraHeader: Record<string, unknown> = {}): string {
  const pub = publicKeyFromJwk(recipient);
  if (pub.kty !== 'EC' || pub.crv !== 'P-256') throw new Error('Only P-256 recipients are supported');
  const eph = p256.utils.randomSecretKey();
  const z = p256.getSharedSecret(eph, pub.point).subarray(1);
  const epk = publicKeyToJwk({ kty: 'EC', crv: 'P-256', point: p256.getPublicKey(eph, false) });
  const header: Record<string, unknown> = { alg: 'ECDH-ES', enc, epk, ...extraHeader };
  if (recipient.kid) header.kid = recipient.kid;
  const apu = typeof header.apu === 'string' ? bytes.base64UrlDecode(header.apu) : undefined;
  const apv = typeof header.apv === 'string' ? bytes.base64UrlDecode(header.apv) : undefined;
  const cek = concatKdf(z, enc, apu, apv);
  const protectedB64 = bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(header)));
  const iv = bytes.randomBytes(12);
  const sealed = gcm(cek, iv, bytes.utf8Encode(protectedB64)).encrypt(plaintext);
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  return `${protectedB64}..${bytes.base64UrlEncode(iv)}.${bytes.base64UrlEncode(ct)}.${bytes.base64UrlEncode(tag)}`;
}

export function decryptJwe(jwe: string, ecdh: (peerUncompressed: Uint8Array) => Uint8Array): { header: Record<string, unknown>; plaintext: Uint8Array } {
  const [h, ek, iv, ct, tag] = jwe.split('.');
  if (h === undefined || ek === undefined || iv === undefined || ct === undefined || tag === undefined) throw new Error('Not a compact JWE');
  if (ek !== '') throw new Error('Only ECDH-ES direct key agreement is supported');
  const header = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(h))) as Record<string, unknown>;
  if (header.alg !== 'ECDH-ES') throw new Error(`Unsupported JWE alg ${String(header.alg)}`);
  const enc = header.enc as JweEnc;
  if (enc !== 'A128GCM' && enc !== 'A256GCM') throw new Error(`Unsupported JWE enc ${String(enc)}`);
  const epk = publicKeyFromJwk(header.epk as Jwk);
  if (epk.kty !== 'EC') throw new Error('Bad epk');
  const cek = concatKdf(ecdh(epk.point), enc,
    typeof header.apu === 'string' ? bytes.base64UrlDecode(header.apu) : undefined,
    typeof header.apv === 'string' ? bytes.base64UrlDecode(header.apv) : undefined);
  const plaintext = gcm(cek, bytes.base64UrlDecode(iv), bytes.utf8Encode(h))
    .decrypt(bytes.concatBytes(bytes.base64UrlDecode(ct), bytes.base64UrlDecode(tag)));
  return { header, plaintext };
}
