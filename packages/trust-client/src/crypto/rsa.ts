/** RSA signature verification (RSASSA-PKCS1-v1_5 and RSASSA-PSS, RFC 8017) using BigInt. */
import { bytesEqual, bytesToBigInt, bigIntToBytes, concatBytes } from '../util/bytes.js';
import { digest, type HashName } from './hash.js';

export interface RsaPublicKey {
  n: bigint;
  e: bigint;
}

/** Smallest RSA modulus a signature is verified with. */
export const MIN_RSA_MODULUS_BITS = 2048;
/** Largest modulus and public exponent accepted: both are the signer's choice and set the cost of a verification. */
export const MAX_RSA_MODULUS_BITS = 8192;
export const MAX_RSA_EXPONENT_BITS = 256;

/**
 * Why an RSA public key is not acceptable for verifying anything, or null. With e = 1 a "signature" is the padded
 * hash itself; an even e or n is not an RSA key; a short modulus can be factored.
 */
export function rsaKeyProblem(key: RsaPublicKey): string | null {
  if (key.n <= 0n || key.e <= 0n) return 'the key is not a positive modulus and exponent';
  const bits = bitLength(key.n);
  if (bits < MIN_RSA_MODULUS_BITS) return `the modulus has ${bits} bits, fewer than ${MIN_RSA_MODULUS_BITS}`;
  if (bits > MAX_RSA_MODULUS_BITS) return `the modulus has ${bits} bits, more than ${MAX_RSA_MODULUS_BITS}`;
  if ((key.n & 1n) === 0n) return 'the modulus is even';
  if (key.e === 1n) return 'the public exponent is 1';
  if ((key.e & 1n) === 0n) return 'the public exponent is even';
  if (bitLength(key.e) > MAX_RSA_EXPONENT_BITS) return `the public exponent has more than ${MAX_RSA_EXPONENT_BITS} bits`;
  return null;
}

function bitLength(n: bigint): number {
  const hex = n.toString(16);
  return (hex.length - 1) * 4 + (32 - Math.clz32(parseInt(hex[0]!, 16)));
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function byteLength(n: bigint): number {
  return Math.ceil(n.toString(16).length / 2);
}

const DIGEST_INFO: Record<HashName, Uint8Array> = {
  'SHA-256': Uint8Array.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
  'SHA-384': Uint8Array.from([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
  'SHA-512': Uint8Array.from([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
};

function rsavp1(key: RsaPublicKey, sig: Uint8Array): Uint8Array | null {
  if (rsaKeyProblem(key)) return null;
  const k = byteLength(key.n);
  if (sig.length !== k) return null;
  const s = bytesToBigInt(sig);
  if (s >= key.n) return null;
  return bigIntToBytes(modPow(s, key.e, key.n), k);
}

export function verifyPkcs1(key: RsaPublicKey, hash: HashName, data: Uint8Array, sig: Uint8Array): boolean {
  const em = rsavp1(key, sig);
  if (!em) return false;
  const t = concatBytes(DIGEST_INFO[hash], digest(hash, data));
  const k = em.length;
  if (k < t.length + 11) return false;
  const expected = new Uint8Array(k);
  expected[0] = 0x00;
  expected[1] = 0x01;
  expected.fill(0xff, 2, k - t.length - 1);
  expected[k - t.length - 1] = 0x00;
  expected.set(t, k - t.length);
  return bytesEqual(em, expected);
}

function mgf1(hash: HashName, seed: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let o = 0;
  for (let c = 0; o < len; c++) {
    const block = digest(hash, concatBytes(seed, Uint8Array.of((c >>> 24) & 0xff, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff)));
    out.set(block.subarray(0, Math.min(block.length, len - o)), o);
    o += block.length;
  }
  return out;
}

export function verifyPss(key: RsaPublicKey, hash: HashName, data: Uint8Array, sig: Uint8Array, saltLength?: number): boolean {
  const modBits = key.n.toString(2).length;
  const emBits = modBits - 1;
  const emLen = Math.ceil(emBits / 8);
  const decoded = rsavp1(key, sig);
  if (!decoded) return false;
  const em = decoded.subarray(decoded.length - emLen);
  const mHash = digest(hash, data);
  const hLen = mHash.length;
  const sLen = saltLength ?? hLen;
  if (emLen < hLen + sLen + 2 || em[emLen - 1] !== 0xbc) return false;
  const maskedDB = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);
  const zeroBits = 8 * emLen - emBits;
  if ((maskedDB[0]! & (0xff << (8 - zeroBits)) & 0xff) !== 0) return false;
  const dbMask = mgf1(hash, h, emLen - hLen - 1);
  const db = new Uint8Array(maskedDB.length);
  for (let i = 0; i < db.length; i++) db[i] = maskedDB[i]! ^ dbMask[i]!;
  db[0] = db[0]! & (0xff >> zeroBits);
  const psLen = emLen - hLen - sLen - 2;
  for (let i = 0; i < psLen; i++) if (db[i] !== 0) return false;
  if (db[psLen] !== 0x01) return false;
  const salt = db.subarray(db.length - sLen);
  const mPrime = concatBytes(new Uint8Array(8), mHash, salt);
  return bytesEqual(digest(hash, mPrime), h);
}
