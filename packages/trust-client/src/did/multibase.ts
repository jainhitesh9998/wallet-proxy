/** base58btc and multicodec helpers for did:key / Multikey. */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const d = ALPHABET.indexOf(c);
    if (d < 0) throw new Error(`Invalid base58 character ${c}`);
    n = n * 58n + BigInt(d);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

export function base58Encode(data: Uint8Array): string {
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of data) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

export function readVarint(data: Uint8Array): { codec: number; payload: Uint8Array } {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < data.length; i++) {
    const b = data[i]!;
    value |= (b & 0x7f) << shift;
    if (!(b & 0x80)) return { codec: value, payload: data.subarray(i + 1) };
    shift += 7;
  }
  throw new Error('Invalid multicodec varint');
}

export function writeVarint(codec: number, payload: Uint8Array): Uint8Array {
  const head: number[] = [];
  let v = codec;
  while (v >= 0x80) {
    head.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  head.push(v);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head);
  out.set(payload, head.length);
  return out;
}

export const MULTICODEC = { ed25519: 0xed, x25519: 0xec, p256: 0x1200, p384: 0x1201, secp256k1: 0xe7, jwkJcs: 0xeb51 } as const;
