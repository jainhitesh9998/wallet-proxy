/**
 * Runtime polyfills for Hermes (Expo Go / native). Imported first from index.ts, before any protocol code.
 *  - crypto.getRandomValues: noble-curves key generation, PKCE, nonces (expo-crypto, available in Expo Go)
 *  - TextEncoder / TextDecoder: UTF-8 only fallbacks when the engine lacks them
 * URL / URLSearchParams / structuredClone are provided by Expo itself on native.
 */
import { getRandomValues } from 'expo-crypto';

const g = globalThis as unknown as Record<string, unknown> & { crypto?: { getRandomValues?: unknown } };

if (typeof g.crypto?.getRandomValues !== 'function') {
  const rv = <T extends ArrayBufferView | null>(array: T): T => getRandomValues(array as never) as T;
  if (g.crypto) {
    try {
      (g.crypto as Record<string, unknown>).getRandomValues = rv;
    } catch {
      g.crypto = { ...g.crypto, getRandomValues: rv };
    }
  } else g.crypto = { getRandomValues: rv };
}

function utf8Encode(s: string): Uint8Array {
  const out: number[] = [];
  for (const ch of s) {
    let cp = ch.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return Uint8Array.from(out);
}

function utf8Decode(input?: ArrayBuffer | ArrayBufferView): string {
  if (!input) return '';
  const b = input instanceof Uint8Array ? input
    : ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(input);
  let out = '';
  for (let i = 0; i < b.length;) {
    const b0 = b[i++]!;
    let cp: number;
    if (b0 < 0x80) cp = b0;
    else if (b0 < 0xe0) cp = ((b0 & 0x1f) << 6) | (b[i++]! & 0x3f);
    else if (b0 < 0xf0) cp = ((b0 & 0x0f) << 12) | ((b[i++]! & 0x3f) << 6) | (b[i++]! & 0x3f);
    else cp = ((b0 & 0x07) << 18) | ((b[i++]! & 0x3f) << 12) | ((b[i++]! & 0x3f) << 6) | (b[i++]! & 0x3f);
    out += String.fromCodePoint(cp);
  }
  return out;
}

if (typeof g.TextEncoder === 'undefined') {
  g.TextEncoder = class {
    readonly encoding = 'utf-8';
    encode(s = '') { return utf8Encode(s); }
  };
}
if (typeof g.TextDecoder === 'undefined') {
  g.TextDecoder = class {
    readonly encoding = 'utf-8';
    decode(b?: ArrayBuffer | ArrayBufferView) { return utf8Decode(b); }
  };
}
