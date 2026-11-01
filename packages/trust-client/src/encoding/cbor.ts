/**
 * Minimal, dependency-free CBOR (RFC 8949) codec sufficient for mdoc / COSE: integers (incl. bigint),
 * byte and text strings, arrays, maps (decoded as Map to keep integer keys), tags, floats, simple values.
 * Encoding is deterministic (shortest-form heads, definite lengths; map key order as given).
 */
import { utf8Decode, utf8Encode, concatBytes } from '../util/bytes.js';

/** A CBOR tagged value, e.g. tag 24 (embedded CBOR) or tag 0 (date-time string). */
export class Tagged<T = unknown> {
  constructor(public readonly tag: number, public readonly value: T) {}
}

/** Wraps a value as tag 24 (encoded CBOR data item) when encoding. */
export function embeddedCbor(value: unknown): Tagged<Uint8Array> {
  return new Tagged(24, encode(value));
}

export type CborValue = unknown;

export function decode(data: Uint8Array): CborValue {
  const r = new Reader(data);
  const v = r.item();
  if (r.pos !== data.length) throw new Error(`Trailing bytes after CBOR item (${data.length - r.pos})`);
  return v;
}

/** Decodes one item and returns it with the number of bytes consumed. */
export function decodeFirst(data: Uint8Array): { value: CborValue; length: number } {
  const r = new Reader(data);
  return { value: r.item(), length: r.pos };
}

class Reader {
  pos = 0;
  private view: DataView;
  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  private byte(): number {
    if (this.pos >= this.data.length) throw new Error('Unexpected end of CBOR data');
    return this.data[this.pos++]!;
  }

  private length(info: number): number | bigint {
    if (info < 24) return info;
    if (info === 24) return this.byte();
    if (info === 25) { const v = this.view.getUint16(this.pos); this.pos += 2; return v; }
    if (info === 26) { const v = this.view.getUint32(this.pos); this.pos += 4; return v; }
    if (info === 27) {
      const v = this.view.getBigUint64(this.pos);
      this.pos += 8;
      return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
    }
    if (info === 31) return -1;
    throw new Error(`Invalid CBOR additional info ${info}`);
  }

  private bytes(n: number): Uint8Array {
    if (this.pos + n > this.data.length) throw new Error('Unexpected end of CBOR data');
    const out = this.data.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  item(): CborValue {
    const ib = this.byte();
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0: return this.length(info);
      case 1: {
        const n = this.length(info);
        return typeof n === 'bigint' ? -1n - n : -1 - n;
      }
      case 2:
      case 3: {
        const n = this.length(info);
        let b: Uint8Array;
        if (n === -1) {
          const chunks: Uint8Array[] = [];
          while (this.data[this.pos] !== 0xff) chunks.push(this.item() as Uint8Array);
          this.pos++;
          b = major === 3 ? utf8Encode((chunks as unknown as string[]).join('')) : concatBytes(...chunks);
          return major === 2 ? b : utf8Decode(b);
        }
        b = this.bytes(Number(n));
        return major === 2 ? b : utf8Decode(b);
      }
      case 4: {
        const n = this.length(info);
        const arr: CborValue[] = [];
        if (n === -1) {
          while (this.data[this.pos] !== 0xff) arr.push(this.item());
          this.pos++;
        } else for (let i = 0; i < Number(n); i++) arr.push(this.item());
        return arr;
      }
      case 5: {
        const n = this.length(info);
        const m = new Map<CborValue, CborValue>();
        if (n === -1) {
          while (this.data[this.pos] !== 0xff) m.set(this.item(), this.item());
          this.pos++;
        } else for (let i = 0; i < Number(n); i++) m.set(this.item(), this.item());
        return m;
      }
      case 6: {
        const tag = Number(this.length(info));
        const v = this.item();
        if (tag === 2 && v instanceof Uint8Array) return bytesToBig(v);
        if (tag === 3 && v instanceof Uint8Array) return -1n - bytesToBig(v);
        return new Tagged(tag, v);
      }
      default: {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return undefined;
        if (info === 25) { const v = getFloat16(this.view.getUint16(this.pos)); this.pos += 2; return v; }
        if (info === 26) { const v = this.view.getFloat32(this.pos); this.pos += 4; return v; }
        if (info === 27) { const v = this.view.getFloat64(this.pos); this.pos += 8; return v; }
        if (info < 24) return { simple: info };
        if (info === 24) return { simple: this.byte() };
        throw new Error(`Unsupported CBOR simple/float ${info}`);
      }
    }
  }
}

function bytesToBig(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function getFloat16(h: number): number {
  const s = (h & 0x8000) >> 15;
  const e = (h & 0x7c00) >> 10;
  const f = h & 0x03ff;
  if (e === 0) return (s ? -1 : 1) * Math.pow(2, -14) * (f / 1024);
  if (e === 0x1f) return f ? NaN : (s ? -1 : 1) * Infinity;
  return (s ? -1 : 1) * Math.pow(2, e - 15) * (1 + f / 1024);
}

export function encode(value: CborValue): Uint8Array {
  const parts: Uint8Array[] = [];
  write(value, parts);
  return concatBytes(...parts);
}

function head(major: number, n: number | bigint): Uint8Array {
  const mt = major << 5;
  if (typeof n === 'bigint') {
    if (n <= BigInt(Number.MAX_SAFE_INTEGER)) n = Number(n);
    else {
      const b = new Uint8Array(9);
      b[0] = mt | 27;
      new DataView(b.buffer).setBigUint64(1, n);
      return b;
    }
  }
  if (n < 24) return Uint8Array.of(mt | n);
  if (n < 0x100) return Uint8Array.of(mt | 24, n);
  if (n < 0x10000) return Uint8Array.of(mt | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of(mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  const b = new Uint8Array(9);
  b[0] = mt | 27;
  new DataView(b.buffer).setBigUint64(1, BigInt(n));
  return b;
}

function write(v: CborValue, out: Uint8Array[]): void {
  if (v === null) { out.push(Uint8Array.of(0xf6)); return; }
  if (v === undefined) { out.push(Uint8Array.of(0xf7)); return; }
  if (v === true) { out.push(Uint8Array.of(0xf5)); return; }
  if (v === false) { out.push(Uint8Array.of(0xf4)); return; }
  if (typeof v === 'number') {
    if (Number.isInteger(v)) {
      out.push(v >= 0 ? head(0, v) : head(1, -1 - v));
    } else {
      const b = new Uint8Array(9);
      b[0] = 0xfb;
      new DataView(b.buffer).setFloat64(1, v);
      out.push(b);
    }
    return;
  }
  if (typeof v === 'bigint') {
    const mag = v >= 0n ? v : -1n - v;
    if (mag < 1n << 64n) { out.push(v >= 0n ? head(0, mag) : head(1, mag)); return; }
    // RFC 8949 §3.4.3 bignums for values beyond 64 bits
    const hex = mag.toString(16);
    const b = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0, h = hex.padStart(b.length * 2, '0'); i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    out.push(head(6, v >= 0n ? 2 : 3), head(2, b.length), b);
    return;
  }
  if (typeof v === 'string') { const b = utf8Encode(v); out.push(head(3, b.length), b); return; }
  if (v instanceof Uint8Array) { out.push(head(2, v.length), v); return; }
  if (v instanceof Tagged) { out.push(head(6, v.tag)); write(v.value, out); return; }
  if (Array.isArray(v)) { out.push(head(4, v.length)); for (const x of v) write(x, out); return; }
  if (v instanceof Map) { out.push(head(5, v.size)); for (const [k, x] of v) { write(k, out); write(x, out); } return; }
  if (v instanceof Date) { write(new Tagged(0, v.toISOString().replace(/\.\d{3}Z$/, 'Z')), out); return; }
  if (typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined);
    out.push(head(5, entries.length));
    for (const [k, x] of entries) { write(k, out); write(x, out); }
    return;
  }
  throw new Error(`Cannot CBOR-encode ${typeof v}`);
}

/** Reads a key from a decoded CBOR map or plain object. */
export function mapGet(m: unknown, key: string | number): unknown {
  if (m instanceof Map) return m.get(key);
  if (m && typeof m === 'object') return (m as Record<string, unknown>)[String(key)];
  return undefined;
}

/** Unwraps tag 24 (bstr .cbor) to the embedded item, or returns raw bytes decoded if untagged bytes. */
export function unwrapEmbedded(v: unknown): unknown {
  if (v instanceof Tagged && v.tag === 24 && v.value instanceof Uint8Array) return decode(v.value);
  if (v instanceof Uint8Array) return decode(v);
  return v;
}
