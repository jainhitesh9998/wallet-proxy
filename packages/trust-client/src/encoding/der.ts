/**
 * Strict DER reader (X.690 section 10), used for certificates and CRLs. It reads only what DER allows: definite
 * lengths in their shortest form, single-octet tags, minimal INTEGERs, canonical BOOLEANs. An encoding that is valid
 * BER but not DER is an error, so that one certificate has exactly one encoding (its hash identifies it) and every
 * implementation that reads it sees the same thing.
 */
export interface Tlv {
  tag: number;
  /** offset of the TLV start */
  start: number;
  /** offset of the value */
  valueStart: number;
  end: number;
}

export const TAG = {
  boolean: 0x01, integer: 0x02, bitString: 0x03, octetString: 0x04, null: 0x05, oid: 0x06, enumerated: 0x0a,
  utf8String: 0x0c, sequence: 0x30, set: 0x31, printableString: 0x13, ia5String: 0x16, utcTime: 0x17, generalizedTime: 0x18,
} as const;

export function readTlv(data: Uint8Array, offset: number): Tlv {
  if (offset + 2 > data.length) throw new Error('DER truncated');
  const tag = data[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new Error('DER tag numbers above 30 are not supported');
  let p = offset + 1;
  let len = data[p++]!;
  if (len === 0x80) throw new Error('DER does not allow an indefinite length');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new Error('Unsupported DER length');
    if (p + n > data.length) throw new Error('DER truncated');
    if (data[p] === 0) throw new Error('DER length is not in its shortest form');
    // Arithmetic, not bit shifts: a 4-byte length must not wrap into a negative int32.
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + data[p++]!;
    if (len < 0x80) throw new Error('DER length is not in its shortest form');
  }
  if (len > data.length - p) throw new Error('DER length exceeds data');
  return { tag, start: offset, valueStart: p, end: p + len };
}

/** The one element that {@code data} consists of: nothing may follow it. */
export function readSingle(data: Uint8Array, what = 'DER element'): Tlv {
  const t = readTlv(data, 0);
  if (t.end !== data.length) throw new Error(`Trailing bytes after the ${what} (DER)`);
  return t;
}

/** Children of a constructed TLV; each must lie inside it. */
export function children(data: Uint8Array, tlv: Tlv): Tlv[] {
  if (!(tlv.tag & 0x20)) throw new Error('DER element is not constructed');
  const out: Tlv[] = [];
  let p = tlv.valueStart;
  while (p < tlv.end) {
    const c = readTlv(data, p);
    if (c.end > tlv.end) throw new Error('DER element exceeds its parent');
    out.push(c);
    p = c.end;
  }
  return out;
}

export function slice(data: Uint8Array, tlv: Tlv): Uint8Array {
  return data.subarray(tlv.start, tlv.end);
}

export function value(data: Uint8Array, tlv: Tlv): Uint8Array {
  return data.subarray(tlv.valueStart, tlv.end);
}

/** {@code tlv} when it has the expected tag; an error naming {@code what} otherwise (also when it is missing). */
export function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv) throw new Error(`DER: ${what} is missing`);
  if (tlv.tag !== tag) throw new Error(`DER: ${what} has tag 0x${tlv.tag.toString(16)}, expected 0x${tag.toString(16)}`);
  return tlv;
}

/** Children of a SEQUENCE (or another constructed element with the given tag). */
export function sequence(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.sequence): Tlv[] {
  return children(data, expectTag(tlv, tag, what));
}

/**
 * Content octets of an INTEGER (or ENUMERATED, or an IMPLICIT-tagged integer: pass its tag), checked to be the
 * shortest two's-complement form: not empty, no redundant leading 0x00 or 0xFF.
 */
export function integerBytes(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.integer): Uint8Array {
  const v = value(data, expectTag(tlv, tag, what));
  if (v.length === 0) throw new Error(`DER: ${what} is an empty INTEGER`);
  if (v.length > 1 && ((v[0] === 0x00 && !(v[1]! & 0x80)) || (v[0] === 0xff && (v[1]! & 0x80)))) {
    throw new Error(`DER: ${what} is not a minimally encoded INTEGER`);
  }
  return v;
}

/** A non-negative INTEGER as a bigint. */
export function unsignedInteger(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.integer): bigint {
  const v = integerBytes(data, tlv, what, tag);
  if (v[0]! & 0x80) throw new Error(`DER: ${what} is negative`);
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  return n;
}

/** A small non-negative INTEGER (a version, a path length, a reason code). */
export function smallInteger(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.integer): number {
  const n = unsignedInteger(data, tlv, what, tag);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`DER: ${what} is too large`);
  return Number(n);
}

/** A BOOLEAN in its DER form: one octet, 0x00 or 0xFF. */
export function booleanValue(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.boolean): boolean {
  const v = value(data, expectTag(tlv, tag, what));
  if (v.length !== 1 || (v[0] !== 0x00 && v[0] !== 0xff)) throw new Error(`DER: ${what} is not a DER BOOLEAN`);
  return v[0] === 0xff;
}

/** A BIT STRING: its octets and the number of unused bits in the last one (which must be zero bits). */
export function bitString(data: Uint8Array, tlv: Tlv | undefined, what: string, tag: number = TAG.bitString): { bytes: Uint8Array; unused: number } {
  const v = value(data, expectTag(tlv, tag, what));
  if (v.length === 0) throw new Error(`DER: ${what} is an empty BIT STRING`);
  const unused = v[0]!;
  const bytes = v.subarray(1);
  if (unused > 7 || (bytes.length === 0 && unused !== 0)) throw new Error(`DER: ${what} has an invalid unused-bits count`);
  if (unused > 0 && (bytes[bytes.length - 1]! & ((1 << unused) - 1)) !== 0) throw new Error(`DER: ${what} has non-zero unused bits`);
  return { bytes, unused };
}

/** A BIT STRING that carries whole octets (a key, a signature). */
export function octetAlignedBitString(data: Uint8Array, tlv: Tlv | undefined, what: string): Uint8Array {
  const b = bitString(data, tlv, what);
  if (b.unused !== 0) throw new Error(`DER: ${what} is not a whole number of octets`);
  return b.bytes;
}

/** Dotted form of OBJECT IDENTIFIER content octets; sub-identifiers must be in their shortest form. */
export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0 || (bytes[bytes.length - 1]! & 0x80)) throw new Error('DER: malformed OBJECT IDENTIFIER');
  const parts: number[] = [];
  let v = 0;
  let start = true;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (start && b === 0x80) throw new Error('DER: OBJECT IDENTIFIER is not in its shortest form');
    v = v * 128 + (b & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER) throw new Error('DER: OBJECT IDENTIFIER component is too large');
    start = false;
    if (!(b & 0x80)) {
      if (parts.length === 0) {
        const first = v < 80 ? Math.floor(v / 40) : 2;
        parts.push(first, v - first * 40);
      } else parts.push(v);
      v = 0;
      start = true;
    }
  }
  return parts.join('.');
}

export function oid(data: Uint8Array, tlv: Tlv | undefined, what: string): string {
  return decodeOid(value(data, expectTag(tlv, TAG.oid, what)));
}
