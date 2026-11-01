/** Minimal DER TLV reader, used to slice the exact signed bytes (TBSCertificate) out of a certificate. */
export interface Tlv {
  tag: number;
  /** offset of the TLV start */
  start: number;
  /** offset of the value */
  valueStart: number;
  end: number;
}

export function readTlv(data: Uint8Array, offset: number): Tlv {
  if (offset + 2 > data.length) throw new Error('DER truncated');
  const tag = data[offset]!;
  let p = offset + 1;
  let len = data[p++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Unsupported DER length');
    if (p + n > data.length) throw new Error('DER truncated');
    // Arithmetic, not bit shifts: a 4-byte length must not wrap into a negative int32.
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + data[p++]!;
  }
  if (len > data.length - p) throw new Error('DER length exceeds data');
  return { tag, start: offset, valueStart: p, end: p + len };
}

/** Children of a constructed TLV; each must lie inside it. */
export function children(data: Uint8Array, tlv: Tlv): Tlv[] {
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
