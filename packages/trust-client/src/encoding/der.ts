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
  const tag = data[offset]!;
  let p = offset + 1;
  let len = data[p++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | data[p++]!;
  }
  if (p + len > data.length) throw new Error('DER length exceeds data');
  return { tag, start: offset, valueStart: p, end: p + len };
}

/** Children of a constructed TLV. */
export function children(data: Uint8Array, tlv: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = tlv.valueStart;
  while (p < tlv.end) {
    const c = readTlv(data, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

export function slice(data: Uint8Array, tlv: Tlv): Uint8Array {
  return data.subarray(tlv.start, tlv.end);
}
