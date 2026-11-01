/** Revocation / suspension status: W3C Bitstring Status List and IETF Token Status List. */
import { gunzipSync, unzlibSync } from 'fflate';
import { bytes, decodeJws, verifyJws, parseCertificate, type TrustClient } from '@vctrust/trust-client';

export interface StatusResult {
  status: 'valid' | 'revoked' | 'suspended' | 'unknown';
  detail: string;
}

export async function checkBitstringStatus(entry: Record<string, unknown>, f: typeof fetch): Promise<StatusResult> {
  const url = String(entry.statusListCredential ?? '');
  const index = Number(entry.statusListIndex);
  const purpose = String(entry.statusPurpose ?? 'revocation');
  if (!url || Number.isNaN(index)) return { status: 'unknown', detail: 'Malformed status entry' };
  try {
    const r = await f(url, { headers: { Accept: 'application/vc+ld+json, application/ld+json, application/json' } });
    if (!r.ok) return { status: 'unknown', detail: `Status list ${url}: HTTP ${r.status}` };
    const list = (await r.json()) as { credentialSubject?: { encodedList?: string } };
    const encoded = list.credentialSubject?.encodedList;
    if (!encoded) return { status: 'unknown', detail: 'Status list has no encodedList' };
    const raw = gunzipSync(bytes.base64UrlDecode(encoded.startsWith('u') ? encoded.slice(1) : encoded));
    const bit = (raw[index >> 3]! >> (7 - (index & 7))) & 1;
    return bit ? { status: purpose === 'suspension' ? 'suspended' : 'revoked', detail: `Bit ${index} set in ${url}` }
      : { status: 'valid', detail: `Bit ${index} clear in ${url} (${purpose})` };
  } catch (e) {
    return { status: 'unknown', detail: `Status check failed: ${(e as Error).message}` };
  }
}

/** IETF Token Status List: {status_list: {idx, uri}} → statuslist+jwt, LSB-first packed values. */
export async function checkTokenStatus(ref: { idx: number; uri: string }, f: typeof fetch, trust?: TrustClient): Promise<StatusResult> {
  try {
    const r = await f(ref.uri, { headers: { Accept: 'application/statuslist+jwt' } });
    if (!r.ok) return { status: 'unknown', detail: `Status list ${ref.uri}: HTTP ${r.status}` };
    const jws = decodeJws<Record<string, unknown>>((await r.text()).trim());
    const x5c = Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : [];
    if (x5c.length > 0) {
      const leaf = parseCertificate(x5c[0]!);
      if (!leaf.publicKey || !verifyJws(jws, leaf.publicKey)) return { status: 'unknown', detail: 'Status list token signature invalid' };
      if (trust) {
        const d = await trust.validateChain(x5c, 'status-list').catch(() => null);
        if (d && !d.valid && d.anchorFound) return { status: 'unknown', detail: 'Status list signer not trusted' };
      }
    }
    if (jws.payload.sub !== ref.uri) return { status: 'unknown', detail: 'Status list sub does not match uri' };
    const sl = jws.payload.status_list as { bits: number; lst: string };
    const data = unzlibSync(bytes.base64UrlDecode(sl.lst));
    const bitsPer = sl.bits;
    const pos = ref.idx * bitsPer;
    if ((pos >> 3) >= data.length) return { status: 'unknown', detail: 'Status index out of bounds' };
    const value = (data[pos >> 3]! >> (pos & 7)) & ((1 << bitsPer) - 1);
    if (value === 0) return { status: 'valid', detail: `Index ${ref.idx}: VALID` };
    if (value === 1) return { status: 'revoked', detail: `Index ${ref.idx}: INVALID` };
    if (value === 2) return { status: 'suspended', detail: `Index ${ref.idx}: SUSPENDED` };
    return { status: 'unknown', detail: `Index ${ref.idx}: application-specific status ${value}` };
  } catch (e) {
    return { status: 'unknown', detail: `Status check failed: ${(e as Error).message}` };
  }
}
