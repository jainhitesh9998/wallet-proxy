/**
 * Credential status: IETF Token Status List — JWT (SD-JWT VC) and CWT (ISO mdoc) — and W3C Bitstring Status List.
 * Lists are fetched through the trust client when one is given (lookups.statusLists: from the issuer, or through the
 * service's relay), and always verified here: signature, signer, subject and freshness. The relay is not trusted.
 */
import { gunzipSync, unzlibSync } from 'fflate';
import { bytes, cbor, coseAlgToJose, coseX5chain, decodeJws, parseCertificate, parseCoseSign1, validateCertificateChain, verifyJws,
  verifySignature, type PublicKey, type TrustClient, type TrustDecision } from '@vctrust/trust-client';

export interface StatusResult {
  status: 'valid' | 'revoked' | 'suspended' | 'unknown';
  detail: string;
}

/** The credential a status belongs to: who may sign its status list. */
export interface StatusContext {
  trust?: TrustClient;
  fetch: typeof fetch;
  /** the credential's signing certificate chain (x5c / x5chain), leaf first, base64 DER */
  signerX5c?: string[];
  /** the credential's issuer trust decision (its x509 anchor may also certify the status list signer) */
  decision?: TrustDecision | null;
  /** W3C: the credential's issuer id; a Bitstring Status List credential must come from the same issuer */
  issuer?: string;
  now?: Date;
}

const { Tagged, mapGet } = cbor;

async function fetchList(uri: string, accept: string, ctx: StatusContext): Promise<{ body: Uint8Array; contentType: string; via: string }> {
  if (ctx.trust) {
    const r = await ctx.trust.fetchStatusList(uri, accept);
    return { body: r.body, contentType: r.contentType, via: r.source === 'trust-service' ? ' (via the trust service relay)' : '' };
  }
  const r = await ctx.fetch(uri, { headers: { Accept: accept } });
  if (!r.ok) throw new Error(`Status list ${uri}: HTTP ${r.status}`);
  return { body: new Uint8Array(await r.arrayBuffer()), contentType: (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim(), via: '' };
}

// ---- W3C Bitstring Status List -------------------------------------------------------------------------------

/** Verifies a status list credential's proof; supplied by the JSON-LD verifier (avoids a module cycle). */
export type ListCredentialVerifier = (vc: Record<string, unknown>) => Promise<{ ok: boolean; detail: string }>;

export async function checkBitstringStatus(entry: Record<string, unknown>, ctx: StatusContext & { verifyListCredential?: ListCredentialVerifier }): Promise<StatusResult> {
  const url = String(entry.statusListCredential ?? '');
  const index = Number(entry.statusListIndex);
  const purpose = String(entry.statusPurpose ?? 'revocation');
  if (!url || Number.isNaN(index)) return { status: 'unknown', detail: 'Malformed status entry' };
  try {
    const { body, via } = await fetchList(url, 'application/vc+ld+json, application/ld+json, application/json', ctx);
    const list = JSON.parse(bytes.utf8Decode(body)) as Record<string, unknown> & { credentialSubject?: { encodedList?: string; statusPurpose?: unknown } };
    if (ctx.verifyListCredential) {
      const v = await ctx.verifyListCredential(list);
      if (!v.ok) return { status: 'unknown', detail: `Status list credential ${url} does not verify: ${v.detail}` };
    }
    const listIssuer = typeof list.issuer === 'string' ? list.issuer : (list.issuer as { id?: string } | undefined)?.id;
    if (ctx.issuer && listIssuer !== ctx.issuer) return { status: 'unknown', detail: `Status list is issued by ${listIssuer}, not by the credential issuer` };
    const purposes = [list.credentialSubject?.statusPurpose].flat().map(String);
    if (list.credentialSubject?.statusPurpose !== undefined && !purposes.includes(purpose)) {
      return { status: 'unknown', detail: `Status list purpose ${purposes.join(',')} does not match ${purpose}` };
    }
    const now = ctx.now ?? new Date();
    if (list.validUntil && new Date(String(list.validUntil)) < now) return { status: 'unknown', detail: `Status list expired ${String(list.validUntil)}` };
    const encoded = list.credentialSubject?.encodedList;
    if (!encoded) return { status: 'unknown', detail: 'Status list has no encodedList' };
    const raw = gunzipSync(bytes.base64UrlDecode(encoded.startsWith('u') ? encoded.slice(1) : encoded));
    if ((index >> 3) >= raw.length) return { status: 'unknown', detail: 'Status index out of bounds' };
    const bit = (raw[index >> 3]! >> (7 - (index & 7))) & 1;
    const checked = ctx.verifyListCredential ? ', list proof verified' : '';
    return bit ? { status: purpose === 'suspension' ? 'suspended' : 'revoked', detail: `Bit ${index} set in ${url}${via}` }
      : { status: 'valid', detail: `Bit ${index} clear in ${url} (${purpose}${checked})${via}` };
  } catch (e) {
    return { status: 'unknown', detail: `Status check failed: ${(e as Error).message}` };
  }
}

// ---- IETF Token Status List ----------------------------------------------------------------------------------

export interface StatusListReference {
  idx: number;
  uri: string;
  /** ISO 18013-5 StatusListInfo: the certificate that signs the status list, when not in its x5chain */
  certificate?: Uint8Array;
}

interface ParsedStatusList {
  form: 'jwt' | 'cwt';
  sub?: string;
  exp?: number;
  bits: number;
  lst: Uint8Array;
  chain: string[];
  signedBy: (key: PublicKey) => boolean;
}

/**
 * IETF Token Status List (draft-ietf-oauth-status-list): {@code statuslist+jwt} for SD-JWT VC, {@code statuslist+cwt}
 * for mdoc (MSO {@code status.status_list}). Values: 0 VALID, 1 INVALID, 2 SUSPENDED (LSB-first packing).
 */
export async function checkTokenStatus(ref: StatusListReference, ctx: StatusContext, form: 'jwt' | 'cwt' = 'jwt'): Promise<StatusResult> {
  try {
    const accept = form === 'cwt' ? 'application/statuslist+cwt, application/statuslist+jwt;q=0.5' : 'application/statuslist+jwt, application/statuslist+cwt;q=0.5';
    const { body, contentType, via } = await fetchList(ref.uri, accept, ctx);
    const list = contentType.includes('statuslist+cwt') || body[0] === 0xd2 || body[0] === 0x84 ? parseCwt(body) : parseJwt(bytes.utf8Decode(body).trim());
    if (ref.certificate && list.chain.length === 0) list.chain.push(bytes.base64Encode(ref.certificate));
    const leaf = list.chain[0] ? parseCertificate(list.chain[0]) : null;
    if (!leaf?.publicKey) return { status: 'unknown', detail: 'Status list token carries no signing certificate' };
    if (ref.certificate && bytes.base64Encode(ref.certificate) !== list.chain[0]) return { status: 'unknown', detail: 'Status list is not signed by the certificate named in the credential' };
    if (!list.signedBy(leaf.publicKey)) return { status: 'unknown', detail: 'Status list token signature invalid' };
    const signer = await signerTrust(list.chain, ctx);
    if (!signer.ok) return { status: 'unknown', detail: `Status list signer not trusted: ${signer.detail}` };
    if (list.sub !== ref.uri) return { status: 'unknown', detail: 'Status list sub does not match uri' };
    const now = Math.floor((ctx.now ?? new Date()).getTime() / 1000);
    if (list.exp !== undefined && list.exp < now) return { status: 'unknown', detail: `Status list token expired at ${new Date(list.exp * 1000).toISOString()}` };
    const data = unzlibSync(list.lst);
    const pos = ref.idx * list.bits;
    if ((pos >> 3) >= data.length) return { status: 'unknown', detail: 'Status index out of bounds' };
    const value = (data[pos >> 3]! >> (pos & 7)) & ((1 << list.bits) - 1);
    const how = `statuslist+${list.form}, signer ${signer.detail}${via}`;
    if (value === 0) return { status: 'valid', detail: `Index ${ref.idx}: VALID (${how})` };
    if (value === 1) return { status: 'revoked', detail: `Index ${ref.idx}: INVALID (${how})` };
    if (value === 2) return { status: 'suspended', detail: `Index ${ref.idx}: SUSPENDED (${how})` };
    return { status: 'unknown', detail: `Index ${ref.idx}: application-specific status ${value}` };
  } catch (e) {
    return { status: 'unknown', detail: `Status check failed: ${(e as Error).message}` };
  }
}

function parseJwt(text: string): ParsedStatusList {
  const jws = decodeJws<Record<string, unknown>>(text);
  if (jws.header.typ !== 'statuslist+jwt') throw new Error(`Unexpected status list typ ${String(jws.header.typ)}`);
  const sl = jws.payload.status_list as { bits: number; lst: string };
  return { form: 'jwt', sub: jws.payload.sub as string | undefined, exp: jws.payload.exp as number | undefined, bits: sl.bits,
    lst: bytes.base64UrlDecode(sl.lst), chain: Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : [],
    signedBy: (key) => verifyJws(jws, key) };
}

/** COSE_Sign1 over a CWT: typ (16), x5chain (33); claims sub (2), exp (4), status_list (65533) = {bits, lst}. */
function parseCwt(body: Uint8Array): ParsedStatusList {
  const sign1 = parseCoseSign1(cbor.decode(body));
  const typ = sign1.protectedHeader.get(16) ?? sign1.unprotectedHeader.get(16);
  if (typ !== 'application/statuslist+cwt' && typ !== 'statuslist+cwt') throw new Error(`Unexpected status list typ ${String(typ)}`);
  if (!sign1.payload) throw new Error('Status list CWT has a detached payload');
  const claims = cbor.decode(sign1.payload);
  const sl = mapGet(claims, 65533);
  const lst = mapGet(sl, 'lst');
  if (!(lst instanceof Uint8Array)) throw new Error('Status list CWT has no status_list');
  const alg = coseAlgToJose(Number(sign1.protectedHeader.get(1)));
  const toBeSigned = cbor.encode(['Signature1', sign1.protectedBytes, new Uint8Array(), sign1.payload]);
  const exp = mapGet(claims, 4);
  return { form: 'cwt', sub: mapGet(claims, 2) as string | undefined, exp: exp === undefined ? undefined : Number(exp instanceof Tagged ? exp.value : exp),
    bits: Number(mapGet(sl, 'bits')), lst, chain: coseX5chain(sign1).map((c) => bytes.base64Encode(c)),
    signedBy: (key) => verifySignature(alg, key, toBeSigned, sign1.signature, 'raw') };
}

/**
 * Who may sign a credential's status list: the credential's own signer, a certificate issued under the trust
 * anchor the credential validated to, or a status list provider trusted in its own right ('status-list' domain).
 */
async function signerTrust(chain: string[], ctx: StatusContext): Promise<{ ok: boolean; detail: string }> {
  if (ctx.signerX5c?.[0] && ctx.signerX5c[0] === chain[0]) return { ok: true, detail: 'the credential signer' };
  const anchor = anchorCertificate(ctx.decision);
  if (anchor) {
    const r = validateCertificateChain(chain, [{ certificate: parseCertificate(anchor), domain: 'status-list' }], { time: ctx.now });
    if (r.valid) return { ok: true, detail: `issued under the credential's trust anchor ${String((r.anchor?.certificate as { subject?: string } | undefined)?.subject ?? '')}`.trim() };
  }
  if (ctx.trust) {
    const r = await ctx.trust.validateChain(chain, 'status-list').catch(() => null);
    if (r?.valid) return { ok: true, detail: 'a trusted status list provider' };
    return { ok: false, detail: parseCertificate(chain[0]!).subject };
  }
  return { ok: true, detail: `${parseCertificate(chain[0]!).subject} (not checked: no trust client)` };
}

function anchorCertificate(d?: TrustDecision | null): string | undefined {
  const c = (d?.evidence?.x509?.anchor as { certificate?: unknown } | undefined)?.certificate;
  if (typeof c === 'string') return c;
  const nested = (c as { certificate?: unknown } | undefined)?.certificate;
  return typeof nested === 'string' ? nested : undefined;
}
