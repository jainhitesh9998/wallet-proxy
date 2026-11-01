/**
 * Credential status: IETF Token Status List (draft-ietf-oauth-status-list) in JWT form for SD-JWT VC and CWT form for
 * ISO mdoc, and W3C Bitstring Status List v1.0. The caller supplies the fetcher (the trust client fetches from the
 * issuer, or through the service's relay); every list is verified here, so neither a relay nor a cache is trusted:
 * signature, signer, subject, freshness, and for Bitstring lists the list credential's proof, issuer and purpose.
 */
import { gunzipSync, unzlibSync } from 'fflate';
import type { FetchedStatusList } from '../client.js';
import { coseX5chain, parseCoseSign1 } from '../credential/extract.js';
import { coseAlgToJose, verifySignature } from '../crypto/verify.js';
import type { PublicKey } from '../crypto/keys.js';
import * as cbor from '../encoding/cbor.js';
import { decodeJws, verifyJws } from '../jose/jws.js';
import type { PathValidationResult, TrustDecision } from '../types.js';
import { base64Encode, base64UrlDecode, utf8Decode } from '../util/bytes.js';
import { parseCertificate } from '../x509/certificate.js';
import { validateCertificateChain } from '../x509/validate.js';

export interface StatusResult {
  status: 'valid' | 'revoked' | 'suspended' | 'unknown';
  detail: string;
  /** the raw status value (Token Status List) or bit (Bitstring) */
  value?: number;
  /** how long the verified list may be reused: its ttl, bounded by its expiry */
  ttlMs?: number;
}

export type StatusListFetcher = (uri: string, accept: string) => Promise<FetchedStatusList>;

/** The credential a status belongs to, and how to fetch and trust its status list. */
export interface StatusContext {
  fetchList: StatusListFetcher;
  /** validates a list signer's chain in a trust domain (the trust client's validateChain) */
  validateChain?: (chain: string[], domain: string) => Promise<PathValidationResult>;
  /** the credential's signing certificate chain (x5c / x5chain), leaf first, base64 DER */
  signerX5c?: string[];
  /** the credential's signing key, for lists signed without a certificate by the same key */
  signerKey?: PublicKey;
  /** the credential's issuer trust decision (its x509 anchor may also certify the status list signer) */
  decision?: TrustDecision | null;
  /** W3C: the credential's issuer id; a Bitstring Status List credential must come from the same issuer */
  issuer?: string;
  now?: Date;
}

/** A Token Status List reference: the {@code status_list} member of a JWT, CWT or ISO mdoc MSO {@code status}. */
export interface TokenStatusReference {
  idx: number;
  uri: string;
  /** ISO 18013-5 StatusListInfo: the certificate that signs the status list, when not in its x5chain */
  certificate?: Uint8Array;
}

/** Verifies a Bitstring Status List credential's proof; supplied by the JSON-LD verifier. */
export type ListCredentialVerifier = (vc: Record<string, unknown>) => Promise<{ ok: boolean; detail: string }>;

const MAX_TTL_MS = 3600_000;
/** reuse of a list that states no ttl */
const DEFAULT_TTL_MS = 5 * 60_000;
const via = (l: FetchedStatusList) => (l.source === 'trust-service' ? ' (via the trust service relay)' : l.source === 'cache' ? ' (cached)' : '');
const unknown = (detail: string): StatusResult => ({ status: 'unknown', detail });

// ---- IETF Token Status List ----------------------------------------------------------------------------------

interface ParsedTokenList {
  form: 'jwt' | 'cwt';
  sub?: string;
  iat?: number;
  exp?: number;
  ttl?: number;
  bits: number;
  lst: Uint8Array;
  chain: string[];
  signedBy: (key: PublicKey) => boolean;
}

/** Values: 0 VALID, 1 INVALID, 2 SUSPENDED, others application-specific; {@code bits} per entry, LSB first. */
export async function checkTokenStatus(ref: TokenStatusReference, ctx: StatusContext, form: 'jwt' | 'cwt' = 'jwt'): Promise<StatusResult> {
  if (!ref?.uri || !Number.isInteger(ref.idx) || ref.idx < 0) return unknown('Malformed status_list reference');
  let fetched: FetchedStatusList;
  try {
    fetched = await ctx.fetchList(ref.uri, form === 'cwt' ? 'application/statuslist+cwt, application/statuslist+jwt;q=0.5'
      : 'application/statuslist+jwt, application/statuslist+cwt;q=0.5');
  } catch (e) {
    return unknown(`Status list unavailable: ${(e as Error).message}`);
  }
  try {
    const { body, contentType } = fetched;
    const list = contentType.includes('statuslist+cwt') || body[0] === 0xd2 || body[0] === 0x84 ? parseCwt(body) : parseJwt(utf8Decode(body).trim());
    if (ref.certificate && list.chain.length === 0) list.chain.push(base64Encode(ref.certificate));
    if (ref.certificate && base64Encode(ref.certificate) !== list.chain[0]) return unknown('Status list is not signed by the certificate named in the credential');
    let signer: { ok: boolean; detail: string };
    if (list.chain.length > 0) {
      const leaf = parseCertificate(list.chain[0]!);
      if (!leaf.publicKey || !list.signedBy(leaf.publicKey)) return unknown('Status list token signature invalid');
      signer = await signerTrust(list.chain, ctx);
    } else if (ctx.signerKey) {
      if (!list.signedBy(ctx.signerKey)) return unknown('Status list token is not signed by the credential signer');
      signer = { ok: true, detail: 'the credential signer' };
    } else {
      return unknown('Status list token carries no signing certificate');
    }
    if (!signer.ok) return unknown(`Status list signer not trusted: ${signer.detail}`);
    if (list.sub !== ref.uri) return unknown('Status list sub does not match uri');
    const now = Math.floor((ctx.now ?? new Date()).getTime() / 1000);
    if (list.exp !== undefined && list.exp < now) return unknown(`Status list token expired at ${new Date(list.exp * 1000).toISOString()}`);
    if (list.iat !== undefined && list.iat > now + 300) return unknown('Status list token is issued in the future');
    if (![1, 2, 4, 8].includes(list.bits)) return unknown(`Status list has an invalid bits value ${list.bits}`);
    const data = unzlibSync(list.lst);
    const pos = ref.idx * list.bits;
    if ((pos >> 3) >= data.length) return unknown('Status index out of bounds');
    const value = (data[pos >> 3]! >> (pos & 7)) & ((1 << list.bits) - 1);
    const ttlMs = Math.min(MAX_TTL_MS, list.ttl !== undefined ? list.ttl * 1000 : DEFAULT_TTL_MS,
      list.exp !== undefined ? (list.exp - now) * 1000 : MAX_TTL_MS);
    const how = `statuslist+${list.form}, signer ${signer.detail}${via(fetched)}`;
    if (value === 0) return { status: 'valid', detail: `Index ${ref.idx}: VALID (${how})`, value, ttlMs };
    if (value === 1) return { status: 'revoked', detail: `Index ${ref.idx}: INVALID (${how})`, value, ttlMs };
    if (value === 2) return { status: 'suspended', detail: `Index ${ref.idx}: SUSPENDED (${how})`, value, ttlMs };
    return { status: 'unknown', detail: `Index ${ref.idx}: application-specific status ${value} (${how})`, value, ttlMs };
  } catch (e) {
    return unknown(`Status check failed: ${(e as Error).message}`);
  }
}

function parseJwt(text: string): ParsedTokenList {
  const jws = decodeJws<Record<string, unknown>>(text);
  if (jws.header.typ !== 'statuslist+jwt') throw new Error(`Unexpected status list typ ${String(jws.header.typ)}`);
  const sl = jws.payload.status_list as { bits: number; lst: string } | undefined;
  if (!sl || typeof sl.lst !== 'string') throw new Error('Status list JWT has no status_list');
  const num = (v: unknown) => (typeof v === 'number' ? v : undefined);
  return { form: 'jwt', sub: jws.payload.sub as string | undefined, iat: num(jws.payload.iat), exp: num(jws.payload.exp), ttl: num(jws.payload.ttl),
    bits: Number(sl.bits), lst: base64UrlDecode(sl.lst), chain: Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : [],
    signedBy: (key) => verifyJws(jws, key) };
}

/** COSE_Sign1 over a CWT: typ (16), x5chain (33); claims sub (2), exp (4), iat (6), status_list (65533), ttl (65534). */
function parseCwt(body: Uint8Array): ParsedTokenList {
  const sign1 = parseCoseSign1(cbor.decode(body));
  const typ = sign1.protectedHeader.get(16) ?? sign1.unprotectedHeader.get(16);
  if (typ !== 'application/statuslist+cwt' && typ !== 'statuslist+cwt') throw new Error(`Unexpected status list typ ${String(typ)}`);
  if (!sign1.payload) throw new Error('Status list CWT has a detached payload');
  const claims = cbor.decode(sign1.payload);
  const sl = cbor.mapGet(claims, 65533);
  const lst = cbor.mapGet(sl, 'lst');
  if (!(lst instanceof Uint8Array)) throw new Error('Status list CWT has no status_list');
  const alg = coseAlgToJose(Number(sign1.protectedHeader.get(1)));
  const toBeSigned = cbor.encode(['Signature1', sign1.protectedBytes, new Uint8Array(), sign1.payload]);
  const num = (k: number) => {
    const v = cbor.mapGet(claims, k);
    return v === undefined ? undefined : Number(v instanceof cbor.Tagged ? v.value : v);
  };
  return { form: 'cwt', sub: cbor.mapGet(claims, 2) as string | undefined, iat: num(6), exp: num(4), ttl: num(65534),
    bits: Number(cbor.mapGet(sl, 'bits')), lst, chain: coseX5chain(sign1).map((c) => base64Encode(c)),
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
  const subject = parseCertificate(chain[0]!).subject;
  if (ctx.validateChain) {
    const r = await ctx.validateChain(chain, 'status-list').catch(() => null);
    if (r?.valid) return { ok: true, detail: 'a trusted status list provider' };
  }
  return { ok: false, detail: subject };
}

function anchorCertificate(d?: TrustDecision | null): string | undefined {
  const c = (d?.evidence?.x509?.anchor as { certificate?: unknown } | undefined)?.certificate;
  if (typeof c === 'string') return c;
  const nested = (c as { certificate?: unknown } | undefined)?.certificate;
  return typeof nested === 'string' ? nested : undefined;
}

// ---- W3C Bitstring Status List -------------------------------------------------------------------------------

/**
 * A {@code BitstringStatusListEntry} (or the older {@code StatusList2021Entry}). The list credential must verify
 * ({@code verifyListCredential}), come from the credential's issuer, carry the entry's purpose and be within its
 * validity period. {@code statusSize} > 1 entries ({@code statusPurpose: 'message'}) report the value as unknown.
 */
export async function checkBitstringStatus(entry: Record<string, unknown>, ctx: StatusContext & { verifyListCredential?: ListCredentialVerifier }): Promise<StatusResult> {
  const url = String(entry.statusListCredential ?? '');
  const index = Number(entry.statusListIndex);
  const purpose = String(entry.statusPurpose ?? 'revocation');
  const size = Number(entry.statusSize ?? 1);
  if (!url || !Number.isInteger(index) || index < 0 || !Number.isInteger(size) || size < 1) return unknown('Malformed status entry');
  let fetched: FetchedStatusList;
  try {
    fetched = await ctx.fetchList(url, 'application/vc+ld+json, application/vc, application/ld+json, application/json');
  } catch (e) {
    return unknown(`Status list unavailable: ${(e as Error).message}`);
  }
  try {
    const list = JSON.parse(utf8Decode(fetched.body)) as Record<string, unknown> & { credentialSubject?: Record<string, unknown> };
    if (ctx.verifyListCredential) {
      const v = await ctx.verifyListCredential(list);
      if (!v.ok) return unknown(`Status list credential ${url} does not verify: ${v.detail}`);
    }
    const listIssuer = typeof list.issuer === 'string' ? list.issuer : (list.issuer as { id?: string } | undefined)?.id;
    if (ctx.issuer && listIssuer !== ctx.issuer) return unknown(`Status list is issued by ${listIssuer}, not by the credential issuer`);
    const subject = list.credentialSubject ?? {};
    const purposes = [subject.statusPurpose].flat().map(String);
    if (subject.statusPurpose !== undefined && !purposes.includes(purpose)) {
      return unknown(`Status list purpose ${purposes.join(',')} does not match ${purpose}`);
    }
    const now = ctx.now ?? new Date();
    const until = list.validUntil ?? list.expirationDate;
    if (until && new Date(String(until)) < now) return unknown(`Status list expired ${String(until)}`);
    const from = list.validFrom ?? list.issuanceDate;
    if (from && new Date(String(from)).getTime() > now.getTime() + 300_000) return unknown('Status list is not yet valid');
    const encoded = subject.encodedList;
    if (typeof encoded !== 'string') return unknown('Status list has no encodedList');
    const raw = gunzipSync(base64UrlDecode(encoded.startsWith('u') ? encoded.slice(1) : encoded));
    const bitPos = index * size;
    if (((bitPos + size - 1) >> 3) >= raw.length) return unknown('Status index out of bounds');
    let value = 0;
    for (let i = 0; i < size; i++) value = (value << 1) | ((raw[(bitPos + i) >> 3]! >> (7 - ((bitPos + i) & 7))) & 1);
    const ttlMs = Math.min(MAX_TTL_MS, typeof subject.ttl === 'number' ? subject.ttl : DEFAULT_TTL_MS,
      until ? new Date(String(until)).getTime() - now.getTime() : MAX_TTL_MS);
    const checked = ctx.verifyListCredential ? ', list proof verified' : '';
    if (size > 1 || purpose === 'message') return { status: 'unknown', detail: `Status message ${value} at ${index} in ${url}${via(fetched)}`, value, ttlMs };
    if (value) return { status: purpose === 'suspension' ? 'suspended' : 'revoked', detail: `Bit ${index} set in ${url} (${purpose}${checked})${via(fetched)}`, value, ttlMs };
    return { status: 'valid', detail: `Bit ${index} clear in ${url} (${purpose}${checked})${via(fetched)}`, value, ttlMs };
  } catch (e) {
    return unknown(`Status check failed: ${(e as Error).message}`);
  }
}
