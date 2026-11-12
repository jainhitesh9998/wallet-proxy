/**
 * Credential status: IETF Token Status List (draft-ietf-oauth-status-list) in JWT form for SD-JWT VC and CWT form for
 * ISO mdoc, and W3C Bitstring Status List v1.0. The caller supplies the fetcher (the trust client fetches from the
 * issuer, or through the service's relay); every list is verified here, so neither a relay nor a cache is trusted:
 * signature, signer, subject, freshness, and for Bitstring lists the list credential's proof, issuer and purpose.
 */
import { Gunzip, Unzlib } from 'fflate';
import type { FetchedStatusList } from '../client.js';
import { coseX5chain, parseCoseSign1 } from '../credential/extract.js';
import { coseAlgToJose, verifySignature } from '../crypto/verify.js';
import type { PublicKey } from '../crypto/keys.js';
import * as cbor from '../encoding/cbor.js';
import { decodeJws, verifyJws } from '../jose/jws.js';
import type { PathValidationResult, TrustDecision } from '../types.js';
import { base64Encode, base64UrlDecode, utf8Decode } from '../util/bytes.js';
import { parseCertificate } from '../x509/certificate.js';
import { validateCertificateChain, type LocalAnchor } from '../x509/validate.js';

export interface StatusResult {
  status: 'valid' | 'revoked' | 'suspended' | 'unknown';
  detail: string;
  /** the raw status value (Token Status List) or bit (Bitstring) */
  value?: number;
  /** how long the verified list may be reused: its ttl, bounded by its expiry */
  ttlMs?: number;
}

export type StatusListFetcher = (uri: string, accept: string) => Promise<FetchedStatusList>;

/** Largest decompressed status list accepted (128 M one-bit entries); anything bigger is refused, not inflated. */
export const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/**
 * Inflates a status list without letting a small input expand without bound: the input goes in 1 KiB at a time, so
 * each step yields at most about 1 MiB, and inflation stops once the output passes the limit.
 */
export function inflateCapped(data: Uint8Array, kind: 'zlib' | 'gzip', max = MAX_STATUS_LIST_BYTES): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  const stream = kind === 'gzip' ? new Gunzip() : new Unzlib();
  stream.ondata = (chunk) => {
    total += chunk.length;
    if (total > max) throw new Error(`Status list is larger than ${max} bytes when decompressed`);
    parts.push(chunk);
  };
  if (data.length === 0) throw new Error('Status list is empty');
  for (let i = 0; i < data.length; i += 1024) stream.push(data.subarray(i, Math.min(i + 1024, data.length)), i + 1024 >= data.length);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** The credential a status belongs to, and how to fetch and trust its status list. */
export interface StatusContext {
  fetchList: StatusListFetcher;
  /** validates a list signer's chain in a trust domain (the trust client's validateChain) */
  validateChain?: (chain: string[], domain: string) => Promise<PathValidationResult>;
  /**
   * Validates a list signer's chain under the trust anchor the credential's chain validated to, as every chain on the
   * device is validated: revocation included, with the CRLs at hand, the CRL lookups and the rules in force (the trust
   * client supplies it, over validateChainOnDevice). Without it a signer is not accepted through that anchor, since its
   * revocation status cannot be established.
   */
  validateUnderAnchor?: (chain: string[], anchor: LocalAnchor, time?: Date) => Promise<PathValidationResult>;
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
/**
 * How long a status list that states no end of validity (a Token Status List without {@code exp}, a Bitstring Status
 * List credential without {@code validUntil}) is accepted after its {@code iat} / {@code validFrom}. Without a limit
 * an old list, from before a revocation, could be replayed forever.
 */
export const MAX_STATUS_LIST_AGE_MS = 7 * 24 * 3600_000;
/** W3C Bitstring Status List v1.0, section 3.2 (Validate Algorithm): the minimum number of entries of a list. */
export const MIN_BITSTRING_ENTRIES = 131_072;
const CLOCK_SKEW_MS = 300_000;
const days = (ms: number) => ms / (24 * 3600_000);
const via = (l: FetchedStatusList) => (l.source === 'proxy' ? ' (via the trust service relay)' : l.source === 'cache' ? ' (cached)' : '');
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
  if (!ref?.uri || !Number.isSafeInteger(ref.idx) || ref.idx < 0) return unknown('Malformed status_list reference');
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
    for (const [name, v] of [['exp', list.exp], ['iat', list.iat], ['ttl', list.ttl]] as const) {
      if (v !== undefined && !Number.isFinite(v)) return unknown(`Status list token has an invalid ${name}`);
    }
    if (list.exp !== undefined && list.exp < now) return unknown(`Status list token expired at ${new Date(list.exp * 1000).toISOString()}`);
    if (list.iat !== undefined && list.iat > now + CLOCK_SKEW_MS / 1000) return unknown('Status list token is issued in the future');
    // No exp: the list is accepted for a limited time after it was issued, and not at all when it does not say when.
    let remainingMs = list.exp !== undefined ? (list.exp - now) * 1000 : MAX_TTL_MS;
    if (list.exp === undefined) {
      if (list.iat === undefined) return unknown('Status list token states neither exp nor iat, so its age cannot be established');
      remainingMs = list.iat * 1000 + MAX_STATUS_LIST_AGE_MS - now * 1000;
      if (remainingMs < 0) {
        return unknown(`Status list token has no exp and was issued more than ${days(MAX_STATUS_LIST_AGE_MS)} days ago (${new Date(list.iat * 1000).toISOString()})`);
      }
    }
    if (![1, 2, 4, 8].includes(list.bits)) return unknown(`Status list has an invalid bits value ${list.bits}`);
    const data = inflateCapped(list.lst, 'zlib');
    // Plain arithmetic on safe integers, bounds first: shifts and multiplications would wrap at 32 bits, and an
    // index beyond the list would then read some other entry.
    const perByte = 8 / list.bits;
    const byteIndex = Math.floor(ref.idx / perByte);
    if (byteIndex >= data.length) return unknown('Status index out of bounds');
    const value = (data[byteIndex]! >> ((ref.idx % perByte) * list.bits)) & ((1 << list.bits) - 1);
    const ttlMs = Math.min(MAX_TTL_MS, list.ttl !== undefined ? list.ttl * 1000 : DEFAULT_TTL_MS, remainingMs);
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
 *
 * A certificate under the credential's anchor is validated like every other chain on the device, revocation included
 * (StatusContext.validateUnderAnchor): a revoked or suspended signer could otherwise still say "valid" of a revoked
 * credential, and an unknown signer status is refused when the rules in force require a known one.
 */
async function signerTrust(chain: string[], ctx: StatusContext): Promise<{ ok: boolean; detail: string }> {
  if (ctx.signerX5c?.[0] && ctx.signerX5c[0] === chain[0]) return { ok: true, detail: 'the credential signer' };
  const anchor = credentialAnchor(ctx.decision);
  let refused: string | undefined;
  if (anchor) {
    // Without a validator that can check revocation, the signer's status cannot be established: as a rule that requires it.
    const r = ctx.validateUnderAnchor ? await ctx.validateUnderAnchor(chain, anchor, ctx.now).catch(() => null)
      : validateCertificateChain(chain, [anchor], { time: ctx.now, revocation: { crls: [], require: true } });
    if (r?.valid) return { ok: true, detail: `issued under the credential's trust anchor ${anchor.certificate.subject}`.trim() };
    refused = r?.issues.find((i) => i.severity === 'ERROR')?.message;
  }
  const subject = parseCertificate(chain[0]!).subject;
  if (ctx.validateChain) {
    const r = await ctx.validateChain(chain, 'status-list').catch(() => null);
    if (r?.valid) return { ok: true, detail: 'a trusted status list provider' };
  }
  return { ok: false, detail: refused ? `${subject} (${refused})` : subject };
}

/**
 * The trust anchor the credential's chain validated to, as its decision describes it: the certificate, and the record's
 * status and constraints (among them where its CA publishes its CRL, crlUrls).
 */
function credentialAnchor(d?: TrustDecision | null): LocalAnchor | undefined {
  const a = d?.evidence?.x509?.anchor as { certificate?: unknown; status?: unknown; constraints?: unknown } | undefined;
  const c = a?.certificate;
  const der = typeof c === 'string' ? c : (c as { certificate?: unknown } | undefined)?.certificate;
  if (typeof der !== 'string') return undefined;
  return { certificate: parseCertificate(der), domain: 'status-list', status: typeof a?.status === 'string' ? a.status : undefined,
    constraints: a?.constraints && typeof a.constraints === 'object' ? a.constraints as Record<string, unknown> : {} };
}

// ---- W3C Bitstring Status List -------------------------------------------------------------------------------

/** A non-negative integer given as a number or, as the W3C data model writes indexes, as a base-10 string. */
function nonNegativeInteger(v: unknown): number | undefined {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v) ? Number(v) : NaN;
  return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
}

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);

/** A date-time string of a credential as epoch milliseconds: undefined when absent, NaN when it is not a date. */
function dateTime(v: unknown): number | undefined {
  if (v === undefined || v === null) return undefined;
  return typeof v === 'string' ? Date.parse(v) : NaN;
}

/**
 * A {@code BitstringStatusListEntry} (W3C Bitstring Status List v1.0) or the older {@code StatusList2021Entry}.
 *
 * The list is a credential anyone can serve, so it counts only when it is verified: {@code verifyListCredential}
 * (its proof) and {@code issuer} (who must have issued it: the credential's issuer) are both required, and without
 * them the answer is {@code unknown}. The list must then be a status list of the entry's kind, carry the entry's
 * {@code statusPurpose}, be within its validity period (or, when it states no end, not older than
 * {@link MAX_STATUS_LIST_AGE_MS}), and hold at least {@link MIN_BITSTRING_ENTRIES} entries.
 * {@code statusSize} > 1 entries ({@code statusPurpose: 'message'}) report the value as unknown.
 */
export async function checkBitstringStatus(entry: Record<string, unknown>, ctx: StatusContext & { verifyListCredential?: ListCredentialVerifier }): Promise<StatusResult> {
  const url = typeof entry?.statusListCredential === 'string' ? entry.statusListCredential : '';
  const index = nonNegativeInteger(entry?.statusListIndex);
  const size = entry?.statusSize === undefined ? 1 : nonNegativeInteger(entry.statusSize);
  const entryTypes = asList(entry?.type);
  const kind = entryTypes.includes('BitstringStatusListEntry') ? 'BitstringStatusList' : entryTypes.includes('StatusList2021Entry') ? 'StatusList2021' : undefined;
  if (!url || index === undefined || size === undefined || size < 1 || size > 32) return unknown('Malformed status entry');
  if (!kind) return unknown('Malformed status entry: its type is not BitstringStatusListEntry');
  const purpose = entry.statusPurpose;
  if (typeof purpose !== 'string' || purpose === '') return unknown('Malformed status entry: it has no statusPurpose');
  if (!ctx?.verifyListCredential || !ctx.issuer) {
    const missing = [!ctx?.verifyListCredential ? 'a verifier for the list credential\'s proof' : '', !ctx?.issuer ? 'the issuer the list must come from' : ''].filter(Boolean).join(' and ');
    return unknown(`Status list ${url} could not be verified: ${missing} was not supplied`);
  }
  let fetched: FetchedStatusList;
  try {
    fetched = await ctx.fetchList(url, 'application/vc+ld+json, application/vc, application/ld+json, application/json');
  } catch (e) {
    return unknown(`Status list unavailable: ${(e as Error).message}`);
  }
  try {
    const list = JSON.parse(utf8Decode(fetched.body)) as Record<string, unknown> & { credentialSubject?: Record<string, unknown> };
    if (list === null || typeof list !== 'object' || Array.isArray(list)) return unknown(`Status list ${url} is not a credential`);
    const v = await ctx.verifyListCredential(list);
    if (!v.ok) return unknown(`Status list credential ${url} does not verify: ${v.detail}`);
    const listIssuer = typeof list.issuer === 'string' ? list.issuer : (list.issuer as { id?: string } | undefined)?.id;
    if (listIssuer !== ctx.issuer) return unknown(`Status list is issued by ${listIssuer}, not by the credential issuer`);
    if (!asList(list.type).includes(`${kind}Credential`)) return unknown(`Status list ${url} is not a ${kind}Credential`);
    const subject = list.credentialSubject;
    if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) return unknown(`Status list ${url} has no credentialSubject`);
    if (!asList(subject.type).includes(kind)) return unknown(`Status list credentialSubject type is ${asList(subject.type).join(',') || 'missing'}, not ${kind}`);
    const purposes = asList(subject.statusPurpose).filter((x): x is string => typeof x === 'string');
    if (!purposes.includes(purpose)) return unknown(`Status list purpose ${purposes.join(',') || '(none)'} does not match ${purpose}`);
    const now = (ctx.now ?? new Date()).getTime();
    const until = dateTime(list.validUntil ?? list.expirationDate);
    const from = dateTime(list.validFrom ?? list.issuanceDate);
    if (Number.isNaN(until) || Number.isNaN(from)) return unknown('Status list has an invalid validity period');
    if (until !== undefined && until < now) return unknown(`Status list expired ${String(list.validUntil ?? list.expirationDate)}`);
    if (from !== undefined && from > now + CLOCK_SKEW_MS) return unknown('Status list is not yet valid');
    // No end of validity: the list is accepted for a limited time after validFrom, and not at all when it has neither.
    let remainingMs = until !== undefined ? until - now : MAX_TTL_MS;
    if (until === undefined) {
      if (from === undefined) return unknown('Status list states neither validUntil nor validFrom, so its age cannot be established');
      remainingMs = from + MAX_STATUS_LIST_AGE_MS - now;
      if (remainingMs < 0) return unknown(`Status list has no validUntil and is valid from more than ${days(MAX_STATUS_LIST_AGE_MS)} days ago (${new Date(from).toISOString()})`);
    }
    const encoded = subject.encodedList;
    if (typeof encoded !== 'string') return unknown('Status list has no encodedList');
    const raw = inflateCapped(base64UrlDecode(encoded.startsWith('u') ? encoded.slice(1) : encoded), 'gzip');
    const entries = Math.floor((raw.length * 8) / size);
    if (entries < MIN_BITSTRING_ENTRIES) return unknown(`Status list has ${entries} entries, fewer than the minimum of ${MIN_BITSTRING_ENTRIES}`);
    // Bounds before any arithmetic on the index: index * size must not leave the safe integer range.
    if (index >= entries) return unknown('Status index out of bounds');
    const bitPos = index * size;
    let value = 0;
    for (let i = 0; i < size; i++) value = value * 2 + ((raw[Math.floor((bitPos + i) / 8)]! >> (7 - ((bitPos + i) % 8))) & 1);
    const ttlMs = Math.min(MAX_TTL_MS, typeof subject.ttl === 'number' && subject.ttl >= 0 ? subject.ttl : DEFAULT_TTL_MS, remainingMs);
    const checked = ', list proof verified';
    if (size > 1 || purpose === 'message') return { status: 'unknown', detail: `Status message ${value} at ${index} in ${url}${via(fetched)}`, value, ttlMs };
    if (value) return { status: purpose === 'suspension' ? 'suspended' : 'revoked', detail: `Bit ${index} set in ${url} (${purpose}${checked})${via(fetched)}`, value, ttlMs };
    return { status: 'valid', detail: `Bit ${index} clear in ${url} (${purpose}${checked})${via(fetched)}`, value, ttlMs };
  } catch (e) {
    return unknown(`Status check failed: ${(e as Error).message}`);
  }
}
