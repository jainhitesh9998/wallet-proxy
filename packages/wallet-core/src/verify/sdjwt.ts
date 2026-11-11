/**
 * SD-JWT VC (format dc+sd-jwt) as HAIP 1.0 profiles it: the issuer signs with a key certified by an X.509 chain in
 * the x5c header (HAIP §6.1.1), the holder key is in cnf.jwk, status is a Token Status List.
 *
 * The SD-JWT itself is processed by the rules of RFC 9901 §7.1, which say when it MUST be rejected: a disclosure
 * nothing refers to, a digest that occurs twice, a disclosed name that collides with a claim or is reserved, a
 * disclosure of the wrong shape. The claims a verifier relies on unseen (iss, nbf, exp, cnf, vct, status) must not
 * be selectively disclosable (SD-JWT VC §3.2.2.2).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import type { Jwk, TrustClient, TrustDecision } from '@vctrust/trust-client';
import { bytes, decodeJws, extractIssuerInfo, issuerTrustQuery, jwkThumbprint, parseCertificate, verifyJws, verifyX509Signature,
  type IssuerInfo, type PublicKey } from '@vctrust/trust-client/primitives';
import { Checks, finish, type VerificationReport } from './report.js';

export interface ParsedSdJwt {
  issuerJwt: string;
  disclosures: string[];
  /** the key binding JWT of a presentation; an SD-JWT as issued has none */
  kbJwt?: string;
}

/** Splits {@code <issuer JWT>~<disclosure>~...~[<KB-JWT>]}; the trailing '~' of an SD-JWT without key binding is required. */
export function parseSdJwt(s: string): ParsedSdJwt {
  const parts = s.split('~');
  if (parts.length < 2) throw new Error('Not an SD-JWT: no "~" separator');
  const last = parts[parts.length - 1]!;
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => d === '')) throw new Error('Not an SD-JWT: empty disclosure');
  return { issuerJwt: parts[0]!, disclosures, ...(last !== '' ? { kbJwt: last } : {}) };
}

export function disclosureDigest(disclosure: string): string {
  return bytes.base64UrlEncode(sha256(bytes.utf8Encode(disclosure)));
}

export interface Disclosure {
  raw: string;
  digest: string;
  salt: string;
  /** the claim name of an object property disclosure; undefined for an array element */
  name?: string;
  value: unknown;
}

/** RFC 9901 §4.2: a disclosure is a JSON array [salt, name, value] (object property) or [salt, value] (array element). */
export function decodeDisclosure(raw: string): Disclosure {
  let arr: unknown;
  try {
    arr = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(raw)));
  } catch {
    throw new Error('A disclosure is not base64url-encoded JSON');
  }
  if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3) || typeof arr[0] !== 'string') throw new Error('A disclosure is not [salt, name, value] or [salt, value]');
  if (arr.length === 2) return { raw, digest: disclosureDigest(raw), salt: arr[0], value: arr[1] };
  if (typeof arr[1] !== 'string') throw new Error('A disclosure\'s claim name is not a string');
  return { raw, digest: disclosureDigest(raw), salt: arr[0], name: arr[1], value: arr[2] };
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * RFC 9901 §7.1 step 3: replaces the digests with the disclosed claims and removes the SD-JWT bookkeeping. Throws
 * where the specification says the SD-JWT MUST be rejected. {@code used} are the digests that had a disclosure.
 */
export function reconstruct(payload: Record<string, unknown>, disclosures: Disclosure[]): { claims: Record<string, unknown>; used: Set<string> } {
  const byDigest = new Map<string, Disclosure>();
  for (const d of disclosures) {
    if (byDigest.has(d.digest)) throw new Error('A disclosure is given twice');
    byDigest.set(d.digest, d);
  }
  const seen = new Set<string>();
  const used = new Set<string>();
  const refer = (digest: unknown): Disclosure | undefined => {
    if (typeof digest !== 'string') throw new Error('A digest is not a string');
    if (seen.has(digest)) throw new Error('A digest occurs more than once');
    seen.add(digest);
    const d = byDigest.get(digest);
    if (d) used.add(digest);
    return d;
  };
  const walk = (v: unknown, top = false): unknown => {
    if (Array.isArray(v)) {
      const out: unknown[] = [];
      for (const e of v) {
        if (isObject(e) && '...' in e) {
          if (Object.keys(e).length !== 1) throw new Error('"..." is reserved for array element digests');
          const d = refer(e['...']);
          // A digest without a disclosure is an element that was not disclosed (or a decoy): it is left out.
          if (!d) continue;
          if (d.name !== undefined) throw new Error('An array element digest refers to an object property disclosure');
          out.push(walk(d.value));
        } else out.push(walk(e));
      }
      return out;
    }
    if (!isObject(v)) return v;
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === '...') throw new Error('"..." is reserved for array element digests');
      if (k === '_sd_alg') {
        if (!top) throw new Error('_sd_alg is allowed at the top level only');
        continue;
      }
      if (k !== '_sd') out[k] = walk(x);
    }
    if ('_sd' in v) {
      if (!Array.isArray(v._sd)) throw new Error('_sd is not an array');
      for (const digest of v._sd) {
        const d = refer(digest);
        if (!d) continue;
        if (d.name === undefined) throw new Error('An _sd digest refers to an array element disclosure');
        if (d.name === '_sd' || d.name === '...') throw new Error(`A disclosure uses the reserved claim name ${d.name}`);
        if (Object.prototype.hasOwnProperty.call(out, d.name) || Object.prototype.hasOwnProperty.call(v, d.name)) throw new Error(`The disclosed claim ${d.name} already exists at its level`);
        out[d.name] = walk(d.value);
      }
    }
    return out;
  };
  const claims = walk(payload, true) as Record<string, unknown>;
  const unreferenced = disclosures.filter((d) => !used.has(d.digest)).length;
  if (unreferenced) throw new Error(`${unreferenced} disclosure(s) are not referenced by the issuer-signed JWT`);
  return { claims, used };
}

/** Claims that must be in the issuer-signed JWT itself, never in a disclosure (SD-JWT VC §3.2.2.2). */
const NOT_DISCLOSABLE = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status'];

export interface SdJwtVerifyOptions {
  trust: TrustClient;
  /** the key this wallet proved to the issuer */
  holderJwk?: Jwk;
  now?: Date;
  checkStatus?: boolean;
  /** what the wallet asked for: the configuration's vct */
  expected?: { vct?: string };
}

/** The signer's key from the x5c header, with what HAIP §6.1.1 requires of that chain. */
function signer(header: Record<string, unknown>): { key: PublicKey; subject: string; dnsNames: string[]; uriNames: string[] } {
  if (!Array.isArray(header.x5c) || header.x5c.length === 0 || !header.x5c.every((c) => typeof c === 'string')) {
    throw new Error('No x5c header: this wallet verifies SD-JWT VCs signed with an X.509 certified key (HAIP §6.1.1)');
  }
  const chain = (header.x5c as string[]).map((c) => parseCertificate(c));
  for (const c of chain) {
    if (c.subject === c.issuer && c.publicKey && verifyX509Signature(c, c.publicKey)) {
      throw new Error('x5c contains a self-signed certificate; the trust anchor must not be sent and the signing certificate must not be self-signed (HAIP §6.1.1)');
    }
  }
  const leaf = chain[0]!;
  if (!leaf.publicKey) throw new Error(`Unsupported signing key ${leaf.publicKeyAlgorithm}`);
  return { key: leaf.publicKey, subject: leaf.subject, dnsNames: leaf.dnsNames, uriNames: leaf.uriNames };
}

export async function verifySdJwtVc(credential: string, opts: SdJwtVerifyOptions): Promise<VerificationReport> {
  const checks = new Checks();
  const now = opts.now ?? new Date();
  const nowS = Math.floor(now.getTime() / 1000);
  let claims: Record<string, unknown> = {};
  let issuerInfo: IssuerInfo = { format: 'dc+sd-jwt' };
  let vct: string | undefined;
  let status: unknown;
  let signerKey: PublicKey | undefined;
  let validUntil: string | undefined;
  try {
    const { issuerJwt, disclosures, kbJwt } = parseSdJwt(String(credential));
    if (kbJwt) throw new Error('An issued SD-JWT VC carries no key binding JWT');
    const jws = decodeJws<Record<string, unknown>>(issuerJwt);
    issuerInfo = extractIssuerInfo(credential, 'dc+sd-jwt');
    // SD-JWT VC §3.2.1: typ MUST be dc+sd-jwt.
    if (jws.header.typ === 'dc+sd-jwt') checks.pass('sdjwt.typ', 'Media type', 'dc+sd-jwt');
    else checks.fail('sdjwt.typ', 'Media type', `typ is ${String(jws.header.typ)}; dc+sd-jwt is required`);

    const s = signer(jws.header);
    signerKey = s.key;
    if (verifyJws(jws, s.key)) checks.pass('sdjwt.signature', 'Issuer signature', `${String(jws.header.alg)}, key certified for ${s.subject}`);
    else checks.fail('sdjwt.signature', 'Issuer signature', 'The signature does not verify with the x5c certificate\'s key');
    const iss = jws.payload.iss;
    if (iss !== undefined) {
      // With x5c the issuer is whom the certificate names; an iss that names someone else is at least misleading.
      const host = typeof iss === 'string' ? /^https:\/\/([^/:?#]+)/.exec(iss)?.[1] : undefined;
      if (typeof iss === 'string' && (s.uriNames.includes(iss) || (host && s.dnsNames.includes(host)))) checks.pass('sdjwt.iss', 'Issuer name', `${iss} is named by the signing certificate`);
      else checks.warn('sdjwt.iss', 'Issuer name', `iss ${String(iss)} is not a name in the signing certificate; the issuer is ${s.subject}`);
    }

    // RFC 9901 §7.1: the hash algorithm, then disclosures and digests.
    if (jws.payload._sd_alg !== undefined && jws.payload._sd_alg !== 'sha-256') throw new Error(`Unsupported _sd_alg ${String(jws.payload._sd_alg)} (HAIP requires sha-256)`);
    const decoded = disclosures.map(decodeDisclosure);
    claims = reconstruct(jws.payload, decoded).claims;
    const hidden = NOT_DISCLOSABLE.filter((n) => !Object.prototype.hasOwnProperty.call(jws.payload, n) && Object.prototype.hasOwnProperty.call(claims, n));
    if (hidden.length) throw new Error(`${hidden.join(', ')} must not be selectively disclosable (SD-JWT VC §3.2.2.2)`);
    checks.pass('sdjwt.disclosures', 'Disclosures', `${decoded.length} disclosure(s), each referenced once by the issuer-signed JWT`);

    vct = typeof jws.payload.vct === 'string' && jws.payload.vct ? jws.payload.vct : undefined;
    if (!vct) checks.fail('sdjwt.vct', 'Credential type', 'vct is missing');
    else if (opts.expected?.vct !== undefined && opts.expected.vct !== vct) checks.fail('sdjwt.vct', 'Credential type', `vct ${vct} is not the requested ${opts.expected.vct}`);
    else checks.pass('sdjwt.vct', 'Credential type', vct);

    const { exp, nbf } = jws.payload;
    if ((exp !== undefined && typeof exp !== 'number') || (nbf !== undefined && typeof nbf !== 'number')) checks.fail('sdjwt.validity', 'Validity period', 'exp / nbf are not numbers');
    else if (typeof exp === 'number' && nowS >= exp) checks.fail('sdjwt.validity', 'Validity period', `Expired ${new Date(exp * 1000).toISOString()}`);
    else if (typeof nbf === 'number' && nowS < nbf) checks.fail('sdjwt.validity', 'Validity period', `Not valid before ${new Date(nbf * 1000).toISOString()}`);
    else checks.pass('sdjwt.validity', 'Validity period', typeof exp === 'number' ? `until ${new Date(exp * 1000).toISOString()}` : 'no expiry');
    if (typeof exp === 'number') validUntil = new Date(exp * 1000).toISOString();

    // HAIP §6.1: the holder key is a JWK in cnf (RFC 7800).
    const cnf = jws.payload.cnf;
    const bound = isObject(cnf) && isObject(cnf.jwk) ? cnf.jwk as unknown as Jwk : undefined;
    if (!bound) {
      if (opts.holderJwk) checks.fail('sdjwt.holder', 'Holder binding', 'No cnf.jwk, although the wallet proved a key to the issuer');
      else checks.warn('sdjwt.holder', 'Holder binding', 'No cnf.jwk: the credential is not bound to a holder key');
    } else if (opts.holderJwk && jwkThumbprint(bound) !== jwkThumbprint(opts.holderJwk)) checks.fail('sdjwt.holder', 'Holder binding', 'cnf.jwk is not the key this wallet proved');
    else checks.pass('sdjwt.holder', 'Holder binding', opts.holderJwk ? 'cnf.jwk is this wallet\'s key' : 'cnf.jwk');
    status = jws.payload.status;
  } catch (e) {
    checks.fail('sdjwt.structure', 'Credential structure', (e as Error).message.slice(0, 300));
  }

  let trust: TrustDecision | null = null;
  if (issuerInfo.x5c?.length) trust = await opts.trust.evaluate(issuerTrustQuery(issuerInfo));

  if (status !== undefined && opts.checkStatus !== false) {
    const ref = isObject(status) && isObject(status.status_list) ? status.status_list : undefined;
    if (!ref || !Number.isSafeInteger(ref.idx) || (ref.idx as number) < 0 || typeof ref.uri !== 'string') {
      checks.fail('sdjwt.status', 'Status', 'status carries no usable status_list reference (HAIP §6.1)');
    } else {
      const s = await opts.trust.checkTokenStatus({ idx: ref.idx as number, uri: ref.uri }, { signerX5c: issuerInfo.x5c, signerKey, decision: trust, now });
      if (s.status === 'valid') checks.pass('sdjwt.status', 'Status', s.detail);
      else if (s.status === 'unknown') checks.warn('sdjwt.status', 'Status', s.detail);
      else checks.fail('sdjwt.status', 'Status', `${s.status}: ${s.detail}`);
    }
  }
  return finish('dc+sd-jwt', checks, issuerInfo, trust, claims, { credentialType: vct, validUntil });
}
