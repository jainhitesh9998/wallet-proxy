/**
 * IETF SD-JWT VC (draft -13 as pinned by HAIP): issuer signature (x5c chain, DID kid or JWT VC Issuer
 * Metadata), disclosure digests, validity, cnf holder binding, Token Status List; issuer trust via the client.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytes, decodeJws, verifyJws, parseCertificate, publicKeyToJwk, publicKeyFromMulticodec, decodeMultibase, findVerificationMethod, verificationMethodPublicKey, wellKnownInserted,
  extractIssuerInfo, issuerTrustQuery, type TrustClient, type Jwk, type PublicKey } from '@vctrust/trust-client';
import { checkTokenStatus, type StatusListReference } from './status.js';
import { Checks, finish, type VerificationReport } from './report.js';

export interface ParsedSdJwt {
  issuerJwt: string;
  disclosures: string[];
  kbJwt?: string;
}

export function parseSdJwt(s: string): ParsedSdJwt {
  const parts = s.split('~');
  const issuerJwt = parts[0]!;
  const last = parts[parts.length - 1]!;
  const kbJwt = last !== '' && parts.length > 1 ? last : undefined;
  const disclosures = parts.slice(1, kbJwt ? -1 : parts.length - 1).filter(Boolean);
  return { issuerJwt, disclosures, kbJwt };
}

/** The public key a did:jwk or did:key (or a DID URL of one) names, read without resolution; undefined for other DIDs. */
export function didPublicKey(did: string): Jwk | undefined {
  const id = did.split('#')[0]!;
  try {
    if (id.startsWith('did:key:')) return publicKeyToJwk(publicKeyFromMulticodec(decodeMultibase(id.slice('did:key:'.length))));
    if (!id.startsWith('did:jwk:')) return undefined;
    const jwk = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(id.slice('did:jwk:'.length)))) as Jwk;
    return typeof jwk.kty === 'string' && !('d' in jwk) ? jwk : undefined;
  } catch {
    return undefined;
  }
}

export function disclosureDigest(disclosure: string): string {
  return bytes.base64UrlEncode(sha256(bytes.utf8Encode(disclosure)));
}

export interface Disclosure {
  raw: string;
  digest: string;
  salt: string;
  name?: string;
  value: unknown;
}

export function decodeDisclosure(raw: string): Disclosure {
  const arr = JSON.parse(bytes.utf8Decode(bytes.base64UrlDecode(raw))) as unknown[];
  return arr.length === 3
    ? { raw, digest: disclosureDigest(raw), salt: String(arr[0]), name: String(arr[1]), value: arr[2] }
    : { raw, digest: disclosureDigest(raw), salt: String(arr[0]), value: arr[1] };
}

/** Rebuilds the full claim set; returns the claims and the digests that were referenced. */
export function reconstruct(payload: Record<string, unknown>, disclosures: Disclosure[]): { claims: Record<string, unknown>; used: Set<string> } {
  const byDigest = new Map(disclosures.map((d) => [d.digest, d]));
  const used = new Set<string>();
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      const out: unknown[] = [];
      for (const e of v) {
        if (e && typeof e === 'object' && !Array.isArray(e) && Object.keys(e).length === 1 && '...' in e) {
          const d = byDigest.get(String((e as Record<string, unknown>)['...']));
          if (d) { used.add(d.digest); out.push(walk(d.value)); }
        } else out.push(walk(e));
      }
      return out;
    }
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (k === '_sd') {
          for (const dg of x as string[]) {
            const d = byDigest.get(dg);
            if (d?.name !== undefined) { used.add(d.digest); out[d.name] = walk(d.value); }
          }
        } else if (k !== '_sd_alg') out[k] = walk(x);
      }
      return out;
    }
    return v;
  };
  return { claims: walk(payload) as Record<string, unknown>, used };
}

async function issuerKey(header: Record<string, unknown>, payload: Record<string, unknown>, f: typeof fetch, trust?: TrustClient): Promise<{ key: PublicKey; how: string }> {
  if (Array.isArray(header.x5c) && header.x5c.length > 0) {
    const leaf = parseCertificate(String(header.x5c[0]));
    if (!leaf.publicKey) throw new Error('Unsupported x5c key');
    return { key: leaf.publicKey, how: `x5c ${leaf.subject}` };
  }
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const iss = typeof payload.iss === 'string' ? payload.iss : undefined;
  if (kid?.startsWith('did:') || (iss?.startsWith('did:') && kid)) {
    const vmId = kid!.startsWith('did:') ? kid! : `${iss}${kid!.startsWith('#') ? kid : `#${kid}`}`;
    const r = trust ? await trust.resolveDid(vmId) : null;
    const vm = r?.didDocument ? findVerificationMethod(r.didDocument, vmId) : undefined;
    if (!vm) throw new Error(`Cannot dereference ${vmId}`);
    return { key: verificationMethodPublicKey(vm), how: `DID ${vmId}` };
  }
  if (iss?.startsWith('https://')) {
    const r = await f(wellKnownInserted(iss, 'jwt-vc-issuer'));
    if (!r.ok) throw new Error(`No JWT VC Issuer Metadata for ${iss}`);
    const md = (await r.json()) as { issuer?: string; jwks?: { keys: Jwk[] }; jwks_uri?: string };
    if (md.issuer !== iss) throw new Error('JWT VC Issuer Metadata issuer mismatch');
    const jwks = md.jwks ?? (md.jwks_uri ? ((await (await f(md.jwks_uri)).json()) as { keys: Jwk[] }) : undefined);
    const jwk = jwks?.keys.find((k) => !kid || k.kid === kid);
    if (!jwk) throw new Error('Issuer key not found in JWT VC Issuer Metadata');
    const { publicKeyFromJwk } = await import('@vctrust/trust-client');
    return { key: publicKeyFromJwk(jwk), how: `jwt-vc-issuer ${iss}` };
  }
  throw new Error('No way to resolve the issuer key (x5c, DID kid or https iss)');
}

export async function verifySdJwtVc(credential: string, opts: { trust?: TrustClient; fetch?: typeof fetch; holderJwk?: Jwk; holderDid?: string; now?: Date;
  credentialIssuer?: string; checkStatus?: boolean; format?: string }): Promise<VerificationReport> {
  const checks = new Checks();
  const f = opts.fetch ?? fetch;
  const now = opts.now ?? new Date();
  const nowS = Math.floor(now.getTime() / 1000);
  let claims: Record<string, unknown> = {};
  let issuerInfo = { format: 'dc+sd-jwt' } as ReturnType<typeof extractIssuerInfo>;
  let vct: string | undefined;
  let statusRef: StatusListReference | undefined;
  let signerKey: PublicKey | undefined;
  try {
    issuerInfo = extractIssuerInfo(credential, 'dc+sd-jwt');
    const { issuerJwt, disclosures } = parseSdJwt(credential);
    const jws = decodeJws<Record<string, unknown>>(issuerJwt);
    // SD-JWT VC §3.2.1: typ MUST be dc+sd-jwt; vc+sd-jwt is tolerated only for the pre-1.0 format of that name.
    if (jws.header.typ === 'dc+sd-jwt') checks.pass('sdjwt.typ', 'Media type', 'dc+sd-jwt');
    else if (opts.format === 'vc+sd-jwt' && jws.header.typ === 'vc+sd-jwt') checks.warn('sdjwt.typ', 'Media type', 'vc+sd-jwt (pre-1.0 format)');
    else checks.fail('sdjwt.typ', 'Media type', `typ ${String(jws.header.typ)}; dc+sd-jwt is required`);
    const { key, how } = await issuerKey(jws.header, jws.payload, f, opts.trust);
    signerKey = key;
    if (verifyJws(jws, key)) checks.pass('sdjwt.signature', 'Issuer signature', `${String(jws.header.alg)} via ${how}`);
    else checks.fail('sdjwt.signature', 'Issuer signature', 'Signature does not verify');
    if ((jws.payload._sd_alg ?? 'sha-256') !== 'sha-256') throw new Error(`Unsupported _sd_alg ${String(jws.payload._sd_alg)}`);
    const decoded = disclosures.map(decodeDisclosure);
    const r = reconstruct(jws.payload, decoded);
    const unreferenced = decoded.filter((d) => !r.used.has(d.digest));
    if (unreferenced.length) checks.fail('sdjwt.disclosures', 'Disclosures', `${unreferenced.length} disclosure(s) not referenced by the issuer JWT`);
    else checks.pass('sdjwt.disclosures', 'Disclosures', `${decoded.length} disclosure(s) bound to the issuer JWT`);
    claims = r.claims;
    vct = typeof jws.payload.vct === 'string' ? jws.payload.vct : undefined;
    if (!vct) checks.fail('sdjwt.vct', 'Credential type', 'vct is missing');
    const exp = jws.payload.exp as number | undefined;
    const nbf = jws.payload.nbf as number | undefined;
    if ((exp && nowS > exp) || (nbf && nowS < nbf)) checks.fail('sdjwt.validity', 'Validity period', 'Outside exp/nbf');
    else if (!exp && typeof jws.payload.expirationDate === 'string') {
      // VCDM 1.1's claim name: SD-JWT VC does not define it, so verifiers do not enforce it (HAIP §6.1: exp or status).
      checks.warn('sdjwt.validity', 'Validity period', `no exp; the credential states expirationDate ${jws.payload.expirationDate}, which SD-JWT VC does not define`);
    } else checks.pass('sdjwt.validity', 'Validity period', exp ? `until ${new Date(exp * 1000).toISOString()}` : 'no expiry');
    const cnf = jws.payload.cnf as { jwk?: Jwk; kid?: unknown } | undefined;
    const kid = !cnf?.jwk && typeof cnf?.kid === 'string' ? cnf.kid : undefined;
    const bound = cnf?.jwk ?? (kid ? didPublicKey(kid) : undefined);
    const member = cnf?.jwk ? 'cnf.jwk' : 'cnf.kid';
    const ownDid = !!kid && !!opts.holderDid && kid.split('#')[0] === opts.holderDid.split('#')[0];
    if (!cnf?.jwk && !kid) checks.warn('sdjwt.holder', 'Holder binding', 'No cnf key (bearer credential)');
    // A key this wallet cannot read may be anyone's: the credential is not taken as bound to this wallet.
    else if (!bound && !ownDid) checks.fail('sdjwt.holder', 'Holder binding', `cnf.kid ${kid} names a key this wallet cannot read (only did:jwk, did:key or its own DID); HAIP §6.1 requires the key in cnf.jwk`);
    else if (bound && opts.holderJwk && (bound.x !== opts.holderJwk.x || bound.y !== opts.holderJwk.y)) checks.fail('sdjwt.holder', 'Holder binding', `${member} is not this wallet's key`);
    else if (kid) checks.warn('sdjwt.holder', 'Holder binding', `cnf.kid (${bound ? kid.split(':').slice(0, 2).join(':') : 'this wallet\'s DID'}) names ${opts.holderJwk || ownDid ? 'this wallet\'s' : 'the holder'} key; HAIP §6.1 requires the key in cnf.jwk`);
    else checks.pass('sdjwt.holder', 'Holder binding', 'cnf.jwk');
    statusRef = (jws.payload.status as { status_list?: StatusListReference } | undefined)?.status_list;
  } catch (e) {
    checks.fail('sdjwt.parse', 'Credential structure', (e as Error).message);
  }
  const trust = opts.trust ? await opts.trust.evaluate(issuerTrustQuery(issuerInfo, opts.credentialIssuer)) : null;
  if (statusRef && opts.checkStatus !== false) {
    const s = await checkTokenStatus(statusRef, { trust: opts.trust, fetch: f, signerX5c: issuerInfo.x5c, signerKey, decision: trust, now });
    if (s.status === 'valid') checks.pass('sdjwt.status', 'Status', s.detail);
    else if (s.status === 'unknown') checks.warn('sdjwt.status', 'Status', s.detail);
    else checks.fail('sdjwt.status', 'Status', `${s.status}: ${s.detail}`);
  }
  return finish('dc+sd-jwt', checks, issuerInfo, trust, claims, { credentialType: vct });
}
