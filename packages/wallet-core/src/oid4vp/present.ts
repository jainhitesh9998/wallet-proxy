/**
 * Presentation building and response delivery for OpenID4VP 1.0:
 *  - dc+sd-jwt: selected disclosures + KB-JWT (aud = full client_id, nonce, sd_hash)
 *  - mso_mdoc: DeviceResponse with OpenID4VPHandover session transcript and deviceSignature (COSE_Sign1)
 *  - ldp_vc: Verifiable Presentation with an ecdsa-rdfc-2019 holder proof (challenge = nonce, domain = client_id)
 *  - direct_post / direct_post.jwt (ECDH-ES + A128GCM/A256GCM JWE to the verifier's ephemeral key)
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytes, cbor, decodeIssuerSigned, decodeJws, jwkThumbprintBytes, base58Encode, type Jwk } from '@vctrust/trust-client';
import { nowSeconds, signJwt } from '../crypto/jwt.js';
import { encryptJwe, type JweEnc } from '../crypto/jwe.js';
import type { KeyStore, SigningKey } from '../crypto/keys.js';
import { parseSdJwt, decodeDisclosure, type Disclosure } from '../verify/sdjwt.js';
import { issuerSignedItems } from '../verify/mdoc.js';
import { canonize, createDocumentLoader } from '../verify/jsonld.js';
import type { StoredCredential } from '../store/credentials.js';
import { encryptionKey, type AuthorizationRequest, type DcqlClaim } from './request.js';

const { Tagged } = cbor;

function pathsOf(claims: DcqlClaim[]): string[][] {
  return claims.map((c) => c.path.map((p) => String(p)));
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const arrayRef = (e: unknown): string | undefined => (isPlainObject(e) && Object.keys(e).length === 1 && typeof e['...'] === 'string' ? e['...'] : undefined);

/**
 * The disclosures that reveal exactly the claims at the requested DCQL paths (OpenID4VP §6.4, §7): the disclosures
 * on each path and every disclosure below its leaf. A {@code null} segment selects array elements; with
 * {@code values}, only the branches whose leaf matches. No claims requested → no disclosures (§6.4.1).
 */
export function selectDisclosures(payload: Record<string, unknown>, decoded: Disclosure[], claims: DcqlClaim[]): Disclosure[] {
  const byDigest = new Map(decoded.map((d) => [d.digest, d]));
  const subtree = (v: unknown, out: Disclosure[]): Disclosure[] => {
    if (Array.isArray(v)) {
      for (const e of v) {
        const d = byDigest.get(arrayRef(e) ?? '');
        if (d) { out.push(d); subtree(d.value, out); } else subtree(e, out);
      }
    } else if (isPlainObject(v)) {
      for (const digest of Array.isArray(v._sd) ? v._sd : []) {
        const d = byDigest.get(String(digest));
        if (d) { out.push(d); subtree(d.value, out); }
      }
      for (const [k, child] of Object.entries(v)) if (k !== '_sd' && k !== '_sd_alg') subtree(child, out);
    }
    return out;
  };
  /** disclosures needed to reach the matching leaves below {@code v}, or null when nothing matches */
  const follow = (v: unknown, claim: DcqlClaim, i: number): Disclosure[] | null => {
    if (i === claim.path.length) return claim.values && !claim.values.some((w) => w === v) ? null : subtree(v, []);
    const seg = claim.path[i] as string | number | null;
    if (typeof seg === 'string') {
      if (!isPlainObject(v)) return null;
      if (own(v, seg) && seg !== '_sd') return follow(v[seg], claim, i + 1);
      for (const digest of Array.isArray(v._sd) ? v._sd : []) {
        const d = byDigest.get(String(digest));
        if (d?.name === seg) { const below = follow(d.value, claim, i + 1); return below ? [d, ...below] : null; }
      }
      return null;
    }
    if (!Array.isArray(v)) return null;
    // Elements as the holder's claims have them: digests without a disclosure are decoys and do not count as positions.
    const elements = v.flatMap((e): Array<{ d?: Disclosure; value: unknown }> => {
      const ref = arrayRef(e);
      if (ref === undefined) return [{ value: e }];
      const d = byDigest.get(ref);
      return d ? [{ d, value: d.value }] : [];
    });
    const found: Disclosure[] = [];
    let matched = false;
    for (const el of seg === null ? elements : elements.slice(seg, seg + 1)) {
      const below = follow(el.value, claim, i + 1);
      if (below) { matched = true; if (el.d) found.push(el.d); found.push(...below); }
    }
    return matched ? found : null;
  };
  const selected = new Set<Disclosure>();
  for (const c of claims) for (const d of follow(payload, c, 0) ?? []) selected.add(d);
  return decoded.filter((d) => selected.has(d));
}

/**
 * SD-JWT VC presentation: the issuer JWT, the disclosures {@link selectDisclosures} picks, and a KB-JWT
 * (aud = client_id, nonce, sd_hash) when the credential is holder-bound.
 */
export async function presentSdJwt(c: StoredCredential, claims: DcqlClaim[], req: AuthorizationRequest, key: SigningKey, audience = req.clientId): Promise<string> {
  const { issuerJwt, disclosures } = parseSdJwt(String(c.credential));
  const payload = decodeJws<Record<string, unknown>>(issuerJwt).payload;
  const selected = selectDisclosures(payload, disclosures.map(decodeDisclosure), claims);
  const sdJwt = `${issuerJwt}~${selected.map((d) => `${d.raw}~`).join('')}`;
  if (!(payload.cnf as { jwk?: unknown } | undefined)?.jwk) return sdJwt;
  const sdHash = bytes.base64UrlEncode(sha256(bytes.utf8Encode(sdJwt)));
  const kb = await signJwt({ typ: 'kb+jwt' }, { iat: nowSeconds(), aud: audience, nonce: req.nonce, sd_hash: sdHash }, key);
  return sdJwt + kb;
}

export function openId4VpHandover(req: AuthorizationRequest, encryptionJwk?: Jwk): unknown[] {
  const thumb = encryptionJwk ? jwkThumbprintBytes(encryptionJwk) : null;
  const info = [req.clientId, req.nonce, thumb, req.responseUri ?? req.redirectUri ?? ''];
  return ['OpenID4VPHandover', sha256(cbor.encode(info))];
}

/** mdoc DeviceResponse for one document, disclosing only the requested data elements. */
export async function presentMdoc(c: StoredCredential, claims: DcqlClaim[], req: AuthorizationRequest, key: SigningKey, encryptionJwk?: Jwk): Promise<string> {
  const { issuerSigned, docType: wrapped } = decodeIssuerSigned(String(c.credential));
  const docType = c.report?.credentialType ?? wrapped ?? '';
  const wanted = new Set(pathsOf(claims).map((p) => `${p[0]}|${p[1]}`));
  const nameSpaces = new Map<string, unknown[]>();
  for (const [ns, items] of issuerSignedItems(issuerSigned)) {
    const keep = items.filter((i) => wanted.has(`${ns}|${i.elementIdentifier}`)).map((i) => i.tagged);
    if (keep.length) nameSpaces.set(ns, keep);
  }
  const sessionTranscript = [null, null, openId4VpHandover(req, encryptionJwk)];
  const deviceNameSpacesBytes = new Tagged(24, cbor.encode(new Map()));
  const deviceAuthentication = ['DeviceAuthentication', sessionTranscript, docType, deviceNameSpacesBytes];
  const payload = cbor.encode(new Tagged(24, cbor.encode(deviceAuthentication)));
  const algs = ((req.clientMetadata.vp_formats_supported as Record<string, Record<string, number[]>> | undefined)?.mso_mdoc?.deviceauth_alg_values) ?? [-7];
  const alg = algs.includes(-9) && !algs.includes(-7) ? -9 : -7;
  const protectedBytes = cbor.encode(new Map([[1, alg]]));
  const signature = await key.sign(cbor.encode(['Signature1', protectedBytes, new Uint8Array(), payload]));
  const deviceSignature = [protectedBytes, new Map(), null, signature];
  const document = new Map<string, unknown>([
    ['docType', docType],
    // No requested elements: IssuerSigned without its optional nameSpaces (OpenID4VP §6.4.1).
    ['issuerSigned', new Map<string, unknown>([...(nameSpaces.size ? [['nameSpaces', nameSpaces] as const] : []), ['issuerAuth', cbor.mapGet(issuerSigned, 'issuerAuth')]])],
    ['deviceSigned', new Map<string, unknown>([['nameSpaces', deviceNameSpacesBytes], ['deviceAuth', new Map([['deviceSignature', deviceSignature]])]])],
  ]);
  const response = new Map<string, unknown>([['version', '1.0'], ['documents', [document]], ['status', 0]]);
  return bytes.base64UrlEncode(cbor.encode(response));
}

/** W3C VP with an ecdsa-rdfc-2019 DataIntegrityProof made with the holder's did:jwk / did:key. */
export async function presentLdp(c: StoredCredential, req: AuthorizationRequest, key: SigningKey, f: typeof fetch): Promise<Record<string, unknown>> {
  const vc = typeof c.credential === 'string' ? JSON.parse(c.credential) : c.credential;
  const holder = c.holderDid ?? `did:jwk:${bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify({ crv: 'P-256', kty: 'EC', x: key.publicJwk.x, y: key.publicJwk.y })))}`;
  const vm = holder.startsWith('did:jwk:') ? `${holder}#0` : `${holder}#${holder.slice('did:key:'.length)}`;
  const vp: Record<string, unknown> = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder, verifiableCredential: [vc] };
  const proof: Record<string, unknown> = { type: 'DataIntegrityProof', cryptosuite: 'ecdsa-rdfc-2019', created: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    verificationMethod: vm, proofPurpose: 'authentication', challenge: req.nonce, domain: req.clientId };
  const loader = createDocumentLoader(f);
  const docC = await canonize(vp, loader, false);
  const cfgC = await canonize({ ...proof, '@context': vp['@context'] }, loader, false);
  const hashData = bytes.concatBytes(sha256(bytes.utf8Encode(cfgC)), sha256(bytes.utf8Encode(docC)));
  proof.proofValue = `z${base58Encode(await key.sign(hashData))}`;
  return { ...vp, proof };
}

export interface PresentationSelection {
  /** DCQL credential query id → stored credential and claims to disclose */
  [queryId: string]: { credential: StoredCredential; claims: DcqlClaim[] };
}

export async function buildVpToken(req: AuthorizationRequest, selection: PresentationSelection, keys: KeyStore, f: typeof fetch): Promise<Record<string, unknown[]>> {
  const encJwk = req.responseMode === 'direct_post.jwt' ? encryptionKey(req.clientMetadata) : undefined;
  const vpToken: Record<string, unknown[]> = {};
  for (const [queryId, { credential, claims }] of Object.entries(selection)) {
    const key = await keys.get(credential.holderKeyId);
    if (!key) throw new Error(`Holder key for credential ${credential.id} is not available`);
    switch (credential.format) {
      case 'dc+sd-jwt':
      case 'vc+sd-jwt': vpToken[queryId] = [await presentSdJwt(credential, claims, req, key)]; break;
      case 'mso_mdoc': vpToken[queryId] = [await presentMdoc(credential, claims, req, key, encJwk)]; break;
      case 'ldp_vc': vpToken[queryId] = [await presentLdp(credential, req, key, f)]; break;
      default: throw new Error(`Cannot present format ${credential.format}`);
    }
  }
  return vpToken;
}

export interface SubmitResult {
  status: number;
  redirectUri?: string;
  body?: unknown;
}

export async function submitResponse(req: AuthorizationRequest, payload: Record<string, unknown>, f: typeof fetch): Promise<SubmitResult> {
  if (!req.responseUri) throw new Error('No response_uri');
  const form = new URLSearchParams();
  if (req.responseMode === 'direct_post.jwt' && !payload.error) {
    const jwk = encryptionKey(req.clientMetadata);
    if (!jwk) throw new Error('Verifier client_metadata has no usable ECDH-ES P-256 encryption key');
    const encs = (req.clientMetadata.encrypted_response_enc_values_supported as string[] | undefined) ?? ['A128GCM'];
    const enc: JweEnc = encs.includes('A256GCM') ? 'A256GCM' : 'A128GCM';
    form.set('response', encryptJwe(bytes.utf8Encode(JSON.stringify({ ...payload, ...(req.state ? { state: req.state } : {}) })), jwk, enc));
  } else {
    for (const [k, v] of Object.entries(payload)) form.set(k, typeof v === 'string' ? v : JSON.stringify(v));
    if (req.state) form.set('state', req.state);
  }
  const r = await f(req.responseUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form.toString() });
  const text = await r.text();
  let body: unknown = text;
  try { body = JSON.parse(text); } catch { /* not json */ }
  return { status: r.status, redirectUri: (body as { redirect_uri?: string } | undefined)?.redirect_uri, body };
}
