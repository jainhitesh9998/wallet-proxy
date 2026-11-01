/**
 * Presentation building and response delivery for OpenID4VP 1.0:
 *  - dc+sd-jwt: selected disclosures + KB-JWT (aud = full client_id, nonce, sd_hash)
 *  - mso_mdoc: DeviceResponse with OpenID4VPHandover session transcript and deviceSignature (COSE_Sign1)
 *  - ldp_vc: Verifiable Presentation with an ecdsa-rdfc-2019 holder proof (challenge = nonce, domain = client_id)
 *  - direct_post / direct_post.jwt (ECDH-ES + A128GCM/A256GCM JWE to the verifier's ephemeral key)
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytes, cbor, decodeIssuerSigned, jwkThumbprintBytes, base58Encode, type Jwk } from '@vctrust/trust-client';
import { nowSeconds, signJwt } from '../crypto/jwt.js';
import { encryptJwe, type JweEnc } from '../crypto/jwe.js';
import type { KeyStore, SigningKey } from '../crypto/keys.js';
import { parseSdJwt, decodeDisclosure } from '../verify/sdjwt.js';
import { issuerSignedItems } from '../verify/mdoc.js';
import { canonize, createDocumentLoader } from '../verify/jsonld.js';
import type { StoredCredential } from '../store/credentials.js';
import { encryptionKey, type AuthorizationRequest, type DcqlClaim } from './request.js';

const { Tagged } = cbor;

function pathsOf(claims: DcqlClaim[]): string[][] {
  return claims.map((c) => c.path.map((p) => String(p)));
}

/** SD-JWT VC presentation: discloses only what the claims select (all disclosures when no claims requested). */
export async function presentSdJwt(c: StoredCredential, claims: DcqlClaim[], req: AuthorizationRequest, key: SigningKey, audience = req.clientId): Promise<string> {
  const { issuerJwt, disclosures } = parseSdJwt(String(c.credential));
  const decoded = disclosures.map(decodeDisclosure);
  let selected = decoded;
  if (claims.length) {
    const wanted = new Set(pathsOf(claims).map((p) => p[0]));
    const nested = pathsOf(claims).filter((p) => p.length > 1).map((p) => p.slice(1)).flat();
    // Disclose named members on the requested paths, and every array element / nested member below them.
    selected = decoded.filter((d) => d.name === undefined || wanted.has(d.name) || nested.includes(d.name));
  }
  const sdJwt = `${issuerJwt}~${selected.map((d) => d.raw).join('~')}${selected.length ? '~' : ''}`;
  const sdHash = bytes.base64UrlEncode(sha256(bytes.utf8Encode(sdJwt)));
  const kb = await signJwt({ typ: 'kb+jwt' }, { iat: nowSeconds(), aud: audience, nonce: req.nonce, sd_hash: sdHash }, key);
  return sdJwt + kb;
}

export function openId4VpHandover(req: AuthorizationRequest, encryptionJwk?: Jwk): unknown[] {
  const thumb = encryptionJwk ? jwkThumbprintBytes(encryptionJwk) : null;
  const info = [req.clientId, req.nonce, thumb, req.responseUri ?? req.redirectUri ?? ''];
  return ['OpenID4VPHandover', sha256(cbor.encode(info))];
}

/** mdoc DeviceResponse for one document, disclosing the requested data elements. */
export async function presentMdoc(c: StoredCredential, claims: DcqlClaim[], req: AuthorizationRequest, key: SigningKey, encryptionJwk?: Jwk): Promise<string> {
  const { issuerSigned, docType: wrapped } = decodeIssuerSigned(String(c.credential));
  const docType = c.report?.credentialType ?? wrapped ?? '';
  const wanted = new Set(pathsOf(claims).map((p) => `${p[0]}|${p[1]}`));
  const nameSpaces = new Map<string, unknown[]>();
  for (const [ns, items] of issuerSignedItems(issuerSigned)) {
    const keep = items.filter((i) => !claims.length || wanted.has(`${ns}|${i.elementIdentifier}`)).map((i) => i.tagged);
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
    ['issuerSigned', new Map<string, unknown>([['nameSpaces', nameSpaces], ['issuerAuth', cbor.mapGet(issuerSigned, 'issuerAuth')]])],
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
