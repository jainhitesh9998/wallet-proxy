/** Local, standards-based DID resolution (did:key, did:jwk, did:web) used when the trust service is unavailable. */
import { base64UrlDecode, utf8Decode } from '../util/bytes.js';
import { DID_ERRORS, didErrorResult, parseDid } from './did.js';
import { decodeMultibase, publicKeyFromMulticodec } from './keys.js';
import { readVarint, MULTICODEC } from './multibase.js';
import type { DidDocument, DidResolutionResult, VerificationMethod } from '../types.js';

export interface LocalDidResolverOptions {
  fetch: typeof fetch;
  /** Hosts for which did:web may use plain http (development only). */
  httpHosts?: string[];
  timeoutMs?: number;
}

function singleKeyDoc(did: string, contexts: string[], vm: VerificationMethod, signing: boolean, keyAgreement: boolean): DidDocument {
  const doc: DidDocument = { '@context': contexts, id: did, verificationMethod: [vm] };
  if (signing) for (const rel of ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation']) doc[rel] = [vm.id];
  if (keyAgreement) doc.keyAgreement = [vm.id];
  return doc;
}

function ok(doc: DidDocument, extra: Record<string, unknown> = {}): DidResolutionResult {
  return { didDocument: doc, didResolutionMetadata: { contentType: 'application/did+ld+json', ...extra }, didDocumentMetadata: {} };
}

export function resolveDidKey(did: string): DidResolutionResult {
  const id = parseDid(did).id;
  try {
    const raw = decodeMultibase(id);
    const { codec } = readVarint(raw);
    if (codec === MULTICODEC.jwkJcs) {
      const jwk = JSON.parse(utf8Decode(readVarint(raw).payload));
      return ok(singleKeyDoc(did, ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        { id: `${did}#0`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk }, true, false));
    }
    if (codec !== MULTICODEC.x25519) publicKeyFromMulticodec(raw);
    const vm: VerificationMethod = { id: `${did}#${id}`, type: 'Multikey', controller: did, publicKeyMultibase: id };
    return ok(singleKeyDoc(did, ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'], vm,
      codec !== MULTICODEC.x25519, codec === MULTICODEC.x25519));
  } catch (e) {
    return didErrorResult(DID_ERRORS.INVALID_DID, (e as Error).message);
  }
}

export function resolveDidJwk(did: string): DidResolutionResult {
  try {
    const jwk = JSON.parse(utf8Decode(base64UrlDecode(parseDid(did).id))) as Record<string, unknown>;
    if (typeof jwk.kty !== 'string' || 'd' in jwk) return didErrorResult(DID_ERRORS.INVALID_DID, 'Invalid did:jwk key');
    const vm: VerificationMethod = { id: `${did}#0`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk as never };
    return ok(singleKeyDoc(did, ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'], vm,
      jwk.use !== 'enc', jwk.use !== 'sig' && jwk.crv !== 'Ed25519'));
  } catch (e) {
    return didErrorResult(DID_ERRORS.INVALID_DID, (e as Error).message);
  }
}

export function didWebUrl(did: string, httpHosts: string[] = []): string {
  const parts = parseDid(did).id.split(':');
  const hostPort = decodeURIComponent(parts[0]!);
  const host = hostPort.split(':')[0]!;
  const scheme = httpHosts.includes(host) ? 'http' : 'https';
  const path = parts.length === 1 ? '/.well-known/did.json' : `/${parts.slice(1).map(decodeURIComponent).join('/')}/did.json`;
  return `${scheme}://${hostPort}${path}`;
}

export async function resolveDidWeb(did: string, opts: LocalDidResolverOptions): Promise<DidResolutionResult> {
  let url: string;
  try {
    url = didWebUrl(did, opts.httpHosts);
  } catch (e) {
    return didErrorResult(DID_ERRORS.INVALID_DID, (e as Error).message);
  }
  let res: Response;
  try {
    res = await fetchWithTimeout(opts.fetch, url, { headers: { Accept: 'application/did+json, application/json' } }, opts.timeoutMs ?? 8000);
  } catch (e) {
    return didErrorResult(DID_ERRORS.INTERNAL_ERROR, `Fetching ${url} failed: ${(e as Error).message}`);
  }
  if (res.status === 404 || res.status === 410) return didErrorResult(DID_ERRORS.NOT_FOUND, `HTTP ${res.status} from ${url}`);
  if (!res.ok) return didErrorResult(DID_ERRORS.INTERNAL_ERROR, `HTTP ${res.status} from ${url}`);
  let doc: DidDocument;
  try {
    doc = (await res.json()) as DidDocument;
  } catch {
    return didErrorResult(DID_ERRORS.INVALID_DID_DOCUMENT, 'did.json is not JSON');
  }
  if (doc.id !== parseDid(did).did) return didErrorResult(DID_ERRORS.INVALID_DID_DOCUMENT, `DID document id ${doc.id} does not match ${did}`);
  return ok(doc, { documentUrl: url });
}

export async function resolveDidLocally(did: string, opts: LocalDidResolverOptions): Promise<DidResolutionResult> {
  let method: string;
  let bare: string;
  try {
    const p = parseDid(did);
    method = p.method;
    bare = p.did;
  } catch (e) {
    return didErrorResult(DID_ERRORS.INVALID_DID, (e as Error).message);
  }
  switch (method) {
    case 'key': return resolveDidKey(bare);
    case 'jwk': return resolveDidJwk(bare);
    case 'web': return resolveDidWeb(bare, opts);
    default: return didErrorResult(DID_ERRORS.METHOD_NOT_SUPPORTED, `DID method ${method} cannot be resolved without the trust service`);
  }
}

export async function fetchWithTimeout(f: typeof fetch, url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : undefined;
  const timer = setTimeout(() => ctrl?.abort(), timeoutMs);
  try {
    return await f(url, { ...init, signal: ctrl?.signal });
  } finally {
    clearTimeout(timer);
  }
}
