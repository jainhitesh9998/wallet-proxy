/**
 * W3C VCDM 2.0 credentials and presentations secured with Data Integrity (ecdsa-rdfc-2019, eddsa-rdfc-2022), issued and
 * verified by the Digital Bazaar libraries, with Bitstring Status List v1.0 status (section 3.2, Validate Algorithm).
 */
import * as vc from '@digitalbazaar/vc';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import { cryptosuite as ecdsaRdfc2019 } from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import { cryptosuite as eddsaRdfc2022 } from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import { driver as didKeyDriver } from '@digitalbazaar/did-method-key';
import { securityLoader } from '@digitalbazaar/security-document-loader';
import { checkStatus as checkBitstringStatus, decodeList } from '@digitalbazaar/vc-bitstring-status-list';
import jsonld from 'jsonld';
import { didJwkKey } from './keys.mjs';

export const SUITES = { 'ecdsa-rdfc-2019': ecdsaRdfc2019, 'eddsa-rdfc-2022': eddsaRdfc2022 };
/** Bitstring Status List v1.0 section 3.2: the fewest entries a status list may have unless an ecosystem says otherwise. */
const MINIMUM_STATUS_ENTRIES = 131_072;
const DID_V1 = 'https://www.w3.org/ns/did/v1';
const MULTIKEY_V1 = 'https://w3id.org/security/multikey/v1';
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const verifierSuites = () => Object.values(SUITES).map((cryptosuite) => new DataIntegrityProof({ cryptosuite }));

const didKey = didKeyDriver();
didKey.use({ multibaseMultikeyHeader: 'z6Mk', fromMultibase: Ed25519Multikey.from });
didKey.use({ multibaseMultikeyHeader: 'zDna', fromMultibase: EcdsaMultikey.from });

/** The did:web of an origin (did:web method: the port's colon is percent-encoded). */
export const didWeb = (url) => `did:web:${new URL(url).host.replace(':', '%3A')}`;

/** The issuer's assertion keys (Multikey), one per cryptosuite; `exported` restores them. */
export async function createAssertionKeys(did, exported) {
  const keys = {};
  for (const [suite, lib, opts] of [['ecdsa-rdfc-2019', EcdsaMultikey, { curve: 'P-256' }], ['eddsa-rdfc-2022', Ed25519Multikey, {}]]) {
    const key = exported?.[suite] ? await lib.from(exported[suite]) : await lib.generate({ ...opts, controller: did });
    key.controller = did;
    key.id = `${did}#${key.publicKeyMultibase}`;
    keys[suite] = key;
  }
  return keys;
}

export const exportAssertionKeys = async (keys) => Object.fromEntries(await Promise.all(
  Object.entries(keys).map(async ([suite, key]) => [suite, await key.export({ publicKey: true, secretKey: true, includeContext: true })])));

/** The issuer's DID document: every assertion key is a Multikey verification method referenced from assertionMethod. */
export async function didDocument(did, keys) {
  const methods = await Promise.all(Object.values(keys).map((k) => k.export({ publicKey: true, includeContext: false })));
  return { '@context': [DID_V1, MULTIKEY_V1], id: did, verificationMethod: methods, assertionMethod: methods.map((m) => m.id) };
}

/** did:jwk: the key as the one JsonWebKey2020 verification method, `#0`, for authentication and assertion. */
function didJwkDocument(did) {
  const id = `${did}#0`;
  return { '@context': [DID_V1, 'https://w3id.org/security/suites/jws-2020/v1'], id: did,
    verificationMethod: [{ id, type: 'JsonWebKey2020', controller: did, publicKeyJwk: didJwkKey(did) }], authentication: [id], assertionMethod: [id] };
}

/** did:web resolves over https; http is used for loopback hosts only, where this ecosystem runs. */
function didWebUrl(did) {
  const [host, ...path] = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  const scheme = LOOPBACK.has(new URL(`http://${host}`).hostname) ? 'http' : 'https';
  return `${scheme}://${host}/${path.length ? path.join('/') : '.well-known'}/did.json`;
}

async function fetchJson(url, fetcher) {
  const { protocol, hostname } = new URL(url);
  if (protocol !== 'https:' && !LOOPBACK.has(hostname)) throw new Error(`Refusing to load ${url} over an insecure connection`);
  const response = await fetcher(url, { headers: { Accept: 'application/ld+json, application/json' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  return response.json();
}

/**
 * A JSON-LD document loader that knows the standard contexts and the given documents, and resolves did:key and did:jwk
 * locally. With a `fetch`, did:web documents and other http(s) documents (contexts, status list credentials) are
 * retrieved; without one nothing is fetched. A DID URL with a fragment loads that verification method.
 * @param {{ statics?: Record<string, object>, fetch?: typeof fetch }} [opts]
 */
export function documentLoader({ statics = {}, fetch: fetcher } = {}) {
  const loader = securityLoader();
  const resolveDid = async (did) => {
    if (statics[did]) return statics[did];
    if (did.startsWith('did:key:')) return didKey.get({ did });
    if (did.startsWith('did:jwk:')) return didJwkDocument(did);
    if (did.startsWith('did:web:') && fetcher) {
      const document = await fetchJson(didWebUrl(did), fetcher);
      if (document.id !== did) throw new Error(`The document at ${didWebUrl(did)} is not the DID document of ${did}`);
      return document;
    }
    throw new Error(`Cannot resolve ${did}`);
  };
  for (const [url, doc] of Object.entries(statics)) loader.addStatic(url, doc);
  loader.setDidResolver({ get: async ({ url }) => {
    const document = await resolveDid(url.split('#')[0]);
    if (!url.includes('#')) return document;
    const method = (document.verificationMethod ?? []).find((m) => m.id === url);
    if (!method) throw new Error(`${url} is not a verification method of its DID document`);
    return { '@context': document['@context'], ...method };
  } });
  if (fetcher) for (const protocol of ['http', 'https']) loader.setProtocolHandler({ protocol, handler: { get: ({ url }) => fetchJson(url, fetcher) } });
  return loader.build();
}

export function signCredential(credential, key, suite, loader) {
  return vc.issue({ credential, suite: new DataIntegrityProof({ signer: key.signer(), cryptosuite: SUITES[suite] }), documentLoader: loader });
}

/**
 * The status of a credential with BitstringStatusListEntry status entries. The reference library retrieves and verifies
 * the status list credential, compares the status purposes and reads the bit; this adds the two steps of the Validate
 * Algorithm it leaves to the caller: the minimum list length (step 9) and what the bit means (a set revocation or
 * suspension bit makes the credential invalid).
 */
export async function checkStatus({ credential, documentLoader }) {
  // Every document is retrieved once, so the length is checked on the very list the reference library read.
  const loaded = new Map();
  const loader = (url) => loaded.get(url) ?? loaded.set(url, documentLoader(url)).get(url);
  const result = await checkBitstringStatus({ credential, documentLoader: loader, suite: verifierSuites(), verifyBitstringStatusListCredential: true, verifyMatchingIssuers: true });
  if (!result.verified) return result;
  for (const { credentialStatus, status } of result.results) {
    const { document } = await loader(credentialStatus.statusListCredential);
    const list = await decodeList({ encodedList: document.credentialSubject.encodedList });
    if (list.length / (credentialStatus.statusSize ?? 1) < MINIMUM_STATUS_ENTRIES) {
      return { verified: false, error: new Error(`STATUS_LIST_LENGTH_ERROR: the status list has fewer than ${MINIMUM_STATUS_ENTRIES} entries`) };
    }
    if (status && ['revocation', 'suspension'].includes(credentialStatus.statusPurpose)) {
      return { verified: false, error: new Error(`The credential's ${credentialStatus.statusPurpose} status is set`), results: result.results };
    }
  }
  return result;
}

/** The types of a credential as IRIs, which is how an OpenID4VP DCQL query names them (appendix B.1.1, type_values). */
export async function expandedTypes(credential, loader) {
  const [expanded] = await jsonld.expand(credential, { documentLoader: loader, safe: true });
  return expanded['@type'];
}

/** The public key of a verification method as multibase, whichever form (Multikey, JsonWebKey2020) it is given in. */
async function publicKeyOf(method) {
  for (const lib of [EcdsaMultikey, Ed25519Multikey]) {
    try { return (await lib.from(method)).publicKeyMultibase; } catch { /* a key of the other kind */ }
  }
  return undefined;
}

/**
 * Cryptographic holder binding of a W3C credential (OpenID4VP 1.0 section 2: control over the same private key during
 * issuance and presentation): whether a verification method, the one that signed a presentation, holds a key the
 * credential's subject authenticates with. The subject may name that key by another DID than the presentation does.
 */
export async function isSubjectKey(credential, verificationMethod, loader) {
  const subject = credential.credentialSubject?.id;
  const key = await publicKeyOf(verificationMethod);
  if (!key || typeof subject !== 'string' || !subject.startsWith('did:')) return false;
  const { document } = await loader(subject);
  for (const reference of [document.authentication ?? []].flat()) {
    const method = typeof reference === 'string' ? (await loader(reference)).document : reference;
    if (await publicKeyOf(method) === key) return true;
  }
  return false;
}

/** Verifies a credential and, when it has one, its status. */
export function verifyCredential(credential, loader) {
  return vc.verifyCredential({ credential, suite: verifierSuites(), documentLoader: loader, checkStatus });
}

/** Why a result of @digitalbazaar/vc is negative: the messages of its own, its credentials' and their status errors. */
export function failureReasons(result) {
  const errors = [result, ...(result.credentialResults ?? [])].flatMap((r) => [r.error, r.statusResult?.error]).filter(Boolean);
  return [...new Set(errors.flatMap((e) => e.errors ?? [e]).map((e) => e.message))].join('; ');
}

/** Verifies a presentation (authentication proof over the challenge and domain) and every credential in it, with status. */
export function verifyPresentation(presentation, { challenge, domain }, loader) {
  return vc.verify({ presentation, challenge, domain, suite: verifierSuites(), documentLoader: loader, checkStatus });
}
