/**
 * W3C Verifiable Credentials secured with Data Integrity proofs (OpenID4VCI format ldp_vc): VCDM 2.0, and VCDM 1.1 as
 * the format still allows. Cryptosuites: ecdsa-rdfc-2019 (P-256, P-384), eddsa-rdfc-2022 and Ed25519Signature2020.
 *
 * Checked: the data model's required members; every proof (the verification method is the issuer's own and is
 * authorized for assertionMethod, the signature covers the RDFC-1.0 canonical form of the whole document); the
 * validity period; the binding to this wallet; the status; and, through the trust client, the issuer's trust.
 * Nothing the specifications forbid is waved through: a term no context defines, a context given inline, a key
 * published under another DID or a relationship that lists the DID instead of the key each fail the credential.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import type { Jwk, TrustClient, TrustDecision } from '@vctrust/trust-client';
import { bytes, decodeMultibase, didError, extractIssuerInfo, findVerificationMethod, hasRelationship, issuerTrustQuery, jwkThumbprint, verificationMethodPublicKey,
  verifySignature, type IssuerInfo } from '@vctrust/trust-client/primitives';
import { BUNDLED_CONTEXTS } from './contexts.js';
import { canonize, createDocumentLoader, notCompact, type DocumentLoader, type LoaderStats } from './jsonld.js';
import { didPublicKey } from '../crypto/did-key.js';
import { Checks, finish, type VerificationReport } from './report.js';

const V2 = 'https://www.w3.org/ns/credentials/v2';
const V1 = 'https://www.w3.org/2018/credentials/v1';
const SUITES = new Set(['ecdsa-rdfc-2019', 'eddsa-rdfc-2022', 'Ed25519Signature2020']);
/** XML Schema dateTimeStamp: a dateTime with a time zone, as VCDM 2.0 requires of validFrom / validUntil. */
const DATE_TIME_STAMP = /^-?\d{4,}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface LdpVerifyOptions {
  trust: TrustClient;
  documentLoader?: DocumentLoader;
  /** the DID this wallet asked the credential to be bound to */
  holderDid?: string;
  holderJwk?: Jwk;
  now?: Date;
  checkStatus?: boolean;
  /** what the wallet asked for: the configuration's credential_definition (OpenID4VCI 1.0 Appendix A.1.2.2) */
  expected?: { context?: string[]; type?: string[] };
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const list = <T>(v: T | T[] | undefined | null): T[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

function date(v: unknown): Date | undefined {
  if (typeof v !== 'string' || !DATE_TIME_STAMP.test(v)) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** The data model's own rules (VCDM 2.0 §4, VCDM 1.1 §4): what a conforming document has, whatever its proof says. */
function checkModel(vc: Record<string, unknown>, checks: Checks): { v2: boolean; issuer?: string; from?: Date; until?: Date } {
  const problems: string[] = [];
  const contexts = vc['@context'];
  const v2 = Array.isArray(contexts) && contexts[0] === V2;
  if (!Array.isArray(contexts) || (contexts[0] !== V2 && contexts[0] !== V1)) problems.push(`@context must be an array starting with ${V2} (or ${V1})`);
  // An inline context could rename terms without changing a single signed statement; only contexts by URL are processed,
  // and only at the top of the document: a context further down could do the same to the members below it.
  else if (contexts.some((c) => typeof c !== 'string')) problems.push('@context contains an inline context; this wallet processes contexts given by URL only');
  else if (hasNestedContext(vc)) problems.push('a member below the top level carries its own @context; this wallet processes the document\'s contexts only');
  if (!list(vc.type as string | string[]).includes('VerifiableCredential')) problems.push('type must include VerifiableCredential');
  const issuer = typeof vc.issuer === 'string' ? vc.issuer : isObject(vc.issuer) && typeof vc.issuer.id === 'string' ? vc.issuer.id : undefined;
  if (!issuer) problems.push('issuer must be a URL or an object with an id');
  const subjects = list(vc.credentialSubject);
  if (subjects.length === 0 || !subjects.every(isObject)) problems.push('credentialSubject must be an object, or a list of objects');
  const [fromName, untilName] = v2 ? ['validFrom', 'validUntil'] : ['issuanceDate', 'expirationDate'];
  const from = date(vc[fromName]);
  const until = date(vc[untilName]);
  if (vc[fromName] !== undefined && !from) problems.push(`${fromName} is not a dateTimeStamp`);
  if (vc[untilName] !== undefined && !until) problems.push(`${untilName} is not a dateTimeStamp`);
  if (!v2 && vc.issuanceDate === undefined) problems.push('issuanceDate is required by VCDM 1.1');
  if (v2 && (vc.issuanceDate !== undefined || vc.expirationDate !== undefined)) problems.push('issuanceDate / expirationDate are VCDM 1.1 members; VCDM 2.0 uses validFrom / validUntil');
  if (from && until && until < from) problems.push(`${untilName} is before ${fromName}`);
  if (problems.length) checks.fail('ldp.model', 'Data model', problems.join('; '));
  else checks.pass('ldp.model', 'Data model', v2 ? 'Verifiable Credentials Data Model 2.0' : 'Verifiable Credentials Data Model 1.1');
  return { v2, issuer, from, until };
}

/** Whether any member below the top level has an @context of its own. */
function hasNestedContext(doc: Record<string, unknown>): boolean {
  const walk = (v: unknown, top: boolean): boolean => {
    if (Array.isArray(v)) return v.some((x) => walk(x, false));
    if (!isObject(v)) return false;
    return Object.entries(v).some(([k, x]) => (k === '@context' ? !top : walk(x, false)));
  };
  return walk(doc, true);
}

/** Verifies one proof; returns a description of it, or throws with the reason it does not hold. */
async function verifyProof(vc: Record<string, unknown>, proof: Record<string, unknown>, issuer: string | undefined, loader: DocumentLoader,
                           trust: TrustClient, now: Date): Promise<string> {
  const suite = proof.type === 'DataIntegrityProof' ? String(proof.cryptosuite ?? '') : String(proof.type ?? '');
  if (!SUITES.has(suite) || (proof.type !== 'DataIntegrityProof' && proof.type !== 'Ed25519Signature2020')) {
    throw new Error(`Unsupported proof ${String(proof.type)}${proof.cryptosuite ? ` / ${String(proof.cryptosuite)}` : ''}`);
  }
  if (proof.proofPurpose !== 'assertionMethod') throw new Error(`proofPurpose must be assertionMethod (got ${String(proof.proofPurpose)})`);
  const vmId = typeof proof.verificationMethod === 'string' ? proof.verificationMethod : '';
  const vmDid = vmId.split('#')[0]!;
  if (!vmId.includes('#') || !vmDid.startsWith('did:')) throw new Error(`verificationMethod must be a DID URL naming a key (got ${vmId || 'none'})`);
  // The issuer is who the credential says it is: the key must be published by that very DID.
  if (vmDid !== issuer) throw new Error(`The verification method belongs to ${vmDid}, not to the issuer ${String(issuer)}`);
  const resolved = await trust.resolveDid(vmId);
  if (!resolved.didDocument) throw new Error(`Cannot resolve ${vmDid}: ${didError(resolved) ?? 'no document'}`);
  const vm = findVerificationMethod(resolved.didDocument, vmId);
  if (!vm) throw new Error(`Verification method ${vmId} is not in the DID document`);
  if (vm.controller !== undefined && vm.controller !== vmDid) throw new Error(`Verification method ${vmId} is controlled by ${String(vm.controller)}`);
  if (!hasRelationship(resolved.didDocument, 'assertionMethod', vmId)) throw new Error(`Verification method ${vmId} is not authorized for assertionMethod`);
  const key = verificationMethodPublicKey(vm);

  const { proofValue, ...options } = proof;
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) throw new Error('proofValue must be multibase base58-btc');
  const { proof: _proofs, ...unsecured } = vc;
  // Proof options are canonicalized under the document's contexts (Data Integrity §4.3; a proof's own @context must be a prefix of them).
  const own = options['@context'];
  const contexts = vc['@context'] as string[];
  if (own !== undefined && !(Array.isArray(own) && own.every((c, i) => c === contexts[i]))) throw new Error('The proof\'s @context is not a prefix of the document\'s');
  const [document, config] = [await canonize(unsecured, loader), await canonize({ ...options, '@context': contexts }, loader)];
  const p384 = suite === 'ecdsa-rdfc-2019' && key.kty === 'EC' && key.crv === 'P-384';
  const hash = p384 ? sha384 : sha256;
  const hashData = bytes.concatBytes(hash(bytes.utf8Encode(config)), hash(bytes.utf8Encode(document)));
  const signature = decodeMultibase(proofValue);
  let ok: boolean;
  if (suite === 'ecdsa-rdfc-2019') {
    if (key.kty !== 'EC' || (key.crv !== 'P-256' && key.crv !== 'P-384')) throw new Error('ecdsa-rdfc-2019 needs a P-256 or P-384 key');
    ok = verifySignature(p384 ? 'ES384' : 'ES256', key, hashData, signature, 'raw');
  } else {
    if (key.kty !== 'OKP') throw new Error(`${suite} needs an Ed25519 key`);
    ok = ed25519.verify(signature, hashData, key.x);
  }
  if (!ok) throw new Error(`${suite} signature does not verify`);
  if (proof.expires !== undefined && !(date(proof.expires) && date(proof.expires)! >= now)) throw new Error(`The proof expired ${String(proof.expires)}`);
  return `${suite} by ${vmId} (${String(resolved.didResolutionMetadata.source ?? 'resolved')})`;
}

export async function verifyLdpVc(vcIn: Record<string, unknown> | string, opts: LdpVerifyOptions): Promise<VerificationReport> {
  const checks = new Checks();
  const now = opts.now ?? new Date();
  const stats: LoaderStats = { unvouched: new Set() };
  const loader = opts.documentLoader ?? createDocumentLoader(opts.trust, stats);
  let vc: Record<string, unknown>;
  try {
    vc = (typeof vcIn === 'string' ? JSON.parse(vcIn) : vcIn) as Record<string, unknown>;
    if (!isObject(vc)) throw new Error('not a JSON object');
  } catch (e) {
    checks.fail('ldp.model', 'Data model', `Not a JSON-LD credential: ${(e as Error).message}`);
    return finish('ldp_vc', checks, { format: 'ldp_vc' }, null, {});
  }
  const model = checkModel(vc, checks);
  const modelOk = checks.ok;
  const issuerInfo: IssuerInfo = extractIssuerInfo(vc, 'ldp_vc');

  const expected = opts.expected;
  if (expected) {
    const types = list(vc.type as string | string[]);
    const missing = (expected.type ?? []).filter((t) => !types.includes(t));
    const contexts = Array.isArray(vc['@context']) ? vc['@context'] : [];
    const sameContexts = !expected.context || (expected.context.length === contexts.length && expected.context.every((c, i) => c === contexts[i]));
    if (missing.length) checks.fail('ldp.requested', 'Requested credential', `The credential lacks the requested type ${missing.join(', ')}`);
    else if (!sameContexts) checks.fail('ldp.requested', 'Requested credential', 'The credential\'s @context is not the one the issuer metadata declares for this credential');
    else checks.pass('ldp.requested', 'Requested credential', (expected.type ?? []).join(', '));
  }

  // Every proof must hold: a proof the wallet cannot check is not evidence of anything.
  const proofs = list(vc.proof);
  if (proofs.length === 0) checks.fail('ldp.signature', 'Issuer signature', 'The credential has no proof');
  else if (!modelOk) checks.skip('ldp.signature', 'Issuer signature', 'Not checked: the document is not a conforming credential');
  else {
    try {
      const verified: string[] = [];
      for (const proof of proofs) {
        if (!isObject(proof)) throw new Error('A proof is not an object');
        verified.push(await verifyProof(vc, proof, model.issuer, loader, opts.trust, now));
      }
      // The document must say everything in the terms of its contexts: what is signed is then what is read below
      // (validity, status, the claims). A signed statement spelled another way would be covered and not seen.
      const stray = await notCompact(vc, loader);
      if (stray) throw new Error(`The member ${stray} is not written in the terms of the document's contexts, so what the signature covers is not what the document appears to say`);
      // Which of the document's contexts the trust layer does not vouch for is asked here rather than left to the
      // loader: the JSON-LD processor may reuse a context it resolved earlier without consulting the loader again.
      for (const url of vc['@context'] as string[]) {
        if (!Object.prototype.hasOwnProperty.call(BUNDLED_CONTEXTS, url) && !(await opts.trust.context(url)).vouched) stats.unvouched.add(url);
      }
      checks.pass('ldp.signature', 'Issuer signature', `${verified.join('; ')} over RDFC-1.0`);
      if (stats.unvouched.size) {
        checks.warn('ldp.contexts', 'JSON-LD contexts', `Fetched from their own hosts, not vouched for by the trust service: ${[...stats.unvouched].join(', ')}`);
      } else checks.pass('ldp.contexts', 'JSON-LD contexts', 'Built in or vouched for by the trust service');
    } catch (e) {
      checks.fail('ldp.signature', 'Issuer signature', (e as Error).message.slice(0, 300));
    }
  }

  const span = `${model.from?.toISOString() ?? 'no start'} – ${model.until?.toISOString() ?? 'no expiry'}`;
  if (model.from && model.from > now) checks.fail('ldp.validity', 'Validity period', `Not valid before ${model.from.toISOString()}`);
  else if (model.until && model.until < now) checks.fail('ldp.validity', 'Validity period', `Expired ${model.until.toISOString()}`);
  else checks.pass('ldp.validity', 'Validity period', span);

  // Holder binding: the subject is this wallet's DID when the wallet proved a DID to the issuer.
  const subject = list(vc.credentialSubject)[0] as Record<string, unknown> | undefined;
  const subjectId = typeof subject?.id === 'string' ? subject.id.split('#')[0] : undefined;
  if (opts.holderDid) {
    if (subjectId === opts.holderDid.split('#')[0]) checks.pass('ldp.holder', 'Holder binding', 'credentialSubject.id is this wallet\'s DID');
    else checks.fail('ldp.holder', 'Holder binding', subjectId ? `credentialSubject.id ${subjectId} is not this wallet's DID` : 'credentialSubject has no id, although the wallet proved a DID');
  } else if (opts.holderJwk) {
    // The wallet proved a key: the subject must be that key (a did:jwk or did:key of it). Another kind of identifier does not bind the credential to this wallet.
    const subjectKey = subjectId ? didPublicKey(subjectId) : undefined;
    if (!subjectId) checks.fail('ldp.holder', 'Holder binding', 'credentialSubject has no id, although the wallet proved a key');
    else if (!subjectKey) checks.fail('ldp.holder', 'Holder binding', `credentialSubject.id ${subjectId} does not name the key this wallet proved`);
    else if (jwkThumbprint(subjectKey) !== jwkThumbprint(opts.holderJwk)) checks.fail('ldp.holder', 'Holder binding', `credentialSubject.id ${subjectId} is not this wallet's key`);
    else checks.pass('ldp.holder', 'Holder binding', 'credentialSubject.id is this wallet\'s key');
  } else if (subjectId) checks.pass('ldp.holder', 'Holder binding', subjectId);
  else checks.warn('ldp.holder', 'Holder binding', 'credentialSubject has no id: the credential is not bound to a holder');

  let trust: TrustDecision | null = null;
  try {
    trust = await opts.trust.evaluate(issuerTrustQuery(issuerInfo));
  } catch (e) {
    checks.fail('ldp.issuer', 'Issuer', `The issuer could not be evaluated: ${(e as Error).message}`);
  }

  if (opts.checkStatus !== false) await checkStatus(vc, model.issuer, trust, loader, opts, now, checks);

  return finish('ldp_vc', checks, issuerInfo, trust, { ...(subject ?? {}) }, { credentialType: issuerInfo.credentialType,
    validFrom: model.from?.toISOString(), validUntil: model.until?.toISOString() });
}

/**
 * credentialStatus: one entry or several (VCDM 2.0 §4.10). A BitstringStatusListEntry is checked against its list
 * credential, which must itself verify and come from the same issuer; a status of a kind this wallet does not know
 * leaves the status unknown, which the report says.
 */
async function checkStatus(vc: Record<string, unknown>, issuer: string | undefined, trust: TrustDecision | null, loader: DocumentLoader,
                           opts: LdpVerifyOptions, now: Date, checks: Checks): Promise<void> {
  for (const [i, entry] of list(vc.credentialStatus).entries()) {
    const id = `ldp.status${i ? `.${i + 1}` : ''}`;
    if (!isObject(entry)) { checks.fail(id, 'Status', 'credentialStatus is not an object'); continue; }
    if (entry.type !== 'BitstringStatusListEntry') {
      checks.warn(id, 'Status', `Status of type ${String(entry.type)} is not supported; whether the credential is revoked is unknown`);
      continue;
    }
    const s = await opts.trust.checkBitstringStatus(entry, { issuer, decision: trust, now,
      verifyListCredential: async (listCredential) => {
        const r = await verifyLdpVc(listCredential, { trust: opts.trust, documentLoader: loader, now, checkStatus: false });
        return { ok: r.valid, detail: r.checks.filter((c) => c.status === 'fail' && c.id !== 'issuer.trust').map((c) => c.detail).join('; ') };
      } });
    const purpose = typeof entry.statusPurpose === 'string' ? `${entry.statusPurpose}: ` : '';
    if (s.status === 'valid') checks.pass(id, 'Status', `${purpose}${s.detail}`);
    else if (s.status === 'unknown') checks.warn(id, 'Status', `${purpose}${s.detail}`);
    else checks.fail(id, 'Status', `${s.status}: ${s.detail}`);
  }
}
