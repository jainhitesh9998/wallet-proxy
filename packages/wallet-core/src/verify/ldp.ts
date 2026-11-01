/**
 * W3C VC (VCDM 1.1 / 2.0) with JSON-LD Data Integrity proofs: Ed25519Signature2020, DataIntegrityProof with
 * eddsa-rdfc-2022 or ecdsa-rdfc-2019. Verifies the proof over RDFC-1.0 canonical form, that the issuer controls
 * the verification method, the proof purpose, validity, holder binding and status; issuer trust via the client.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';
import { bytes, decodeMultibase, didError, findVerificationMethod, hasRelationship, samePublicKey, verificationMethodPublicKey,
  verifySignature, extractIssuerInfo, issuerTrustQuery, type TrustClient, type DidDocument, type Jwk } from '@vctrust/trust-client';
import { canonize, createDocumentLoader, type DocumentLoader, type LoaderStats } from './jsonld.js';
import { checkBitstringStatus } from './status.js';
import { Checks, finish, type VerificationReport } from './report.js';

const SUPPORTED = new Set(['Ed25519Signature2020', 'DataIntegrityProof']);

export interface LdpVerifyOptions {
  trust?: TrustClient;
  fetch?: typeof fetch;
  documentLoader?: DocumentLoader;
  holderDid?: string;
  holderJwk?: Jwk;
  now?: Date;
  credentialIssuer?: string;
  checkStatus?: boolean;
}

function issuerIdOf(vc: Record<string, unknown>): string | undefined {
  const i = vc.issuer;
  return typeof i === 'string' ? i : (i as { id?: string } | undefined)?.id;
}

export async function verifyLdpVc(vcIn: Record<string, unknown> | string, opts: LdpVerifyOptions): Promise<VerificationReport> {
  const vc = (typeof vcIn === 'string' ? JSON.parse(vcIn) : vcIn) as Record<string, unknown>;
  const f = opts.fetch ?? fetch;
  const stats: LoaderStats = { remote: new Set() };
  const loader = opts.documentLoader ?? createDocumentLoader(f, stats);
  const checks = new Checks();
  const now = opts.now ?? new Date();
  const issuerInfo = extractIssuerInfo(vc, 'ldp_vc');
  const issuerId = issuerIdOf(vc);
  const proofs = (Array.isArray(vc.proof) ? vc.proof : vc.proof ? [vc.proof] : []) as Record<string, unknown>[];
  const proof = proofs[0];
  const contexts = vc['@context'];
  const v2 = Array.isArray(contexts) && contexts[0] === 'https://www.w3.org/ns/credentials/v2';

  if (!proof) checks.fail('ldp.proof', 'Proof', 'Credential has no proof');
  else if (!SUPPORTED.has(String(proof.type))) checks.fail('ldp.proof', 'Proof', `Unsupported proof type ${String(proof.type)}`);
  else {
    const suite = proof.type === 'DataIntegrityProof' ? String(proof.cryptosuite) : String(proof.type);
    const vmId = String(proof.verificationMethod ?? '');
    try {
      // 1. Resolve the verification method
      const vmDid = vmId.split('#')[0]!;
      // The full DID URL lets the trust client skip a cached/snapshot document that lacks this (rotated) key.
      const resolved = opts.trust ? await opts.trust.resolveDid(vmId) : null;
      if (!resolved?.didDocument) throw new Error(`Cannot resolve ${vmDid}: ${resolved ? didError(resolved) : 'no resolver'}`);
      const vm = findVerificationMethod(resolved.didDocument, vmId);
      if (!vm) throw new Error(`Verification method ${vmId} not found in ${vmDid}`);
      const key = verificationMethodPublicKey(vm);
      checks.pass('ldp.vm', 'Verification method', `${vmId} (${vm.type}, resolved via ${String(resolved.didResolutionMetadata.source ?? 'trust-service')})`);

      // 2. Issuer controls the key
      if (vmDid === issuerId) checks.pass('ldp.controller', 'Key controlled by issuer', issuerId);
      else if (issuerId?.startsWith('did:') && opts.trust) {
        const issuerDoc = (await opts.trust.resolveDid(issuerId)).didDocument as DidDocument | null;
        const equivalent = issuerDoc && (issuerDoc.verificationMethod ?? []).some((m) => {
          try { return samePublicKey(verificationMethodPublicKey(m), key); } catch { return false; }
        });
        if (equivalent) checks.warn('ldp.controller', 'Key controlled by issuer', `Key is published under ${vmDid}; the issuer DID document lists the same key`);
        else checks.fail('ldp.controller', 'Key controlled by issuer', `Verification method DID ${vmDid} is not the issuer ${issuerId}`);
      } else checks.fail('ldp.controller', 'Key controlled by issuer', `Verification method DID ${vmDid} is not the issuer ${String(issuerId)}`);

      // 3. Proof purpose
      const rel = hasRelationship(resolved.didDocument, 'assertionMethod', vmId, true);
      if (proof.proofPurpose !== 'assertionMethod') checks.fail('ldp.purpose', 'Proof purpose', `Expected assertionMethod, got ${String(proof.proofPurpose)}`);
      else if (rel === 'yes') checks.pass('ldp.purpose', 'Proof purpose', 'assertionMethod');
      else if (rel === 'lenient') checks.warn('ldp.purpose', 'Proof purpose', 'assertionMethod lists the bare DID instead of the verification method');
      else checks.fail('ldp.purpose', 'Proof purpose', 'Verification method is not authorized for assertionMethod');

      // 4. Signature over RDFC-1.0 canonical form
      const { proofValue, ...proofConfig } = proof;
      const unsecured = { ...vc };
      delete unsecured.proof;
      const configDoc = { ...proofConfig, '@context': contexts };
      let docC: string;
      let cfgC: string;
      let safeOk = true;
      try {
        [docC, cfgC] = [await canonize(unsecured, loader, true), await canonize(configDoc, loader, true)];
      } catch (e) {
        safeOk = false;
        [docC, cfgC] = [await canonize(unsecured, loader, false), await canonize(configDoc, loader, false)];
        checks.warn('ldp.jsonld_safe', 'JSON-LD terms', `Some terms are not defined by the @context and are not covered by the signature: ${(e as Error).message.slice(0, 160)}`);
      }
      const p384 = suite === 'ecdsa-rdfc-2019' && key.kty === 'EC' && key.crv === 'P-384';
      const h = p384 ? sha384 : sha256;
      const hashData = bytes.concatBytes(h(bytes.utf8Encode(cfgC)), h(bytes.utf8Encode(docC)));
      const sig = decodeMultibase(String(proofValue));
      let ok: boolean;
      if (suite === 'Ed25519Signature2020' || suite === 'eddsa-rdfc-2022') ok = key.kty === 'OKP' && ed25519.verify(sig, hashData, key.x);
      else if (suite === 'ecdsa-rdfc-2019') ok = verifySignature(p384 ? 'ES384' : 'ES256', key, hashData, sig, 'raw');
      else throw new Error(`Unsupported cryptosuite ${suite}`);
      if (ok) checks.pass('ldp.signature', 'Issuer signature', `${suite} over RDFC-1.0${safeOk ? '' : ' (non-strict)'}`);
      else checks.fail('ldp.signature', 'Issuer signature', `${suite} signature does not verify`);
      if (proof.expires && new Date(String(proof.expires)) < now) checks.fail('ldp.proof_expiry', 'Proof expiry', `Proof expired ${String(proof.expires)}`);
      if (stats.remote.size > 0) checks.warn('ldp.contexts', 'JSON-LD contexts', `Fetched remotely: ${[...stats.remote].join(', ')}`);
    } catch (e) {
      checks.fail('ldp.signature', 'Issuer signature', (e as Error).message);
    }
  }

  // Validity
  const from = String(vc.validFrom ?? vc.issuanceDate ?? '');
  const until = vc.validUntil ?? vc.expirationDate;
  if (from && new Date(from) > now) checks.fail('ldp.validity', 'Validity period', `Not valid before ${from}`);
  else if (until && new Date(String(until)) < now) checks.fail('ldp.validity', 'Validity period', `Expired ${String(until)}`);
  else checks.pass('ldp.validity', 'Validity period', `${from || 'n/a'} – ${until ? String(until) : 'no expiry'}`);
  if (!v2) checks.warn('ldp.vcdm', 'Data model', 'Not a VCDM 2.0 credential');

  // Holder binding
  const subject = (Array.isArray(vc.credentialSubject) ? vc.credentialSubject[0] : vc.credentialSubject) as Record<string, unknown> | undefined;
  const subjectId = typeof subject?.id === 'string' ? subject.id.split('#')[0] : undefined;
  if (!subjectId) checks.warn('ldp.holder', 'Holder binding', 'credentialSubject has no id (bearer credential)');
  else if (opts.holderDid) {
    if (subjectId === opts.holderDid.split('#')[0]) checks.pass('ldp.holder', 'Holder binding', 'credentialSubject.id is this wallet\'s DID');
    else checks.fail('ldp.holder', 'Holder binding', `credentialSubject.id ${subjectId} is not this wallet`);
  } else checks.pass('ldp.holder', 'Holder binding', subjectId);

  const trust = opts.trust ? await opts.trust.evaluate(issuerTrustQuery(issuerInfo, opts.credentialIssuer)) : null;

  // Status: the status list credential is itself verified (proof, issuer, purpose) — it may come through a relay.
  const status = vc.credentialStatus as Record<string, unknown> | undefined;
  if (status && opts.checkStatus !== false && (status.type === 'BitstringStatusListEntry' || status.type === 'StatusList2021Entry')) {
    const s = await checkBitstringStatus(status, { trust: opts.trust, fetch: f, issuer: issuerId, decision: trust, now,
      verifyListCredential: async (list) => {
        const r = await verifyLdpVc(list, { trust: opts.trust, fetch: f, documentLoader: loader, now, checkStatus: false });
        return { ok: r.valid, detail: r.checks.filter((c) => c.status === 'fail' && c.id !== 'issuer.trust').map((c) => c.detail).join('; ') };
      } });
    if (s.status === 'valid') checks.pass('ldp.status', 'Status', s.detail);
    else if (s.status === 'unknown') checks.warn('ldp.status', 'Status', s.detail);
    else checks.fail('ldp.status', 'Status', `${s.status}: ${s.detail}`);
  }

  const claims = { ...(subject ?? {}) };
  return finish('ldp_vc', checks, issuerInfo, trust, claims, { credentialType: issuerInfo.credentialType,
    validFrom: from || undefined, validUntil: until ? String(until) : undefined });
}
