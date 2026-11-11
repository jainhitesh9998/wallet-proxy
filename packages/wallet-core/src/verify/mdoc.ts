/**
 * ISO/IEC 18013-5 mdoc as OpenID4VCI issues it (format mso_mdoc, Appendix A.2.4: the base64url IssuerSigned).
 *
 * Checked, as ISO 18013-5 §9.1.2 and §9.3.1 lay out: the COSE_Sign1 issuerAuth verifies with the Document Signer
 * certificate's key; the MobileSecurityObject is a tag-24 byte string, version 1.0, with a known digest algorithm;
 * every IssuerSignedItem is a tag-24 byte string whose digest is the one the MSO lists under its digestID; the
 * validity dates are tdates and include now; the docType is the one asked for; the device key is this wallet's.
 * The Document Signer chain is evaluated through the trust client (IACA anchors, CRLs), and the MSO's status (Token
 * Status List in CWT form) is checked. An encoding the standard does not allow fails the credential.
 */
import type { Jwk, TrustClient, TrustDecision } from '@vctrust/trust-client';
import { cbor, bytes, coseAlgToJose, digest, extractIssuerInfo, issuerTrustQuery, jwkThumbprint, parseCertificate, parseCoseSign1, coseX5chain,
  verifySignature, type IssuerInfo } from '@vctrust/trust-client/primitives';
import { Checks, CLOCK_SKEW_MS, finish, type VerificationReport } from './report.js';

const { Tagged, mapGet } = cbor;

export function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array, externalAad = new Uint8Array()): Uint8Array {
  return cbor.encode(['Signature1', protectedBytes, externalAad, payload]);
}

/** COSE_Key (EC2) → JWK. */
export function coseKeyToJwk(key: unknown): Jwk | null {
  const kty = mapGet(key, 1);
  if (kty !== 2) return null;
  const crv = mapGet(key, -1);
  const name = crv === 1 ? 'P-256' : crv === 2 ? 'P-384' : crv === 3 ? 'P-521' : undefined;
  const x = mapGet(key, -2);
  const y = mapGet(key, -3);
  if (!name || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) return null;
  return { kty: 'EC', crv: name, x: bytes.base64UrlEncode(x), y: bytes.base64UrlEncode(y) };
}

export function jwkToCoseKey(jwk: Jwk): Map<number, unknown> {
  const crv = jwk.crv === 'P-256' ? 1 : jwk.crv === 'P-384' ? 2 : 3;
  return new Map<number, unknown>([[1, 2], [-1, crv], [-2, bytes.base64UrlDecode(jwk.x!)], [-3, bytes.base64UrlDecode(jwk.y!)]]);
}

/** A tdate (ISO 18013-5 §7.2.1: #6.0(tstr), RFC 3339 in UTC), or undefined for anything else. */
function tdate(v: unknown): Date | undefined {
  if (!(v instanceof Tagged) || v.tag !== 0 || typeof v.value !== 'string') return undefined;
  const d = new Date(v.value);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** Converts decoded CBOR element values into JSON-friendly display values. */
export function displayValue(v: unknown): unknown {
  if (v instanceof Tagged) return displayValue(v.value);
  if (v instanceof Uint8Array) return { $bytes: bytes.base64Encode(v), length: v.length };
  if (v instanceof Map) return Object.fromEntries([...v.entries()].map(([k, x]) => [String(k), displayValue(x)]));
  if (Array.isArray(v)) return v.map(displayValue);
  if (typeof v === 'bigint') return v.toString();
  return v;
}

export interface IssuerSignedItem {
  digestID: number;
  random: Uint8Array;
  elementIdentifier: string;
  elementValue: unknown;
  /** the IssuerSignedItemBytes (tag 24) as received: what the MSO digest covers, and what a DeviceResponse sends on */
  tagged: unknown;
}

/** The IssuerSignedItems per namespace. Each must be IssuerSignedItemBytes: a tag-24 byte string (ISO 18013-5 §8.3.2.1.2.2). */
export function issuerSignedItems(issuerSigned: unknown): Map<string, IssuerSignedItem[]> {
  const out = new Map<string, IssuerSignedItem[]>();
  const ns = mapGet(issuerSigned, 'nameSpaces');
  if (ns === undefined) return out;
  if (!(ns instanceof Map)) throw new Error('nameSpaces is not a map');
  for (const [name, items] of ns) {
    if (!Array.isArray(items)) throw new Error(`Namespace ${String(name)} is not an array of items`);
    const list: IssuerSignedItem[] = [];
    for (const it of items) {
      if (!(it instanceof Tagged) || it.tag !== 24 || !(it.value instanceof Uint8Array)) throw new Error(`An item of ${String(name)} is not a tag-24 byte string (IssuerSignedItemBytes)`);
      const inner = cbor.decode(it.value);
      const [digestID, random, elementIdentifier] = [mapGet(inner, 'digestID'), mapGet(inner, 'random'), mapGet(inner, 'elementIdentifier')];
      if (!Number.isSafeInteger(Number(digestID)) || Number(digestID) < 0 || !(random instanceof Uint8Array) || typeof elementIdentifier !== 'string') {
        throw new Error(`An item of ${String(name)} lacks digestID, random or elementIdentifier`);
      }
      list.push({ digestID: Number(digestID), random, elementIdentifier, elementValue: mapGet(inner, 'elementValue'), tagged: it });
    }
    out.set(String(name), list);
  }
  return out;
}

/** The bare IssuerSigned structure of a credential as issued (OpenID4VCI 1.0 Appendix A.2.4): nothing wrapped around it. */
export function decodeIssuedMdoc(credential: string): unknown {
  if (typeof credential !== 'string' || !/^[A-Za-z0-9_-]+$/.test(credential)) throw new Error('The credential is not a base64url string');
  const issuerSigned = cbor.decode(bytes.base64UrlDecode(credential));
  if (!(issuerSigned instanceof Map) || !issuerSigned.has('issuerAuth')) throw new Error('The credential is not an IssuerSigned structure (OpenID4VCI 1.0 A.2.4)');
  for (const k of issuerSigned.keys()) if (k !== 'issuerAuth' && k !== 'nameSpaces') throw new Error(`IssuerSigned has an unknown member ${String(k)}`);
  return issuerSigned;
}

const DIGESTS = new Set(['SHA-256', 'SHA-384', 'SHA-512']);

export interface MdocVerifyOptions {
  trust: TrustClient;
  /** the key this wallet proved to the issuer */
  holderJwk?: Jwk;
  now?: Date;
  checkStatus?: boolean;
  /** what the wallet asked for: the configuration's doctype */
  expected?: { doctype?: string };
}

export async function verifyMdoc(credential: string, opts: MdocVerifyOptions): Promise<VerificationReport> {
  const checks = new Checks();
  const now = opts.now ?? new Date();
  const claims: Record<string, Record<string, unknown>> = {};
  let issuerInfo: IssuerInfo = { format: 'mso_mdoc' };
  let validFrom: Date | undefined;
  let validUntil: Date | undefined;
  let docType: string | undefined;
  let statusRef: { idx: number; uri: string; certificate?: Uint8Array } | undefined;
  try {
    const issuerSigned = decodeIssuedMdoc(credential);
    issuerInfo = extractIssuerInfo(credential, 'mso_mdoc');
    const auth = parseCoseSign1(mapGet(issuerSigned, 'issuerAuth'));
    const alg = auth.protectedHeader.get(1);
    if (typeof alg !== 'number') throw new Error('issuerAuth has no alg in its protected header');
    const chain = coseX5chain(auth);
    if (chain.length === 0) throw new Error('issuerAuth carries no x5chain');
    const ds = parseCertificate(chain[0]!);
    if (!ds.publicKey) throw new Error(`Unsupported Document Signer key ${ds.publicKeyAlgorithm}`);
    if (!auth.payload) throw new Error('issuerAuth has a detached payload');
    if (verifySignature(coseAlgToJose(alg), ds.publicKey, sigStructure(auth.protectedBytes, auth.payload), auth.signature, 'raw')) {
      checks.pass('mdoc.signature', 'Issuer signature (COSE_Sign1)', `alg ${alg}, Document Signer ${ds.subject}`);
    } else checks.fail('mdoc.signature', 'Issuer signature (COSE_Sign1)', 'The signature does not verify with the Document Signer key');

    const wrapped = cbor.decode(auth.payload);
    if (!(wrapped instanceof Tagged) || wrapped.tag !== 24 || !(wrapped.value instanceof Uint8Array)) throw new Error('The issuerAuth payload is not MobileSecurityObjectBytes (a tag-24 byte string, ISO 18013-5 §9.1.2.4)');
    const mso = cbor.decode(wrapped.value);
    if (mapGet(mso, 'version') !== '1.0') throw new Error(`Unsupported MSO version ${String(mapGet(mso, 'version'))}`);
    docType = typeof mapGet(mso, 'docType') === 'string' ? mapGet(mso, 'docType') as string : undefined;
    if (!docType) checks.fail('mdoc.doctype', 'Document type', 'The MSO has no docType');
    else if (opts.expected?.doctype !== undefined && opts.expected.doctype !== docType) checks.fail('mdoc.doctype', 'Document type', `docType ${docType} is not the requested ${opts.expected.doctype}`);
    else checks.pass('mdoc.doctype', 'Document type', docType);

    const algName = mapGet(mso, 'digestAlgorithm');
    if (typeof algName !== 'string' || !DIGESTS.has(algName)) throw new Error(`Unsupported or missing digestAlgorithm ${String(algName)}`);
    const valueDigests = mapGet(mso, 'valueDigests');
    let elements = 0;
    const bad: string[] = [];
    for (const [ns, items] of issuerSignedItems(issuerSigned)) {
      const expected = mapGet(valueDigests, ns);
      claims[ns] = {};
      const ids = new Set<number>();
      for (const item of items) {
        const want = mapGet(expected, item.digestID);
        const unique = !ids.has(item.digestID) && !Object.prototype.hasOwnProperty.call(claims[ns], item.elementIdentifier);
        ids.add(item.digestID);
        // ISO 18013-5 §9.1.2.5: the digest is taken over the IssuerSignedItemBytes; the random is at least 16 bytes.
        if (unique && item.random.length >= 16 && want instanceof Uint8Array && bytes.bytesEqual(digest(algName as 'SHA-256', cbor.encode(item.tagged)), want)) elements++;
        else bad.push(`${ns}/${item.elementIdentifier}`);
        claims[ns]![item.elementIdentifier] = displayValue(item.elementValue);
      }
    }
    if (bad.length) checks.fail('mdoc.digests', 'Data element digests', `Not covered by the MSO: ${bad.slice(0, 5).join(', ')}${bad.length > 5 ? ` and ${bad.length - 5} more` : ''}`);
    else checks.pass('mdoc.digests', 'Data element digests', `${elements} element(s) match the MSO (${algName})`);

    const vi = mapGet(mso, 'validityInfo');
    const signed = tdate(mapGet(vi, 'signed'));
    validFrom = tdate(mapGet(vi, 'validFrom'));
    validUntil = tdate(mapGet(vi, 'validUntil'));
    if (!signed || !validFrom || !validUntil) checks.fail('mdoc.validity', 'Validity period', 'validityInfo needs signed, validFrom and validUntil as tdate (tag 0) values');
    else if (validFrom < signed || validUntil <= validFrom) checks.fail('mdoc.validity', 'Validity period', 'validFrom is before signed, or validUntil is not after validFrom (ISO 18013-5 §9.1.2.4)');
    // ISO 18013-5 §9.3.1: the MSO was signed while the Document Signer certificate was valid.
    else if (signed < ds.notBefore || signed > ds.notAfter) checks.fail('mdoc.validity', 'Validity period', `Signed ${signed.toISOString()}, outside the validity of the Document Signer certificate`);
    else if (now.getTime() + CLOCK_SKEW_MS < validFrom.getTime() || now > validUntil) checks.fail('mdoc.validity', 'Validity period', `Not valid now (${validFrom.toISOString()} – ${validUntil.toISOString()})`);
    else checks.pass('mdoc.validity', 'Validity period', `${validFrom.toISOString()} – ${validUntil.toISOString()}`);

    const deviceKey = coseKeyToJwk(mapGet(mapGet(mso, 'deviceKeyInfo'), 'deviceKey'));
    if (!deviceKey) checks.fail('mdoc.device_key', 'Holder binding', 'The MSO has no usable deviceKey');
    else if (opts.holderJwk && jwkThumbprint(deviceKey) !== jwkThumbprint(opts.holderJwk)) checks.fail('mdoc.device_key', 'Holder binding', 'deviceKey is not the key this wallet proved');
    else checks.pass('mdoc.device_key', 'Holder binding', opts.holderJwk ? 'deviceKey is this wallet\'s key' : `deviceKey ${deviceKey.crv}`);

    const status = mapGet(mso, 'status');
    const ref = mapGet(status, 'status_list');
    if (ref !== undefined) {
      const [idx, uri, certificate] = [mapGet(ref, 'idx'), mapGet(ref, 'uri'), mapGet(ref, 'certificate')];
      if (!Number.isSafeInteger(Number(idx)) || Number(idx) < 0 || typeof uri !== 'string') checks.fail('mdoc.status', 'Status', 'The MSO status_list has no usable idx and uri');
      else statusRef = { idx: Number(idx), uri, ...(certificate instanceof Uint8Array ? { certificate } : {}) };
    } else if (status !== undefined) {
      checks.warn('mdoc.status', 'Status', 'The MSO names a status mechanism other than a status list; whether the credential is revoked is unknown');
    }
  } catch (e) {
    checks.fail('mdoc.structure', 'Credential structure', (e as Error).message.slice(0, 300));
  }
  let trust: TrustDecision | null = null;
  if (issuerInfo.x5c?.length) trust = await opts.trust.evaluate(issuerTrustQuery({ ...issuerInfo, credentialType: issuerInfo.credentialType ?? docType }));
  if (statusRef && opts.checkStatus !== false) {
    const s = await opts.trust.checkTokenStatus(statusRef, { signerX5c: issuerInfo.x5c, decision: trust, now, form: 'cwt' });
    if (s.status === 'valid') checks.pass('mdoc.status', 'Status', s.detail);
    else if (s.status === 'unknown') checks.warn('mdoc.status', 'Status', s.detail);
    else checks.fail('mdoc.status', 'Status', `${s.status}: ${s.detail}`);
  }
  return finish('mso_mdoc', checks, issuerInfo, trust, claims, { credentialType: docType,
    validFrom: validFrom?.toISOString(), validUntil: validUntil?.toISOString() });
}
