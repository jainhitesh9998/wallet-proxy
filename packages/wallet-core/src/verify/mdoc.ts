/**
 * ISO/IEC 18013-5 mdoc (IssuerSigned) verification: COSE_Sign1 issuerAuth with the Document Signer key,
 * every IssuerSignedItem digest against the MSO, validity window, docType and device key binding, issuer
 * trust (DS chain → IACA, with CRL revocation) through the trust client, and the MSO's status
 * (Token Status List in CWT form).
 */
import { cbor, bytes, coseAlgToJose, decodeIssuerSigned, digest, parseCertificate, parseCoseSign1, coseX5chain,
  verifySignature, type Jwk, type TrustClient, extractIssuerInfo, issuerTrustQuery } from '@vctrust/trust-client';
import { Checks, finish, type VerificationReport } from './report.js';
import { checkTokenStatus, type StatusListReference } from './status.js';

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

function dateOf(v: unknown): Date | undefined {
  const s = v instanceof Tagged ? v.value : v;
  if (typeof s !== 'string') return undefined;
  const d = new Date(s);
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
  /** encoded tag-24 bytes as received (needed to re-send in a DeviceResponse) */
  tagged: unknown;
}

export function issuerSignedItems(issuerSigned: unknown): Map<string, IssuerSignedItem[]> {
  const out = new Map<string, IssuerSignedItem[]>();
  const ns = mapGet(issuerSigned, 'nameSpaces');
  if (!(ns instanceof Map)) return out;
  for (const [name, items] of ns) {
    const list: IssuerSignedItem[] = [];
    for (const it of (items as unknown[]) ?? []) {
      const inner = it instanceof Tagged && it.value instanceof Uint8Array ? cbor.decode(it.value) : it;
      list.push({ digestID: Number(mapGet(inner, 'digestID')), random: mapGet(inner, 'random') as Uint8Array,
        elementIdentifier: String(mapGet(inner, 'elementIdentifier')), elementValue: mapGet(inner, 'elementValue'), tagged: it });
    }
    out.set(String(name), list);
  }
  return out;
}

export async function verifyMdoc(credential: string, opts: { trust?: TrustClient; holderJwk?: Jwk; now?: Date; credentialIssuer?: string;
  expectedDocType?: string; fetch?: typeof fetch; checkStatus?: boolean }): Promise<VerificationReport> {
  const checks = new Checks();
  const now = opts.now ?? new Date();
  const claims: Record<string, Record<string, unknown>> = {};
  let issuerInfo = { format: 'mso_mdoc' } as ReturnType<typeof extractIssuerInfo>;
  let validFrom: Date | undefined;
  let validUntil: Date | undefined;
  let docType: string | undefined;
  let statusRef: StatusListReference | undefined;
  try {
    const raw = cbor.decode(bytes.base64UrlDecode(credential));
    if (!mapGet(raw, 'issuerAuth')) {
      checks.warn('mdoc.encoding', 'Credential encoding', 'Not a bare IssuerSigned (OpenID4VCI 1.0 A.2.4); unwrapped a {docType, issuerSigned} container');
    } else checks.pass('mdoc.encoding', 'Credential encoding', 'base64url IssuerSigned');
    const { issuerSigned, docType: wrapperDocType } = decodeIssuerSigned(credential);
    issuerInfo = extractIssuerInfo(credential, 'mso_mdoc');
    const auth = parseCoseSign1(mapGet(issuerSigned, 'issuerAuth'));
    const alg = auth.protectedHeader.get(1) as number;
    const chain = coseX5chain(auth);
    if (chain.length === 0) throw new Error('issuerAuth carries no x5chain');
    const ds = parseCertificate(chain[0]!);
    if (!ds.publicKey) throw new Error(`Unsupported Document Signer key ${ds.publicKeyAlgorithm}`);
    if (!auth.payload) throw new Error('issuerAuth has a detached payload');
    const sigOk = verifySignature(coseAlgToJose(alg), ds.publicKey, sigStructure(auth.protectedBytes, auth.payload), auth.signature, 'raw');
    if (sigOk) checks.pass('mdoc.signature', 'Issuer signature (COSE_Sign1)', `alg ${alg}, signer ${ds.subject}`);
    else checks.fail('mdoc.signature', 'Issuer signature (COSE_Sign1)', 'Signature does not verify with the Document Signer key');

    let mso = cbor.decode(auth.payload);
    if (mso instanceof Tagged && mso.tag === 24 && mso.value instanceof Uint8Array) mso = cbor.decode(mso.value);
    else checks.warn('mdoc.mso_encoding', 'MSO encoding', 'MobileSecurityObject is not wrapped in tag 24 (ISO 18013-5 §9.1.2.4)');
    docType = String(mapGet(mso, 'docType'));
    if ((wrapperDocType && wrapperDocType !== docType) || (opts.expectedDocType && opts.expectedDocType !== docType)) {
      checks.fail('mdoc.doctype', 'Document type', `MSO docType ${docType} does not match ${wrapperDocType ?? opts.expectedDocType}`);
    } else checks.pass('mdoc.doctype', 'Document type', docType);

    const algName = String(mapGet(mso, 'digestAlgorithm') ?? 'SHA-256').toUpperCase().replace('SHA', 'SHA-').replace('--', '-') as 'SHA-256';
    const valueDigests = mapGet(mso, 'valueDigests');
    let digestsOk = 0;
    let digestsBad = 0;
    for (const [ns, items] of issuerSignedItems(issuerSigned)) {
      const expected = mapGet(valueDigests, ns);
      claims[ns] = {};
      for (const item of items) {
        const encoded = item.tagged instanceof Tagged ? cbor.encode(item.tagged) : cbor.encode(new Tagged(24, cbor.encode(item.tagged)));
        const want = mapGet(expected, item.digestID);
        if (want instanceof Uint8Array && bytes.bytesEqual(digest(algName, encoded), want)) digestsOk++;
        else digestsBad++;
        claims[ns]![item.elementIdentifier] = displayValue(item.elementValue);
      }
    }
    if (digestsBad === 0 && digestsOk > 0) checks.pass('mdoc.digests', 'Data element digests', `${digestsOk} element(s) match the MSO (${algName})`);
    else checks.fail('mdoc.digests', 'Data element digests', `${digestsBad} of ${digestsOk + digestsBad} element(s) do not match the MSO`);

    const vi = mapGet(mso, 'validityInfo');
    validFrom = dateOf(mapGet(vi, 'validFrom'));
    validUntil = dateOf(mapGet(vi, 'validUntil'));
    if (!mapGet(vi, 'signed')) checks.warn('mdoc.validity_signed', 'Signing time', 'validityInfo.signed is missing');
    if (!(mapGet(vi, 'validFrom') instanceof Tagged)) checks.warn('mdoc.validity_encoding', 'Validity encoding', 'validityInfo dates are not tdate (tag 0)');
    if (!validFrom || !validUntil) checks.fail('mdoc.validity', 'Validity period', 'validFrom/validUntil missing or unparseable');
    else if (now < validFrom || now > validUntil) checks.fail('mdoc.validity', 'Validity period', `Not valid now (${validFrom.toISOString()} – ${validUntil.toISOString()})`);
    else checks.pass('mdoc.validity', 'Validity period', `${validFrom.toISOString()} – ${validUntil.toISOString()}`);

    const deviceKey = coseKeyToJwk(mapGet(mapGet(mso, 'deviceKeyInfo'), 'deviceKey'));
    if (!deviceKey) checks.fail('mdoc.device_key', 'Holder binding', 'MSO has no usable deviceKey');
    else if (opts.holderJwk) {
      const same = deviceKey.x === opts.holderJwk.x && deviceKey.y === opts.holderJwk.y;
      if (same) checks.pass('mdoc.device_key', 'Holder binding', 'deviceKey is this wallet\'s key');
      else checks.fail('mdoc.device_key', 'Holder binding', 'deviceKey does not match the wallet key');
    } else checks.pass('mdoc.device_key', 'Holder binding', `deviceKey ${deviceKey.crv}`);

    const status = mapGet(mso, 'status');
    const ref = mapGet(status, 'status_list');
    if (ref !== undefined) {
      const certificate = mapGet(ref, 'certificate');
      statusRef = { idx: Number(mapGet(ref, 'idx')), uri: String(mapGet(ref, 'uri')), certificate: certificate instanceof Uint8Array ? certificate : undefined };
    } else if (mapGet(status, 'identifier_list') !== undefined) {
      checks.warn('mdoc.status', 'Status', 'Identifier lists are not supported; status not checked');
    }
  } catch (e) {
    checks.fail('mdoc.parse', 'Credential structure', (e as Error).message);
  }
  let trust = null;
  if (opts.trust && issuerInfo.x5c) {
    trust = await opts.trust.evaluate(issuerTrustQuery({ ...issuerInfo, credentialType: issuerInfo.credentialType ?? docType }, opts.credentialIssuer));
  }
  if (statusRef && opts.checkStatus !== false) {
    const s = await checkTokenStatus(statusRef, { trust: opts.trust, fetch: opts.fetch ?? fetch, signerX5c: issuerInfo.x5c, decision: trust, now }, 'cwt');
    if (s.status === 'valid') checks.pass('mdoc.status', 'Status', s.detail);
    else if (s.status === 'unknown') checks.warn('mdoc.status', 'Status', s.detail);
    else checks.fail('mdoc.status', 'Status', `${s.status}: ${s.detail}`);
  }
  return finish('mso_mdoc', checks, issuerInfo, trust, claims, { credentialType: docType,
    validFrom: validFrom?.toISOString(), validUntil: validUntil?.toISOString() });
}
