#!/usr/bin/env node
// Summarise a saved credential response: node inspect.mjs samples/<file>.json
// ldp_vc: @context, type, issuer, proof type/cryptosuite/verificationMethod, credentialStatus.
// mso_mdoc: top-level CBOR structure, docType, namespaces/elements, MSO (digestAlgorithm,
//   validityInfo, deviceKeyInfo), COSE alg, and the x5chain subject/issuer DNs.
import { decode, encode, Tag } from 'cbor-x';
import crypto from 'node:crypto';
import fs from 'node:fs';

const COSE_ALGS = { [-7]: 'ES256', [-35]: 'ES384', [-36]: 'ES512', [-8]: 'EdDSA', [-37]: 'PS256', [-257]: 'RS256' };

const unwrap24 = (v) => (v instanceof Tag && v.tag === 24 ? decode(v.value) : v);
// JSON-friendly rendering of decoded CBOR: bstr -> base64url, Tag -> {tag, value}, Map -> object.
const plain = (v) => {
  if (v instanceof Uint8Array) return `bstr:${Buffer.from(v).toString('base64url')}`;
  if (v instanceof Tag) return { tag: v.tag, value: plain(v.value) };
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]));
  if (v instanceof Date) return `Date(${v.toISOString()})`;
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
  return v;
};
const asMap = (m) => (m instanceof Map ? Object.fromEntries(m) : m);

export function inspectMdoc(b64) {
  const isB64u = !/[+/=]/.test(b64);
  const bytes = Buffer.from(b64, isB64u ? 'base64url' : 'base64');
  const top = asMap(decode(bytes));
  const out = { encoding: isB64u ? 'base64url' : 'base64 (standard)', topLevelKeys: Object.keys(top) };
  const issuerSigned = asMap(top.issuerSigned ?? top);
  if (top.docType) out.docType = top.docType;

  out.nameSpaces = {};
  for (const [ns, items] of Object.entries(asMap(issuerSigned.nameSpaces))) {
    out.nameSpaces[ns] = items.map((it) => {
      const item = asMap(unwrap24(it));
      const v = item.elementValue;
      const shown = v instanceof Uint8Array ? `<bstr ${v.length} bytes>` : JSON.stringify(plain(v));
      return `${item.elementIdentifier} = ${shown}`;
    });
  }

  const [protectedBytes, unprotected, payload, signature] = issuerSigned.issuerAuth;
  const prot = asMap(decode(protectedBytes));
  const unprot = asMap(unprotected);
  out.cose = { protectedHeader: prot, alg: COSE_ALGS[prot[1]] ?? prot[1], signatureBytes: signature.length,
    unprotectedHeaderLabels: Object.keys(unprot) };

  // x5chain is label 33; may be in protected or unprotected header; single bstr or array.
  let x5 = unprot[33] ?? prot[33];
  if (x5) {
    x5 = Array.isArray(x5) ? x5 : [x5];
    out.x5chain = x5.map((der) => {
      const c = new crypto.X509Certificate(Buffer.from(der));
      return { subject: c.subject.replace(/\n/g, ', '), issuer: c.issuer.replace(/\n/g, ', '),
        serialNumber: c.serialNumber, validFrom: c.validFrom, validTo: c.validTo,
        publicKey: `${c.publicKey.asymmetricKeyType} ${c.publicKey.asymmetricKeyDetails?.namedCurve ?? ''}`.trim(),
        ca: c.ca, pem: c.toString() };
    });
  }

  // COSE_Sign1 check: Sig_structure = ["Signature1", protected, h'', payload], ES256 raw r||s.
  if (out.x5chain?.length) {
    const leaf = new crypto.X509Certificate(Buffer.from(x5[0]));
    const toBeSigned = encode(['Signature1', Buffer.from(protectedBytes), Buffer.alloc(0), Buffer.from(payload)]);
    out.cose.signatureVerifiesWithX5chainLeaf = crypto.verify('sha256', toBeSigned,
      { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature));
  }
  out.cose.payloadIsTag24Wrapped = Buffer.from(payload)[0] === 0xd8 && Buffer.from(payload)[1] === 0x18;
  const mso = asMap(unwrap24(decode(payload)));
  out.mso = {
    version: mso.version, digestAlgorithm: mso.digestAlgorithm, docType: mso.docType,
    validityInfo: plain(mso.validityInfo),
    valueDigests: Object.fromEntries(Object.entries(asMap(mso.valueDigests)).map(([k, v]) => [k, `${asMap(v) instanceof Object ? Object.keys(asMap(v)).length : '?'} digests`])),
    deviceKey: plain(asMap(mso.deviceKeyInfo)?.deviceKey),
    otherKeys: Object.keys(mso).filter((k) => !['version', 'digestAlgorithm', 'docType', 'validityInfo', 'valueDigests', 'deviceKeyInfo'].includes(k)),
  };
  // valueDigests check: SHA-256 over the full #6.24(bstr) encoding of each IssuerSignedItem.
  const bstrHead = (n) => (n < 24 ? Buffer.from([0x40 + n]) : n < 256 ? Buffer.from([0x58, n])
    : n < 65536 ? Buffer.from([0x59, n >> 8, n & 255]) : Buffer.from([0x5a, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]));
  let checked = 0; let ok = 0;
  for (const [ns, items] of Object.entries(asMap(issuerSigned.nameSpaces))) {
    const digests = asMap(asMap(mso.valueDigests)[ns]);
    for (const it of items) {
      const raw = Buffer.from(it.value);
      const enc = Buffer.concat([Buffer.from([0xd8, 0x18]), bstrHead(raw.length), raw]);
      const item = asMap(decode(raw));
      const want = Buffer.from(digests[item.digestID]);
      checked++; if (crypto.createHash('sha256').update(enc).digest().equals(want)) ok++;
    }
  }
  out.valueDigestsMatching = `${ok}/${checked}`;
  return out;
}

export function inspectLdp(vc) {
  return {
    '@context': vc['@context'], type: vc.type, issuer: vc.issuer, validFrom: vc.validFrom, validUntil: vc.validUntil,
    issuanceDate: vc.issuanceDate, credentialSubjectId: vc.credentialSubject?.id?.slice(0, 60) + '...',
    proof: vc.proof && { type: vc.proof.type, cryptosuite: vc.proof.cryptosuite, proofPurpose: vc.proof.proofPurpose,
      verificationMethod: vc.proof.verificationMethod, created: vc.proof.created },
    credentialStatus: vc.credentialStatus && { type: vc.credentialStatus.type, statusPurpose: vc.credentialStatus.statusPurpose,
      statusListIndex: vc.credentialStatus.statusListIndex },
    renderMethod: vc.renderMethod?.map((r) => r.type),
  };
}

if (process.argv[2]) {
  const resp = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const cred = resp.credentials?.[0]?.credential ?? resp.credential;
  const summary = typeof cred === 'string' ? inspectMdoc(cred) : inspectLdp(cred);
  console.log(JSON.stringify(summary, (k, v) => (v instanceof Map ? Object.fromEntries(v)
    : v instanceof Uint8Array ? `<bstr ${Buffer.from(v).toString('base64url').slice(0, 43)}>` : v), 2));
}
