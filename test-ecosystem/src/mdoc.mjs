/**
 * ISO/IEC 18013-5 mdoc with @owf/mdoc: issuing an mDL under the reference Document Signer (clause 9.1.2.4: the
 * x5chain carries the Document Signer certificate and never the IACA), and verifying IssuerSigned and DeviceResponse
 * structures. The library leaves cryptography and X.509 to its caller; this supplies them from WebCrypto and
 * @peculiar/x509.
 */
import { webcrypto } from 'node:crypto';
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { CoseKey, DateOnly, DeviceKey, DeviceResponse, Issuer, IssuerSigned, SessionTranscript, SignatureAlgorithm, Verifier } from '@owf/mdoc';
import { derOf, validateChain } from './pki.mjs';

export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
export const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DAY = 86_400_000;
/** A 1x1 JPEG: the mDL portrait is mandatory (18013-5 table 5), and this stands in for one. */
const PORTRAIT = Buffer.from('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=', 'base64');
const FULL_DATES = ['birth_date', 'issue_date', 'expiry_date'];

const ECDSA_HASH = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' };
const keyOf = ({ kty, crv, x, y, d }) => ({ kty, crv, x, y, ...(d ? { d } : {}) });

/** WebCrypto parameters of a COSE key: ECDSA with the hash that goes with the curve (ES256, ES384, ES512), or Ed25519. */
async function webKey(coseKey, usage) {
  const jwk = keyOf(coseKey.jwk);
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return { key: await webcrypto.subtle.importKey('jwk', jwk, 'Ed25519', false, [usage]), params: 'Ed25519' };
  if (!ECDSA_HASH[jwk.crv]) throw new Error(`Unsupported key ${jwk.kty} ${jwk.crv}`);
  return { key: await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: jwk.crv }, false, [usage]), params: { name: 'ECDSA', hash: ECDSA_HASH[jwk.crv] } };
}

const noMac = () => { throw new Error('mdoc MAC authentication needs a reader key, which an OpenID4VP session transcript does not have'); };

/** @type {import('@owf/mdoc').MdocContext} */
export const mdocContext = {
  fetch: (input, init) => fetch(input, init),
  crypto: {
    random: (length) => webcrypto.getRandomValues(new Uint8Array(length)),
    digest: async ({ digestAlgorithm, bytes }) => new Uint8Array(await webcrypto.subtle.digest(digestAlgorithm, bytes)),
    hdkf: noMac,
  },
  cose: {
    sign1: {
      sign: async ({ key, toBeSigned }) => {
        const { key: privateKey, params } = await webKey(key, 'sign');
        return new Uint8Array(await webcrypto.subtle.sign(params, privateKey, toBeSigned));
      },
      verify: async ({ key, signature, toBeVerified }) => {
        const { key: publicKey, params } = await webKey(key, 'verify');
        return webcrypto.subtle.verify(params, publicKey, signature, toBeVerified);
      },
    },
    mac0: { authenticate: noMac, verify: noMac },
  },
  x509: {
    getSubjectNameField: ({ certificate, field }) => new x509.X509Certificate(certificate).subjectName.getField(field),
    getPublicKey: async ({ certificate }) => {
      const key = await new x509.X509Certificate(certificate).publicKey.export();
      return CoseKey.fromJwk(keyOf(await webcrypto.subtle.exportKey('jwk', key)));
    },
    verifyCertificateChain: async ({ trustedCertificates, x5chain, now }) => ({ chain: await validateChain(x5chain, trustedCertificates, now) }),
    getCertificateData: async ({ certificate }) => {
      const cert = new x509.X509Certificate(certificate);
      return { issuerName: cert.issuer, subjectName: cert.subject, serialNumber: cert.serialNumber, pem: cert.toString('pem'),
        thumbprint: Buffer.from(await cert.getThumbprint('SHA-256')).toString('hex'), notBefore: cert.notBefore, notAfter: cert.notAfter };
    },
  },
};

/** The mandatory mDL data elements (18013-5 clause 7.2.1, table 5) for a fictitious holder, plus one age attestation. */
const mdlClaims = (now) => ({
  family_name: 'Mustermann', given_name: 'Erika', birth_date: '1990-03-14', issue_date: new Date(now).toISOString().slice(0, 10),
  expiry_date: new Date(now + 5 * 365 * DAY).toISOString().slice(0, 10), issuing_country: 'UT', issuing_authority: 'Reference DMV',
  document_number: 'REF-0001', portrait: PORTRAIT, un_distinguishing_sign: 'UTO', age_over_18: true,
  driving_privileges: [{ vehicle_category_code: 'B', issue_date: new DateOnly('2015-06-01'), expiry_date: new DateOnly('2035-06-01') }],
});

/**
 * Issues an mDL bound to the device key, valid from now until a year from now or the end of the Document Signer
 * certificate, whichever is first.
 * @param {{ pki: import('./pki.mjs').Pki, deviceJwk: JsonWebKey, claims?: Record<string, unknown>, now?: number }} opts
 *   `claims` replace or add data elements of the mDL namespace; the three date elements are given as `YYYY-MM-DD`
 * @returns {Promise<string>} the base64url IssuerSigned structure of an OpenID4VCI Credential Response (A.2.4)
 */
export async function issueMdl({ pki, deviceJwk, claims = {}, now = Date.now() }) {
  const elements = { ...mdlClaims(now), ...claims };
  for (const name of FULL_DATES) elements[name] = new DateOnly(elements[name]);
  const signer = new x509.X509Certificate(pki.ds.pem);
  const issuerSigned = await new Issuer(MDL_DOCTYPE, mdocContext).addIssuerNamespace(MDL_NAMESPACE, elements).sign({
    signingKey: CoseKey.fromJwk(keyOf(pki.ds.privateJwk)), certificates: [new Uint8Array(signer.rawData)],
    algorithm: SignatureAlgorithm.ES256, digestAlgorithm: 'SHA-256', deviceKeyInfo: { deviceKey: DeviceKey.fromJwk(keyOf(deviceJwk)) },
    validityInfo: { signed: new Date(now), validFrom: new Date(now), validUntil: new Date(Math.min(now + 365 * DAY, signer.notAfter.getTime())) },
  });
  return issuerSigned.encodedForOid4Vci;
}

/** The certificate chain of an issued mdoc as base64 DER (the form of a JOSE `x5c`), Document Signer first. */
const issuerChain = (issuerSigned) => issuerSigned.issuerAuth.certificateChain.map((der) => Buffer.from(der).toString('base64'));

/** A data element value as JSON: byte strings as base64url, dates as their ISO string. */
function jsonValue(value) {
  if (value instanceof Uint8Array) return Buffer.from(value).toString('base64url');
  if (value instanceof Date || value instanceof DateOnly) return value.toISOString();
  if (Array.isArray(value)) return value.map(jsonValue);
  if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [k, jsonValue(v)]));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, jsonValue(v)]));
  return value;
}

/** The disclosed data elements of an mdoc, per namespace, as JSON values. */
export function mdocClaims(issuerSigned) {
  return Object.fromEntries([...(issuerSigned.issuerNamespaces?.issuerNamespaces.keys() ?? [])].map((namespace) => [namespace, jsonValue(issuerSigned.getPrettyClaims(namespace))]));
}

/**
 * Verifies an issued mdoc (issuer signature, digests, validity) against trust anchors.
 * @param {string} encoded base64url IssuerSigned
 * @param {string[]} trustAnchorPems
 */
export async function verifyIssuerSigned(encoded, trustAnchorPems) {
  const issuerSigned = IssuerSigned.fromEncodedForOid4Vci(encoded);
  await issuerSigned.verify({ trustedCertificates: [{ issuance: trustAnchorPems.map(derOf) }] }, mdocContext);
  return issuerSigned;
}

/**
 * Verifies a DeviceResponse presented over OpenID4VP 1.0 without the DC API: issuer data authentication, and mdoc
 * authentication over the session transcript of Appendix B.2.6.1 (client_id, nonce, the thumbprint of the response
 * encryption key or null, response_uri).
 * @param {string} encoded base64url DeviceResponse
 * @param {{ clientId: string, nonce: string, responseUri: string, jwkThumbprint?: Uint8Array }} handover
 * @param {(x5c: string[], docType: string) => Promise<Uint8Array[]>} trustAnchorsFor the trust anchors (DER) to
 *   validate a document's certificate chain against
 * @returns {Promise<import('@owf/mdoc').Document[]>}
 */
export async function verifyDeviceResponse(encoded, handover, trustAnchorsFor) {
  const deviceResponse = DeviceResponse.fromEncodedForOid4Vp(encoded);
  const trustedCertificates = [];
  for (const document of deviceResponse.documents ?? []) {
    trustedCertificates.push({ issuance: await trustAnchorsFor(issuerChain(document.issuerSigned), document.docType) });
  }
  const sessionTranscript = await SessionTranscript.forOid4Vp(handover, mdocContext);
  const { documents } = await Verifier.verifyDeviceResponse({ deviceResponse, sessionTranscript, trustedCertificates }, mdocContext);
  return documents.map(({ document }) => document);
}
