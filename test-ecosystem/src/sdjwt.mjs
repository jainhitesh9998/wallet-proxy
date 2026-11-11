/**
 * SD-JWT VC (draft-ietf-oauth-sd-jwt-vc, format `dc+sd-jwt`) with @sd-jwt/sd-jwt-vc. The issuer key is the end-entity
 * certificate in the `x5c` header (section 2.5), the holder key is `cnf.jwk`, and the status is a Token Status List
 * reference (draft-ietf-oauth-status-list sections 5.1 and 6.2) whose token is signed with the same certificate.
 */
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { createHeaderAndPayload } from '@sd-jwt/jwt-status-list';
import { CompactSign, compactVerify, decodeProtectedHeader, importJWK } from 'jose';
import { b64u, certificateJwk, publicOf } from './keys.mjs';
import { b64Der } from './pki.mjs';

const ES256 = { name: 'ECDSA', hash: 'SHA-256' };
/** The JWS algorithms accepted for issuer signatures and Key Binding JWTs. */
export const SIGNATURE_ALGORITHMS = ['ES256', 'ES384', 'ES512'];
/** How long a Status List Token may be cached, and how long it is valid, in seconds. */
const STATUS_TTL_S = 5;
const STATUS_VALIDITY_S = 300;
/** A Key Binding JWT older than this is not a fresh presentation. */
const KEY_BINDING_MAX_AGE_S = 300;

const hasher = (data, alg) => new Uint8Array(createHash(alg.replace('-', '')).update(typeof data === 'string' ? data : new Uint8Array(data)).digest());
const saltGenerator = (bytes) => randomBytes(bytes).toString('base64url');
const signingKey = (privateJwk) => webcrypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

/** Signs the JWS signing input the library hands over, with ES256. */
export const es256Signer = (privateJwk) => async (data) => b64u(await webcrypto.subtle.sign(ES256, await signingKey(privateJwk), Buffer.from(data)));

/** Verifies the signature over a JWS signing input with the given key, using the algorithm the header names. */
async function verifyJws(data, signature, jwk) {
  const jws = `${data}.${signature}`;
  try {
    await compactVerify(jws, await importJWK(publicOf(jwk), decodeProtectedHeader(jws).alg), { algorithms: SIGNATURE_ALGORITHMS });
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {{ pki: import('./pki.mjs').Pki, holderJwk: JsonWebKey, vct: string, claims: Record<string, unknown>,
 *   disclosable: string[], status: { uri: string, idx: number }, now?: number }} opts `disclosable` names the top-level
 *   claims that become selectively disclosable; the registered claims never are (section 2.2.2.3)
 * @returns {Promise<string>} the SD-JWT VC with all disclosures
 */
export function issueSdJwtVc({ pki, holderJwk, vct, claims, disclosable, status, now = Date.now() }) {
  const iat = Math.floor(now / 1000);
  const sdjwt = new SDJwtVcInstance({ signer: es256Signer(pki.issuerSigner.privateJwk), signAlg: 'ES256', hasher, hashAlg: 'sha-256', saltGenerator });
  return sdjwt.issue(
    { iss: pki.issuerUrl, iat, exp: iat + 365 * 86_400, vct, cnf: { jwk: publicOf(holderJwk) }, status: { status_list: status }, ...claims },
    { _sd: disclosable.filter((name) => name in claims) },
    { header: { x5c: [b64Der(pki.issuerSigner.pem)] } });
}

/**
 * The Status List Token (JWT) of a list, signed with the certificate that signs the credentials.
 * @param {{ pki: import('./pki.mjs').Pki, list: import('@sd-jwt/jwt-status-list').StatusList, uri: string, now?: number }} opts
 */
export async function signStatusListToken({ pki, list, uri, now = Date.now() }) {
  const iat = Math.floor(now / 1000);
  const { header, payload } = createHeaderAndPayload(list, { sub: uri, iat, exp: iat + STATUS_VALIDITY_S, ttl: STATUS_TTL_S },
    { alg: 'ES256', typ: 'statuslist+jwt', x5c: [b64Der(pki.issuerSigner.pem)] });
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader(header).sign(await importJWK(pki.issuerSigner.privateJwk, 'ES256'));
}

/**
 * Verifies an SD-JWT VC or a presentation of one: issuer signature with the key of the `x5c` end-entity certificate
 * (whether that certificate is trusted is the caller's decision), disclosures, validity, and the status, whose Status
 * List Token has to be signed with the same certificate. With `keyBinding`, the Key Binding JWT is required and checked
 * against `cnf.jwk`, the nonce, the audience and `sd_hash` (RFC 9901 section 7.3).
 * @param {string} compact
 * @param {{ keyBinding?: { nonce: string, audience: string }, fetch?: typeof fetch }} [opts]
 * @returns {Promise<{ payload: Record<string, unknown>, header: Record<string, unknown>, x5c: string[] }>} the disclosed
 *   claims, the issuer-signed header and the certificate chain
 */
export async function verifySdJwtVc(compact, { keyBinding, fetch: fetcher = fetch } = {}) {
  const { x5c, alg } = decodeProtectedHeader(compact.split('~')[0]);
  if (!Array.isArray(x5c) || x5c.length === 0) throw new Error('The SD-JWT VC names no issuer certificate (x5c)');
  const issuerJwk = await certificateJwk(x5c[0], alg);
  const sdjwt = new SDJwtVcInstance({
    hasher,
    verifier: (data, signature) => verifyJws(data, signature, issuerJwk),
    kbVerifier: (data, signature, payload) => verifyJws(data, signature, payload.cnf.jwk),
    statusListFetcher: async (uri) => {
      const response = await fetcher(uri, { headers: { Accept: 'application/statuslist+jwt' } });
      if (!response.ok) throw new Error(`Status list ${uri} answered ${response.status}`);
      return response.text();
    },
    statusVerifier: (data, signature) => decodeProtectedHeader(`${data}.`).x5c?.[0] === x5c[0] && verifyJws(data, signature, issuerJwk),
  });
  const { payload, header } = await sdjwt.verify(compact, {
    allowedIssuerAlgorithms: SIGNATURE_ALGORITHMS,
    ...(keyBinding ? { keyBindingNonce: keyBinding.nonce, expectedKeyBindingAudience: keyBinding.audience, keyBindingMaxAgeSeconds: KEY_BINDING_MAX_AGE_S, allowedKeyBindingAlgorithms: SIGNATURE_ALGORITHMS } : {}),
  });
  return { payload, header, x5c };
}
