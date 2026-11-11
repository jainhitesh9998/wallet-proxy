/** JOSE plumbing for the reference issuer and verifier: the callbacks the protocol library asks for, on `jose`. */
import { createHash, randomBytes, webcrypto, X509Certificate } from 'node:crypto';
import { calculateJwkThumbprint, compactDecrypt, CompactEncrypt, compactVerify, CompactSign, exportJWK, importJWK, importX509 } from 'jose';

const enc = new TextEncoder();
const dec = new TextDecoder();
export const b64u = (b) => Buffer.from(b).toString('base64url');
export const publicOf = ({ d, ...pub }) => pub;
export const thumbprint = (jwk) => calculateJwkThumbprint(publicOf(jwk), 'sha256');
/** The JWE algorithms of an encrypted OpenID4VP response in this ecosystem (OpenID4VP 1.0 section 8.3). */
export const RESPONSE_ENCRYPTION = { alg: 'ECDH-ES', enc: ['A128GCM', 'A256GCM'] };

export async function generateEcJwk() {
  const { privateKey } = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', privateKey);
  return { kty, crv, x, y, d };
}

/** The public key a did:jwk names (did:jwk method: the method-specific id is the base64url JWK). */
export function didJwkKey(didUrl) {
  const did = didUrl.split('#')[0];
  if (!did.startsWith('did:jwk:')) throw new Error(`Unsupported DID ${did}`);
  return JSON.parse(Buffer.from(did.slice('did:jwk:'.length), 'base64url').toString());
}

/** The public key in a certificate, as a JWK. */
export const certificateJwk = (base64Der, alg) => importX509(new X509Certificate(Buffer.from(base64Der, 'base64')).toString(), alg).then(exportJWK);

async function signerPublicJwk(signer) {
  if (signer.method === 'jwk') return signer.publicJwk;
  if (signer.method === 'did') return didJwkKey(signer.didUrl);
  if (signer.method === 'x5c') return certificateJwk(signer.x5c[0], signer.alg);
  throw new Error(`Unsupported signer method ${signer.method}`);
}

/**
 * @param {Array<object>} privateJwks the private keys this party signs and decrypts with, found by the public key the
 *   library names
 */
export function joseCallbacks(privateJwks) {
  const privateKeyOf = async (publicJwk) => {
    const tp = await thumbprint(publicJwk);
    for (const k of privateJwks) if (await thumbprint(k) === tp) return k;
    throw new Error('No private key for the requested public key');
  };
  return {
    hash: (data, alg) => new Uint8Array(createHash(alg.toLowerCase().replace('-', '')).update(data).digest()),
    generateRandom: (n) => new Uint8Array(randomBytes(n)),
    clientAuthentication: () => undefined,
    signJwt: async (signer, { header, payload }) => {
      const publicJwk = await signerPublicJwk(signer);
      const key = await importJWK(await privateKeyOf(publicJwk), header.alg);
      const jwt = await new CompactSign(enc.encode(JSON.stringify(payload))).setProtectedHeader(header).sign(key);
      return { jwt, signerJwk: publicJwk };
    },
    // Verifies the signature only; whether the key is acceptable is decided by the caller of the library.
    verifyJwt: async (signer, { compact }) => {
      try {
        const signerJwk = await signerPublicJwk(signer);
        await compactVerify(compact, await importJWK(signerJwk, signer.alg), { algorithms: [signer.alg] });
        return { verified: true, signerJwk };
      } catch {
        return { verified: false };
      }
    },
    encryptJwe: async ({ publicJwk, alg, enc: contentEncryption, apu, apv }, data) => {
      const jwe = new CompactEncrypt(enc.encode(data)).setProtectedHeader({ alg, enc: contentEncryption, kid: publicJwk.kid });
      if (apu || apv) jwe.setKeyManagementParameters({ ...(apu ? { apu: Buffer.from(apu, 'base64url') } : {}), ...(apv ? { apv: Buffer.from(apv, 'base64url') } : {}) });
      return { jwe: await jwe.encrypt(await importJWK(publicJwk, alg)), encryptionJwk: publicJwk };
    },
    // Decrypts with the key the library names: the one of the request's client_metadata that the JWE's `kid` selects.
    decryptJwe: async (jwe, { jwk } = {}) => {
      try {
        const key = await importJWK(await privateKeyOf(jwk), RESPONSE_ENCRYPTION.alg);
        const { plaintext } = await compactDecrypt(jwe, key, { keyManagementAlgorithms: [RESPONSE_ENCRYPTION.alg], contentEncryptionAlgorithms: RESPONSE_ENCRYPTION.enc });
        return { decrypted: true, decryptionJwk: jwk, payload: dec.decode(plaintext) };
      } catch {
        return { decrypted: false };
      }
    },
  };
}
