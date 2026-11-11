/**
 * Credential request and response encryption (OID4VCI §8.2, §10): what the issuer's metadata and the wallet's
 * setting call for, sealing a request accordingly and opening the response to it.
 */
import type { Jwk } from '@vctrust/trust-client';
import { bytes } from '@vctrust/trust-client/primitives';
import { randomId } from '../crypto/jwt.js';
import { decryptJwe, encryptJwe, type JweEnc } from '../crypto/jwe.js';
import { SoftwareKey } from '../crypto/keys.js';
import { IssuanceError, type Oid4vciOptions } from './types.js';

interface EncryptionPlan {
  request?: { jwk: Jwk; enc: JweEnc };
  response?: { enc: JweEnc };
}

/** A credential (or deferred) request body, sealed for the issuer when encryption applies. */
export interface SealedRequest {
  body: string;
  contentType: string;
  responseKey?: SoftwareKey;
}

/**
 * OID4VCI §8.2 / §10. Response encryption is requested with a fresh ECDH-ES P-256 key, and only together with request
 * encryption; the request is a JWE to the issuer's credential_request_encryption key (alg and kid from that JWK).
 */
function encryptionPlan(issuerMetadata: Record<string, unknown>, mode: Oid4vciOptions['encryption']): EncryptionPlan {
  const reqMd = issuerMetadata.credential_request_encryption as { jwks?: { keys?: Jwk[] }; enc_values_supported?: string[]; encryption_required?: boolean } | undefined;
  const resMd = issuerMetadata.credential_response_encryption as { alg_values_supported?: string[]; enc_values_supported?: string[]; encryption_required?: boolean } | undefined;
  const prefer = mode === 'preferred';
  const pickEnc = (v?: string[]): JweEnc | undefined => (v?.includes('A256GCM') ? 'A256GCM' : v?.includes('A128GCM') ? 'A128GCM' : undefined);
  const reqKey = reqMd?.jwks?.keys?.find((k) => k.kty === 'EC' && k.crv === 'P-256' && k.alg === 'ECDH-ES' && (!k.use || k.use === 'enc'));
  const reqEnc = pickEnc(reqMd?.enc_values_supported);
  const canSealRequest = !!(reqKey && reqEnc);
  const resEnc = resMd?.alg_values_supported?.includes('ECDH-ES') ? pickEnc(resMd.enc_values_supported) : undefined;
  const unsupported = (what: string) => new IssuanceError(`The issuer requires ${what} encryption with parameters this wallet does not support `
    + '(ECDH-ES on P-256 with A128GCM or A256GCM)', 'invalid_encryption_parameters');
  if (reqMd?.encryption_required && !canSealRequest) throw unsupported('credential request');
  if (resMd?.encryption_required && (!resEnc || !canSealRequest)) throw unsupported('credential response');
  const response = resEnc && canSealRequest && (resMd!.encryption_required || prefer) ? { enc: resEnc } : undefined;
  const request = canSealRequest && (reqMd!.encryption_required || prefer || response) ? { jwk: reqKey!, enc: reqEnc! } : undefined;
  return { request, response };
}

export function sealRequest(body: Record<string, unknown>, issuerMetadata: Record<string, unknown>, mode: Oid4vciOptions['encryption']): SealedRequest {
  const plan = encryptionPlan(issuerMetadata, mode);
  let responseKey: SoftwareKey | undefined;
  if (plan.response) {
    responseKey = SoftwareKey.generate();
    body = { ...body, credential_response_encryption: { jwk: { ...responseKey.publicJwk, alg: 'ECDH-ES', use: 'enc', kid: randomId() }, enc: plan.response.enc } };
  }
  if (!plan.request) return { body: JSON.stringify(body), contentType: 'application/json', responseKey };
  return { body: encryptJwe(bytes.utf8Encode(JSON.stringify(body)), plan.request.jwk, plan.request.enc), contentType: 'application/jwt', responseKey };
}

/** Reads a credential response, decrypting it when encryption was requested (an unencrypted one is then refused). */
export async function openResponse(r: Response, sealed: SealedRequest): Promise<Record<string, unknown>> {
  if (!sealed.responseKey) return (await r.json()) as Record<string, unknown>;
  const contentType = (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (contentType !== 'application/jwt') throw new IssuanceError('The issuer answered without encryption although an encrypted response was requested', 'invalid_encryption_parameters');
  const key = sealed.responseKey;
  const { header, plaintext } = decryptJwe((await r.text()).trim(), (peer) => key.ecdh(peer));
  // No zip was requested, so none is accepted (§8.2: absent zip → no compression); this also rules out inflation bombs.
  if (header.zip !== undefined) throw new IssuanceError(`The issuer compressed the response (zip ${String(header.zip)}) although no compression was requested`, 'invalid_encryption_parameters');
  return JSON.parse(bytes.utf8Decode(plaintext)) as Record<string, unknown>;
}
