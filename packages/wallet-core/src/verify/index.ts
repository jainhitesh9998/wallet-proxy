import { cbor, decodeIssuerSigned, decodeJws, parseCoseSign1, type Jwk, type TrustClient } from '@vctrust/trust-client';
import { coseKeyToJwk, verifyMdoc } from './mdoc.js';
import { verifyLdpVc } from './ldp.js';
import { parseSdJwt, verifySdJwtVc } from './sdjwt.js';
import type { VerificationReport } from './report.js';

export interface VerifyOptions {
  trust?: TrustClient;
  fetch?: typeof fetch;
  holderJwk?: Jwk;
  holderDid?: string;
  credentialIssuer?: string;
  now?: Date;
  checkStatus?: boolean;
}

/** Verifies a credential of any supported format. */
export async function verifyCredential(format: string, credential: unknown, opts: VerifyOptions): Promise<VerificationReport> {
  switch (format) {
    case 'mso_mdoc': return verifyMdoc(String(credential), opts);
    case 'ldp_vc': return verifyLdpVc(credential as Record<string, unknown>, opts);
    case 'dc+sd-jwt':
    case 'vc+sd-jwt': return verifySdJwtVc(String(credential), { ...opts, format });
    default: throw new Error(`Unsupported credential format ${format}`);
  }
}

/**
 * The key or DID a credential is bound to — SD-JWT cnf.jwk, mdoc deviceKey, W3C credentialSubject.id — read without
 * verifying anything; empty for bearer or unparseable credentials (verification reports those).
 */
export function holderBinding(format: string, credential: unknown): { jwk?: Jwk; did?: string } {
  try {
    if (format === 'mso_mdoc') {
      const auth = parseCoseSign1(cbor.mapGet(decodeIssuerSigned(String(credential)).issuerSigned, 'issuerAuth'));
      let mso = cbor.decode(auth.payload!);
      if (mso instanceof cbor.Tagged && mso.value instanceof Uint8Array) mso = cbor.decode(mso.value);
      return { jwk: coseKeyToJwk(cbor.mapGet(cbor.mapGet(mso, 'deviceKeyInfo'), 'deviceKey')) ?? undefined };
    }
    if (format === 'dc+sd-jwt' || format === 'vc+sd-jwt') {
      return { jwk: decodeJws<{ cnf?: { jwk?: Jwk } }>(parseSdJwt(String(credential)).issuerJwt).payload.cnf?.jwk };
    }
    if (format === 'ldp_vc') {
      const vc = (typeof credential === 'string' ? JSON.parse(credential) : credential) as { credentialSubject?: unknown };
      const subject = (Array.isArray(vc.credentialSubject) ? vc.credentialSubject[0] : vc.credentialSubject) as { id?: unknown } | undefined;
      return typeof subject?.id === 'string' ? { did: subject.id.split('#')[0] } : {};
    }
  } catch { /* not parseable */ }
  return {};
}

export type { VerificationReport, Check, CheckStatus } from './report.js';
export { verifyMdoc, verifyLdpVc, verifySdJwtVc };
