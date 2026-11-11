/**
 * Credential verification for the three formats the wallet holds: ISO mdoc (mso_mdoc), SD-JWT VC (dc+sd-jwt) and W3C
 * VCs with Data Integrity proofs (ldp_vc). Every check that needs something from outside the credential (the
 * issuer's trust, a DID document, a JSON-LD context, a CRL, a status list) goes through the trust client.
 */
import type { Jwk, TrustClient } from '@vctrust/trust-client';
import { cbor, decodeJws, parseCoseSign1 } from '@vctrust/trust-client/primitives';
import { coseKeyToJwk, decodeIssuedMdoc, verifyMdoc } from './mdoc.js';
import { verifyLdpVc } from './ldp.js';
import { parseSdJwt, verifySdJwtVc } from './sdjwt.js';
import type { VerificationReport } from './report.js';

/** What the wallet asked the issuer for, read from the credential configuration (OpenID4VCI 1.0 Appendix A). */
export interface ExpectedCredential {
  doctype?: string;
  vct?: string;
  type?: string[];
  context?: string[];
}

export interface VerifyOptions {
  trust: TrustClient;
  /** the key (and, for DID binding, the DID) this wallet proved to the issuer */
  holderJwk?: Jwk;
  holderDid?: string;
  expected?: ExpectedCredential;
  now?: Date;
  checkStatus?: boolean;
}

export const SUPPORTED_FORMATS = ['mso_mdoc', 'dc+sd-jwt', 'ldp_vc'] as const;

/** Verifies a credential of a supported format. */
export async function verifyCredential(format: string, credential: unknown, opts: VerifyOptions): Promise<VerificationReport> {
  switch (format) {
    case 'mso_mdoc': return verifyMdoc(credential as string, opts);
    case 'dc+sd-jwt': return verifySdJwtVc(credential as string, opts);
    case 'ldp_vc': return verifyLdpVc(credential as Record<string, unknown>, opts);
    default: throw new Error(`Unsupported credential format ${format}`);
  }
}

/** The expected type of a credential configuration, per format (OpenID4VCI 1.0 Appendix A.1.2.2, A.2.2, A.3.2). */
export function expectedOf(config: Record<string, unknown>): ExpectedCredential {
  const definition = (config.credential_definition ?? {}) as { type?: unknown; '@context'?: unknown };
  const strings = (v: unknown) => (Array.isArray(v) && v.every((x) => typeof x === 'string') ? v as string[] : undefined);
  switch (config.format) {
    case 'mso_mdoc': return typeof config.doctype === 'string' ? { doctype: config.doctype } : {};
    case 'dc+sd-jwt': return typeof config.vct === 'string' ? { vct: config.vct } : {};
    case 'ldp_vc': return { type: strings(definition.type), context: strings(definition['@context']) };
    default: return {};
  }
}

/**
 * The key or DID a credential is bound to (SD-JWT cnf.jwk, mdoc deviceKey, W3C credentialSubject.id), read without
 * verifying anything; empty for a credential that is not bound or cannot be read (verification reports those).
 */
export function holderBinding(format: string, credential: unknown): { jwk?: Jwk; did?: string } {
  try {
    if (format === 'mso_mdoc') {
      const auth = parseCoseSign1(cbor.mapGet(decodeIssuedMdoc(String(credential)), 'issuerAuth'));
      const mso = cbor.decode(auth.payload!);
      if (!(mso instanceof cbor.Tagged) || !(mso.value instanceof Uint8Array)) return {};
      return { jwk: coseKeyToJwk(cbor.mapGet(cbor.mapGet(cbor.decode(mso.value), 'deviceKeyInfo'), 'deviceKey')) ?? undefined };
    }
    if (format === 'dc+sd-jwt') {
      const cnf = decodeJws<{ cnf?: { jwk?: Jwk } }>(parseSdJwt(String(credential)).issuerJwt).payload.cnf;
      return cnf?.jwk ? { jwk: cnf.jwk } : {};
    }
    if (format === 'ldp_vc') {
      const vc = (typeof credential === 'string' ? JSON.parse(credential) : credential) as { credentialSubject?: unknown };
      const subject = (Array.isArray(vc.credentialSubject) ? vc.credentialSubject[0] : vc.credentialSubject) as { id?: unknown } | undefined;
      return typeof subject?.id === 'string' ? { did: subject.id.split('#')[0] } : {};
    }
  } catch { /* not readable */ }
  return {};
}

export type { VerificationReport, Check, CheckStatus } from './report.js';
export { verifyMdoc, verifyLdpVc, verifySdJwtVc };
