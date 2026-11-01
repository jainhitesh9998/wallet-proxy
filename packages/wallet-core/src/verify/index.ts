import type { Jwk, TrustClient } from '@vctrust/trust-client';
import { verifyMdoc } from './mdoc.js';
import { verifyLdpVc } from './ldp.js';
import { verifySdJwtVc } from './sdjwt.js';
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

export type { VerificationReport, Check, CheckStatus } from './report.js';
export { verifyMdoc, verifyLdpVc, verifySdJwtVc };
