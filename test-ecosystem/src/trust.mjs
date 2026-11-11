/**
 * Which issuers the reference verifier accepts when nothing else is injected: the reference issuer's DID for ldp_vc, a
 * Document Signer of the reference IACA that its CRL does not list for mso_mdoc (ISO/IEC 18013-5 clause 9.3, the
 * inspection procedures), and a certificate of the reference issuer CA that names the `iss` claim for dc+sd-jwt
 * (SD-JWT VC section 2.5).
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { didWeb } from './ldp.mjs';
import { derOf, isRevoked, MDOC_DS_EKU, validateChain } from './pki.mjs';

/**
 * @typedef {{ format: 'ldp_vc' | 'mso_mdoc' | 'dc+sd-jwt', issuer?: string, x5c?: string[], type: string | string[] }} IssuerInfo
 *   `issuer` is the issuer DID of an ldp_vc or the `iss` claim of an SD-JWT VC; `x5c` is the certificate chain of an
 *   mdoc or SD-JWT VC as base64 DER, signer first; `type` is the doctype, the vct, or the expanded types of an ldp_vc
 */

/**
 * @param {import('./pki.mjs').Pki} pki
 * @param {typeof fetch} [fetcher] retrieves the CRL
 * @returns {(info: IssuerInfo) => Promise<boolean>}
 */
export function referenceTrust(pki, fetcher = fetch) {
  const did = didWeb(pki.issuerUrl);
  return async ({ format, issuer, x5c }) => {
    if (format === 'ldp_vc') return issuer === did;
    try {
      const anchor = format === 'mso_mdoc' ? pki.iaca : pki.issuerCa;
      const [signer, signerIssuer] = await validateChain(x5c.map((c) => Buffer.from(c, 'base64')), [derOf(anchor.pem)]);
      const certificate = new x509.X509Certificate(signer);
      if (format === 'mso_mdoc') {
        return certificate.getExtension(x509.ExtendedKeyUsageExtension)?.usages.includes(MDOC_DS_EKU) === true && !(await isRevoked(signer, signerIssuer, fetcher));
      }
      const names = certificate.getExtension(x509.SubjectAlternativeNameExtension)?.names.items ?? [];
      return names.some((name) => name.type === 'url' && name.value === issuer);
    } catch {
      return false;
    }
  };
}
