/**
 * Live wallet-initiated OpenID4VCI authorization code flow against MOSIP collab (Inji Certify + eSignet mock identity),
 * with MOSIP's registered client and Mimoto token proxy expressed as an issuer client registration. The mock identity
 * issuer (the only collab issuer of SD-JWT VCs) has no Mimoto entry of its own; it shares eSignet with Land and Farmer,
 * whose client and token proxy it accepts.
 */
import { describe, expect, it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { IssuanceError, Oid4vciClient, SoftwareKeyStore, type IssuerClientRegistration } from '../src/index.js';
// Headless eSignet OTP login (Playwright) from tools/mosip-issuance
// @ts-expect-error untyped helper script
import { loginAndGetCode } from '../../../tools/mosip-issuance/issue.mjs';

const REDIRECT = 'io.mosip.residentapp.inji://oauthredirect';
const reg = (clientId: string, mimotoIssuer: string): IssuerClientRegistration => ({ clientId, redirectUri: REDIRECT,
  tokenEndpoint: `https://api.collab.mosip.net/v1/mimoto/get-token/${mimotoIssuer}`, extraAuthorizeParams: { ui_locales: 'en' } });
const registrations = {
  'https://injicertify-farmer.collab.mosip.net': reg('mpartner-default-mimoto-land-oidc', 'Farmer'),
  'https://injicertify-landregistry.collab.mosip.net': reg('mpartner-default-mimoto-land-oidc', 'Land'),
  'https://injicertify-mdl.collab.mosip.net': reg('mpartner-default-mimoto-mdl-oidc', 'MockMdl'),
  'https://injicertify-mock.collab.mosip.net': reg('mpartner-default-mimoto-land-oidc', 'Land'),
};
const log = (s: string) => process.stderr.write(`${s}\n`);

const trust = await liveTrust();

describe('MOSIP collab (W3C VCDM 2.0 JSON-LD, mDL, SD-JWT VC)', () => {
  const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: REDIRECT, registrations });

  for (const [issuer, config, expectValid] of [
    ['https://injicertify-farmer.collab.mosip.net', 'FarmerCredential_VCDM2.0', true],
    ['https://injicertify-landregistry.collab.mosip.net', 'LandStatementCredential_VCDM2.0', false],
    ['https://injicertify-mdl.collab.mosip.net', 'DrivingLicenseCredential', true],
    ['https://injicertify-mock.collab.mosip.net', 'MockVerifiableCredential_SD_JWT', true],
  ] as const) {
    it(`${config} via authorization code flow`, async () => {
      const session = await client.startWalletInitiated(issuer, [config]);
      expect(session.issuerTrust.decision).toBe('TRUSTED');
      const { authorizationUrl } = await session.beginAuthorization();
      const { redirectUrl } = await loginAndGetCode(authorizationUrl, REDIRECT, { log: () => undefined });
      // A credential that fails verification is refused (credential_failure to the issuer); its report comes with the error.
      const outcome = await session.completeAuthorization(redirectUrl).then(([c]) => ({ cred: c!, report: c!.report! }),
        (e: unknown) => { if (e instanceof IssuanceError && e.code === 'invalid_credential' && e.report) return { cred: undefined, report: e.report }; throw e; });
      const { report } = outcome;
      log(`\n== ${config}: format=${report.format} valid=${report.valid} trusted=${report.trusted}${outcome.cred ? '' : ' (refused)'}`);
      for (const c of report.checks) log(`  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 200));
      expect(report.valid).toBe(expectValid);
      expect(!!outcome.cred).toBe(expectValid);
      expect(report.trust?.decision).toBe('TRUSTED');
      if (report.format === 'dc+sd-jwt') {
        // Trusted only because the operator relaxed this sandbox anchor: its signing certificate allows keyEncipherment only.
        expect(report.trust?.evidence?.x509?.issues.map((i) => i.code)).toEqual(expect.arrayContaining(['x509.profile_relaxed', 'issuer.key_usage']));
        expect(report.checks.find((c) => c.id === 'sdjwt.holder')?.detail).toMatch(/cnf.kid \(did:jwk\) names this wallet's key/);
      }
    }, 180_000);
  }
});
