/**
 * Live wallet-initiated OpenID4VCI authorization code flow against MOSIP collab (Inji Certify + eSignet mock identity),
 * with MOSIP's registered client and Mimoto token proxy expressed as an issuer client registration.
 */
import { describe, expect, it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { Oid4vciClient, SoftwareKeyStore, type IssuerClientRegistration } from '../src/index.js';
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
};
const log = (s: string) => process.stderr.write(`${s}\n`);

const trust = await liveTrust();

describe('MOSIP collab (W3C VCDM 2.0 JSON-LD, mDL)', () => {
  const client = new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: REDIRECT, registrations });

  for (const [issuer, config, expectValid] of [
    ['https://injicertify-farmer.collab.mosip.net', 'FarmerCredential_VCDM2.0', true],
    ['https://injicertify-landregistry.collab.mosip.net', 'LandStatementCredential_VCDM2.0', false],
    ['https://injicertify-mdl.collab.mosip.net', 'DrivingLicenseCredential', true],
  ] as const) {
    it(`${config} via authorization code flow`, async () => {
      const session = await client.startWalletInitiated(issuer, [config]);
      expect(session.issuerTrust.decision).toBe('TRUSTED');
      const { authorizationUrl } = await session.beginAuthorization();
      const { redirectUrl } = await loginAndGetCode(authorizationUrl, REDIRECT, { log: () => undefined });
      const [cred] = await session.completeAuthorization(redirectUrl);
      log(`\n== ${config}: format=${cred!.format} valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}`);
      for (const c of cred!.report!.checks) log(`  [${c.status}] ${c.label}: ${c.detail ?? ''}`.slice(0, 200));
      expect(cred!.report!.valid).toBe(expectValid);
      expect(cred!.report!.trust?.decision).toBe('TRUSTED');
    }, 180_000);
  }
});
