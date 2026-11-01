/** HAIP-mandatory authorization code flow: PAR + PKCE + DPoP + wallet attestation + RFC 9207 iss, against Animo (Credo). */
import { expect, it } from 'vitest';
import { liveTrust } from './live-trust.js';
import { Oid4vciClient, SoftwareKeyStore } from '../src/index.js';
import { demoAttester } from './wallet-provider.js';
// @ts-expect-error untyped
import { chromium } from '../../../tools/mosip-issuance/node_modules/playwright/index.mjs';

const REDIRECT = 'https://wallet.vctrust.dev/cb';
const log = (s: string) => process.stderr.write(`${s}\n`);

/** Signs in on the playground's demo login and returns the URL the AS redirected to. */
async function signIn(authorizationUrl: string): Promise<string> {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    let redirect = '';
    // Redirect hops are not routed; the request event sees them (the demo redirect host does not resolve).
    const capture = (r: { url(): string }) => { if (r.url().startsWith(REDIRECT) && !redirect) redirect = r.url(); };
    page.on('request', capture);
    page.on('requestfailed', capture);
    await page.goto(authorizationUrl);
    await page.fill('input[name=login]', 'demo-holder');
    await page.fill('input[name=password]', 'demo');
    await page.click('button[type=submit]');
    for (let i = 0; i < 20 && !redirect; i++) {
      // consent / continue screens
      const btn = await page.$('button[type=submit], button.login-submit, button:has-text("Continue"), button:has-text("Accept")');
      if (btn) await btn.click().catch(() => undefined);
      await page.waitForTimeout(500);
    }
    if (!redirect) throw new Error(`No redirect; stuck at ${page.url()}: ${(await page.innerText('body')).slice(0, 300)}`);
    return redirect;
  } finally {
    await browser.close();
  }
}

it('PAR + PKCE + DPoP + wallet attestation authorization code flow', async () => {
  const o = await (await fetch('https://playground.animo.id/api/offers/create', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'browser', deferBy: 'none', requireDpop: true,
      requireWalletAttestation: true, requireKeyAttestation: false }) })).json() as { credentialOffer: string };
  const trust = await liveTrust();
  const session = await new Oid4vciClient({ trust, keyStore: new SoftwareKeyStore(), redirectUri: REDIRECT, attester: demoAttester() }).startFromOffer(o.credentialOffer);
  expect(session.grant).toBe('authorization_code');
  const { authorizationUrl } = await session.beginAuthorization();
  expect(authorizationUrl).toMatch(/[?&]request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri/);   // FAPI2: only client_id + request_uri
  const callback = await signIn(authorizationUrl);
  log(`callback: ${callback.replace(/code=[^&]+/, 'code=…')}`);
  expect(new URL(callback).searchParams.get('iss')).toBeTruthy();
  const [cred] = await session.completeAuthorization(callback);
  log(`credential valid=${cred!.report?.valid} trusted=${cred!.report?.trusted}`);
  expect(cred!.report!.valid).toBe(true);
  expect(cred!.report!.trusted).toBe(true);
}, 120_000);
