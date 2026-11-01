/**
 * Demo wallet (web build) end to end:
 *   settings → trust server, Animo mDL issuance (TRUSTED on the device from the signed trust list, passing checks),
 *   OpenID4VP presentation verified by Animo, the same decision made by the service in 'service' mode, then a simulated
 *   trust-service outage where issuance and trust decisions carry on from the stored trust list.
 */
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

const PLAYGROUND = 'https://playground.animo.id';
const TRUST_URL = process.env.TRUST_URL ?? 'http://localhost:8090';

async function createMdlOffer(request: APIRequestContext): Promise<string> {
  const r = await request.post(`${PLAYGROUND}/api/offers/create`, { data: {
    credentialSupportedIds: ['mdl-mdoc-utopia'], authorization: 'none', deferBy: 'none', requireDpop: false,
    requireWalletAttestation: false, requireKeyAttestation: false } });
  expect(r.ok(), `offer creation: HTTP ${r.status()}`).toBeTruthy();
  const { credentialOffer } = (await r.json()) as { credentialOffer: string };
  expect(credentialOffer).toMatch(/^openid-credential-offer:\/\//);
  return credentialOffer;
}

async function createMdlRequest(request: APIRequestContext) {
  const r = await request.post(`${PLAYGROUND}/api/requests/create`, { data: {
    request: { credentials: [{ id: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name', 'birth_date'] }], combination: 'all' },
    requestScheme: 'openid4vp://', responseMode: 'direct_post.jwt', requestSignerType: 'x5c', transactionAuthorizationType: 'none' } });
  expect(r.ok(), `request creation: HTTP ${r.status()}`).toBeTruthy();
  return (await r.json()) as { authorizationRequestUri: string; verificationSessionId: string };
}

/** Full-page screenshot attached to the HTML report (and kept under test-results/). */
async function shot(page: Page, name: string) {
  const path = test.info().outputPath(`${name}.png`);
  await page.screenshot({ path, fullPage: true });
  await test.info().attach(name, { path, contentType: 'image/png' });
}

async function home(page: Page) {
  await page.goto('/');
  await expect(page.getByTestId('nav-receive')).toBeVisible();
}

async function receive(page: Page, offer: string) {
  await home(page);
  await page.getByTestId('nav-receive').click();
  await page.getByTestId('offer-input').fill(offer);
  await page.getByTestId('offer-load').click();
  await expect(page.getByTestId('issuer-name')).toBeVisible({ timeout: 60_000 });
}

test('demo wallet: trust settings, mDL issuance, presentation, outage fallback', async ({ page, request }) => {
  // ERR_UNSAFE_PORT is the simulated outage (the trust client is pointed at 127.0.0.1:9).
  page.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('ERR_UNSAFE_PORT')) console.log(`[browser] ${m.text()}`); });

  await test.step('configure the trust service in Settings', async () => {
    await home(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-trust-url').fill(TRUST_URL);
    await page.getByTestId('settings-api-key').fill('demo-wallet-key');
    await page.getByTestId('settings-client-id').fill('demo-wallet');
    await page.getByTestId('settings-save').click();
    await expect(page.getByTestId('settings-message')).toContainText('Saved');
    await page.getByTestId('settings-sync-snapshot').click();
    await expect(page.getByTestId('settings-message')).toContainText(/Trust list version \d+ verified/);
    await expect(page.getByTestId('snapshot-version')).toContainText('version');
    await expect(page.getByTestId('snapshot-contents')).toContainText('DID documents');
    await expect(page.getByTestId('snapshot-contents')).toContainText('CRLs');
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: online');
    await expect(page.getByTestId('settings-trust-status-mode')).toContainText('Decisions on this device · trust list v');
  });

  await test.step('receive an Animo mDL (pre-authorized) and see it TRUSTED', async () => {
    await receive(page, await createMdlOffer(request));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');
    await expect(page.getByTestId('issuer-trust-source')).toHaveText(/decided by: device · list v\d+/);
    await expect(page.getByTestId('issuer-metadata-source')).toHaveText('direct');
    await expect(page.getByTestId('offer-grant')).toHaveText('pre-authorized_code');
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 90_000 });
    await page.getByTestId('receive-done').click();

    await expect(page.getByTestId('credential-trust-0-decision')).toHaveText('TRUSTED');
    await expect(page.getByTestId('credential-trust-0-valid')).toHaveText('✓ valid signature');
    await page.getByTestId('credential-card-0').click();
    await expect(page.getByTestId('check-status-mdoc.signature')).toHaveText('PASS');
    await expect(page.getByTestId('check-status-mdoc.digests')).toHaveText('PASS');
    await expect(page.getByTestId('check-status-issuer.trust')).toHaveText('PASS');
    await expect(page.getByTestId('evidence-x509')).toBeVisible();
    // The Document Signer was checked against Animo's IACA CRL, carried in the trust list.
    await expect(page.getByTestId('evidence-revocation-0')).toContainText('not revoked');
    await expect(page.getByTestId('evidence-revocation-0')).toContainText('playground.animo.id/crl');
    await shot(page, '1-credential-detail');
  });

  await test.step('present the mDL to the Animo verifier', async () => {
    const req = await createMdlRequest(request);
    await home(page);
    await page.getByTestId('nav-present').click();
    await page.getByTestId('present-input').fill(req.authorizationRequestUri);
    await page.getByTestId('present-load').click();
    await expect(page.getByTestId('verifier-name')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('verifier-trust-decision')).toHaveText('TRUSTED');
    // DCQL query ids are chosen by the verifier; one mDL candidate must be offered for the (single) query.
    await expect(page.locator('[data-testid^="candidate-"]')).toHaveCount(1);
    await page.getByTestId('present-share').click();
    await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200', { timeout: 60_000 });
    await shot(page, '2-presentation-result');
    await expect.poll(async () => {
      const r = await request.get(`${PLAYGROUND}/api/requests/${req.verificationSessionId}`);
      return ((await r.json()) as { responseStatus?: string }).responseStatus;
    }, { timeout: 30_000, intervals: [500, 1000, 2000] }).toBe('ResponseVerified');
  });

  await test.step("'service' mode: the trust service makes the same decision", async () => {
    await home(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-decision-mode-service').click();
    await page.getByTestId('settings-lookups-service').click();
    await expect(page.getByTestId('settings-trust-status-mode')).toHaveText('Decisions by the trust service');
    await receive(page, await createMdlOffer(request));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');
    await expect(page.getByTestId('issuer-trust-source')).toHaveText('decided by: trust service');
    await expect(page.getByTestId('issuer-metadata-source')).toHaveText('trust-service');
    await home(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-decision-mode-local').click();
    await page.getByTestId('settings-lookups-direct').click();
    await expect(page.getByTestId('settings-trust-status-mode')).toContainText('Decisions on this device');
  });

  await test.step('simulate a trust-service outage: decisions carry on from the stored trust list', async () => {
    await home(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-outage').click();
    await expect(page.getByTestId('settings-outage-state')).toHaveText('ON');
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: offline', { timeout: 30_000 });
    await expect(page.getByTestId('snapshot-version')).toContainText('version');

    await receive(page, await createMdlOffer(request));
    await expect(page.getByTestId('issuer-trust-source')).toHaveText(/decided by: device · list v\d+/);
    await expect(page.getByTestId('issuer-metadata-source')).not.toHaveText('trust-service');
    await shot(page, '3-outage-offer');
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('issued-trust-0-source')).toHaveText(/decided by: device · list v\d+/, { timeout: 90_000 });
    await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
    await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED');
    await page.getByTestId('receive-done').click();
    await expect(page.getByTestId('trust-status')).toHaveText('Trust service: offline');
    await expect(page.getByTestId('credential-count')).toHaveText('2 credential(s)');
    await expect(page.getByTestId('credential-trust-0-source')).toHaveText(/decided by: device · list v\d+/);
    await shot(page, '4-home-after-outage');
  });
});
