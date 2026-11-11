/**
 * The demo wallet (web build) against the public Animo playground (https://playground.animo.id). Needs the internet:
 * runs with LIVE=1 (npm run test:live).
 *
 *   - with the trust service: an Animo mDL is issued (TRUSTED from the snapshot, the Document Signer checked against
 *     Animo's CRL), and presented to Animo's verifier, which verifies it
 *   - without the trust service and without a snapshot: only the Animo root pinned in the app decides. The issuer is
 *     unknown by its URL (the app pins a certificate, not a registry entry) and needs the user's confirmation; the mDL
 *     is then trusted because its Document Signer chains to the pinned root, and Animo's verifier is trusted the same way
 */
import { expect, test, type APIRequestContext } from '@playwright/test';
import { home, homeWithSnapshot, loadOffer, loadRequest, logConsoleErrors, shot } from './support';

const PLAYGROUND = 'https://playground.animo.id';

test.skip(!process.env.LIVE, 'set LIVE=1 to run against the Animo playground (needs the internet)');
test.beforeEach(({ page }) => logConsoleErrors(page));

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

async function verified(request: APIRequestContext, sessionId: string) {
  await expect.poll(async () => {
    const r = await request.get(`${PLAYGROUND}/api/requests/${sessionId}`);
    return ((await r.json()) as { responseStatus?: string }).responseStatus;
  }, { timeout: 30_000, intervals: [500, 1000, 2000] }).toBe('ResponseVerified');
}

test('Animo mDL with the trust service: TRUSTED from the snapshot, presented and verified', async ({ page, request }) => {
  await homeWithSnapshot(page);

  await test.step('issuance', async () => {
    await loadOffer(page, await createMdlOffer(request));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
    await expect(page.getByTestId('issuer-name')).toHaveText('Animo Playground');
    await expect(page.getByTestId('issuer-trust-source')).toHaveText(/decided on: device · snapshot of /);
    await expect(page.getByTestId('issuer-metadata-source')).toHaveText('proxy');
    // A trusted issuer's logo is shown.
    await expect(page.getByTestId('issuer-section').locator('img')).toHaveCount(1);
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 90_000 });
    await page.getByTestId('receive-done').click();
    await page.getByTestId('credential-card-0').click();
    for (const id of ['mdoc.signature', 'mdoc.digests', 'mdoc.validity', 'mdoc.device_key', 'issuer.trust']) await expect(page.getByTestId(`check-status-${id}`)).toHaveText('PASS');
    await expect(page.getByTestId('checks-summary')).toContainText(' 0 failed');
    // The Document Signer was checked against Animo's IACA CRL, carried in the snapshot.
    await expect(page.getByTestId('evidence-revocation-0')).toContainText('not revoked');
    await expect(page.getByTestId('evidence-revocation-0')).toContainText('playground.animo.id/crl');
    // Batch issuance (default 3 instances, Animo's batch_size is 10), each bound to its own key.
    await expect(page.getByTestId('detail-instances')).toContainText('3, 3 not yet presented');
    await shot(page, 'animo-credential');
  });

  await test.step('presentation to the Animo verifier', async () => {
    const req = await createMdlRequest(request);
    await loadRequest(page, req.authorizationRequestUri);
    await expect(page.getByTestId('verifier-trust-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
    await expect(page.locator('[data-testid^="candidate-"]')).toHaveCount(1);
    await expect(page.locator('[data-testid^="instance-"]')).toHaveText('Instance 1 of 3, not shown to any verifier before');
    await page.getByTestId('present-share').click();
    await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200', { timeout: 60_000 });
    await verified(request, req.verificationSessionId);
    await home(page);
    await page.getByTestId('credential-card-0').click();
    await expect(page.getByTestId('detail-instances')).toContainText('3, 2 not yet presented');
  });
});

test('Animo with pinned trust only: no trust service, no snapshot', async ({ page, request }) => {
  await test.step('a wallet that cannot reach the service and holds no snapshot', async () => {
    await homeWithSnapshot(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-outage').click();
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: offline');
    await page.getByTestId('settings-wipe').click();
    await page.getByTestId('settings-wipe').click();
    await expect(page.getByTestId('trust-status-basis')).toHaveText('Decisions on this device · no snapshot, pinned trust only');
  });

  await test.step('the issuer is unknown by its URL; after confirmation the mDL chains to the pinned Animo root', async () => {
    await loadOffer(page, await createMdlOffer(request));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('UNKNOWN', { timeout: 60_000 });
    await expect(page.getByTestId('issuer-trust-source')).toHaveText('decided on: device · pinned trust, no snapshot');
    // No image of an unknown party is fetched: the issuer's logo is not shown.
    await expect(page.getByTestId('issuer-section').locator('img')).toHaveCount(0);
    await expect(page.getByTestId('offer-accept')).toHaveCount(0);
    await page.getByTestId('issuer-confirm-unknown').click();
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 90_000 });
    await expect(page.getByTestId('issued-trust-0-source')).toHaveText('decided on: device · pinned trust, no snapshot');
    await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
    await page.getByTestId('receive-done').click();
    await page.getByTestId('credential-card-0').click();
    await expect(page.getByTestId('evidence-x509')).toContainText('Animo Playground Root');
    await shot(page, 'animo-pinned-credential');
  });

  await test.step("Animo's verifier is trusted through the pinned root too", async () => {
    const req = await createMdlRequest(request);
    await loadRequest(page, req.authorizationRequestUri);
    await expect(page.getByTestId('verifier-trust-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
    await expect(page.getByTestId('verifier-trust-source')).toHaveText('decided on: device · pinned trust, no snapshot');
    await page.getByTestId('present-share').click();
    await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200', { timeout: 60_000 });
    await verified(request, req.verificationSessionId);
  });
});
