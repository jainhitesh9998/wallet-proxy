/**
 * The demo wallet (web build) against the local reference ecosystem and the local trust service. No internet needed.
 *
 *   - trust status and settings: the snapshot, proxy-first defaults, the service key pin, settings of an earlier version
 *   - each of the reference issuer's four configurations: the issuer's trust before anything is requested, issuance,
 *     the verification report, and a presentation the reference verifier verifies
 *   - the authorization code flow from the demo issuer list
 *   - a trust service outage: with a snapshot, business as usual over the fallback; without one, the issuer is unknown,
 *     needs the user's explicit confirmation, and a credential whose signer certificate chains to no anchor is refused
 *   - an issuer the trust service lists as suspended: refused, with no way around it
 *   - a request with an optional credential: shared only when the user adds it
 *
 * Every test starts with a new browser profile, that is, a wallet that has never run.
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, test, type Page } from '@playwright/test';
import { CONFIGURATIONS, createOffer, createRequest, home, homeWithSnapshot, ISSUER, loadOffer, loadRequest, logConsoleErrors, managed, requestState,
  requestsTo, settings, shot, snapshotEntities, SUSPENDED_ISSUER, TRUST_URL, VERIFIER } from './support';

test.beforeEach(({ page }) => logConsoleErrors(page));

/** The check ids of the open credential detail, with their status: { 'mdoc.signature': 'PASS', … }. */
async function reportChecks(page: Page): Promise<Record<string, string>> {
  const rows = page.locator('[data-testid="checks"] [data-testid^="check-status-"]');
  await expect(rows.first()).toBeVisible();
  const out: Record<string, string> = {};
  for (const row of await rows.all()) out[(await row.getAttribute('data-testid'))!.slice('check-status-'.length)] = await row.innerText();
  return out;
}

/** Accepts the loaded pre-authorized offer of a TRUSTED issuer and opens the stored credential. */
async function acceptAndOpen(page: Page) {
  await page.getByTestId('offer-accept').click();
  await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
  await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
  await page.getByTestId('receive-done').click();
  await page.getByTestId('credential-card-0').click();
  await expect(page.getByTestId('detail-trust-decision')).toHaveText('TRUSTED');
}

/** Presents to the reference verifier and waits for its verdict. */
async function presentAndVerify(page: Page, request: Parameters<typeof createRequest>[0], credentials: Array<Record<string, unknown>>) {
  const req = await createRequest(request, credentials);
  await loadRequest(page, req.authorizationRequestUri);
  await expect(page.getByTestId('verifier-name')).toHaveText('Reference verifier');
  await expect(page.getByTestId('verifier-trust-decision')).toHaveText('TRUSTED');
  await expect(page.getByTestId('verifier-trust-source')).toHaveText(/decided on: device · snapshot of /);
  await page.getByTestId('present-share').click();
  await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200', { timeout: 60_000 });
  await expect.poll(async () => (await requestState(request, req.id)).status, { timeout: 30_000, intervals: [300, 500, 1000] }).toBe('verified');
  return requestState(request, req.id);
}

const CASES = [
  { name: 'W3C VC, ecdsa-rdfc-2019', configuration: CONFIGURATIONS.ecdsa,
    pass: ['ldp.model', 'ldp.requested', 'ldp.signature', 'ldp.contexts', 'ldp.validity', 'ldp.holder', 'ldp.status', 'issuer.trust'],
    query: { id: 'degree', format: 'ldp_vc', type: ['https://reference.example/vocab#UniversityDegreeCredential'], claims: [['credentialSubject', 'givenName']] } },
  { name: 'W3C VC, eddsa-rdfc-2022', configuration: CONFIGURATIONS.eddsa,
    pass: ['ldp.model', 'ldp.requested', 'ldp.signature', 'ldp.contexts', 'ldp.validity', 'ldp.holder', 'ldp.status', 'issuer.trust'],
    query: { id: 'degree', format: 'ldp_vc', type: ['https://reference.example/vocab#UniversityDegreeCredential'], claims: [['credentialSubject', 'givenName']] } },
  { name: 'ISO mDL', configuration: CONFIGURATIONS.mdl,
    pass: ['mdoc.signature', 'mdoc.doctype', 'mdoc.digests', 'mdoc.validity', 'mdoc.device_key', 'issuer.trust'],
    query: { id: 'mdl', format: 'mso_mdoc', doctype: 'org.iso.18013.5.1.mDL', claims: [['org.iso.18013.5.1', 'family_name']] } },
  { name: 'SD-JWT VC', configuration: CONFIGURATIONS.identity,
    pass: ['sdjwt.typ', 'sdjwt.signature', 'sdjwt.disclosures', 'sdjwt.vct', 'sdjwt.validity', 'sdjwt.holder', 'sdjwt.status', 'issuer.trust'],
    query: { id: 'identity', format: 'dc+sd-jwt', vct: 'urn:reference:identity:1', claims: [['given_name']] } },
] as const;

for (const c of CASES) {
  test(`reference issuer: ${c.name} is issued, verified and presented`, async ({ page, request }) => {
    const asked = requestsTo(page, ISSUER);
    await homeWithSnapshot(page);

    await test.step('the issuer is TRUSTED before anything is requested from it', async () => {
      await loadOffer(page, await createOffer(request, { configurationIds: [c.configuration] }));
      await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');
      await expect(page.getByTestId('issuer-name')).toHaveText('Reference issuer');
      await expect(page.getByTestId('issuer-trust-source')).toHaveText(/decided on: device · snapshot of /);
      await expect(page.getByTestId('issuer-metadata-source')).toHaveText('proxy');
      await expect(page.getByTestId('issuer-unknown-warning')).toHaveCount(0);
      // The offer came by value and the metadata through the proxy: the issuer has not heard from this wallet.
      expect(asked).toEqual([]);
    });

    await test.step('the credential is issued and its report has no failure', async () => {
      await acceptAndOpen(page);
      const checks = await reportChecks(page);
      for (const id of c.pass) expect(checks[id], `check ${id}`).toBe('PASS');
      expect(Object.values(checks)).not.toContain('FAIL');
      await expect(page.getByTestId('checks-summary')).toContainText(' 0 failed');
      await shot(page, `credential-${c.configuration}`);
    });

    await test.step('the reference verifier verifies the presentation', async () => {
      const state = await presentAndVerify(page, request, [c.query]);
      expect(Object.keys(state.credentials ?? {})).toEqual([c.query.id]);
    });
  });
}

test('trust status: the snapshot, proxy-first lookups and the service key pin', async ({ page, request }) => {
  await settings(page);

  await test.step('TrustClient.status() is shown: service, snapshot, counts', async () => {
    await expect(page.getByTestId('status-service')).toHaveText('online');
    await expect(page.getByTestId('status-degraded')).toHaveText('from a current snapshot');
    await expect(page.getByTestId('snapshot-issued')).toHaveText(/^\d{4}-\d\d-\d\d /);
    await expect(page.getByTestId('snapshot-expiry')).toHaveText(/^\d{4}-\d\d-\d\d /);
    await expect(page.getByTestId('snapshot-contents')).toHaveText(/^\d+ entities, \d+ trust anchors, \d+ DID documents, \d+ JSON-LD contexts, \d+ CRLs$/);
    await expect(page.getByTestId('status-sync-error')).toHaveCount(0);
    await expect(page.getByTestId('pinned-note')).toContainText('Pinned trust is used only while no snapshot is usable');
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: online');
    await expect(page.getByTestId('settings-trust-status-basis')).toContainText('Decisions on this device · snapshot of');
  });

  await test.step('lookups go through the proxy by default; unknown parties are not asked about', async () => {
    for (const kind of ['metadata', 'did', 'crl', 'status-lists']) await expect(page.getByTestId(`settings-${kind}-proxy`)).toHaveAttribute('aria-checked', 'true');
    await expect(page.getByTestId('settings-unknown-parties-state')).toHaveText('OFF');
    await expect(page.getByTestId('settings-outage-state')).toHaveText('OFF');
  });

  await test.step('without a thumbprint the service key is trusted on first use, labelled development only', async () => {
    await expect(page.getByTestId('settings-service-key')).toHaveValue('');
    await expect(page.getByTestId('settings-service-key-mode')).toContainText('Development only');
  });

  await test.step('with the published thumbprint pinned, the snapshot still verifies', async () => {
    const discovery = (await (await request.get(`${TRUST_URL}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string };
    await page.getByTestId('settings-service-key').fill(discovery.signing_key_thumbprint);
    await page.getByTestId('settings-save').click();
    await expect(page.getByTestId('settings-message')).toContainText('Saved');
    await expect(page.getByTestId('settings-service-key-mode')).toContainText('Only snapshots and proxied documents signed with this key are accepted');
    await page.getByTestId('settings-sync-snapshot').click();
    await expect(page.getByTestId('sync-message')).toContainText('verified and stored');
    await expect(page.getByTestId('status-degraded')).toHaveText('from a current snapshot');
  });

  await test.step('with another thumbprint pinned, nothing the service signs is accepted', async () => {
    await page.getByTestId('settings-service-key').fill('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    await page.getByTestId('settings-save').click();
    await expect(page.getByTestId('settings-message')).toContainText('Saved');
    await page.getByTestId('settings-sync-snapshot').click();
    await expect(page.getByTestId('sync-error')).toContainText('could not be refreshed');
    await expect(page.getByTestId('snapshot-none')).toBeVisible();
    await expect(page.getByTestId('status-degraded')).toContainText('no usable snapshot, only pinned trust decides');
    await expect(page.getByTestId('status-sync-error')).toContainText('failed: ');
    await shot(page, 'settings-wrong-service-key');
  });
});

test('a trust service URL the client cannot use leaves the wallet without a service, not broken', async ({ page }) => {
  await settings(page);
  for (const unusable of ['localhost:8090', 'http://localhost@elsewhere.example:8090']) {
    await page.getByTestId('settings-trust-url').fill(unusable);
    await page.getByTestId('settings-save').click();
    await expect(page.getByTestId('settings-error')).toContainText('the wallet runs without a trust service');
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: not configured');
    await expect(page.getByTestId('status-degraded')).toContainText('no usable snapshot, only pinned trust decides');
  }
  await page.getByTestId('settings-trust-url').fill(TRUST_URL);
  await page.getByTestId('settings-save').click();
  await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: online');
  await expect(page.getByTestId('status-degraded')).toHaveText('from a current snapshot');
});

test('settings stored by an earlier version of the app are carried over', async ({ page }) => {
  // What the previous version stored: one `lookups` value, 'service' for the proxy, and three settings that are gone.
  await page.addInitScript(() => {
    if (!localStorage.getItem('app:settings')) {
      localStorage.setItem('app:settings', JSON.stringify({ trustUrl: 'http://localhost:8090', apiKey: 'demo-wallet-key', clientId: 'demo-wallet',
        corsRelayUrl: 'http://localhost:8787', decisions: 'service', lookups: 'service', unknownParties: false, crls: 'none', statusLists: 'direct',
        fallbackEnabled: false, simulateOutage: false, dpop: 'never', walletAttestation: 'auto', keyAttestation: 'auto', highAssurance: false, batchSize: '1' }));
    }
  });
  await settings(page);
  await expect(page.getByTestId('status-service')).toHaveText('online');
  await expect(page.getByTestId('settings-metadata-proxy')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('settings-did-proxy')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('settings-crl-none')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('settings-status-lists-direct')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('settings-dpop-never')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('settings-batch-1')).toHaveAttribute('aria-checked', 'true');
  // A change is stored in the new shape only.
  await page.getByTestId('settings-status-lists-proxy').click();
  await expect(page.getByTestId('settings-status-lists-proxy')).toHaveAttribute('aria-checked', 'true');
  const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('app:settings')!) as Record<string, unknown>);
  expect(stored).toMatchObject({ metadata: 'proxy', did: 'proxy', crl: 'none', statusLists: 'proxy', serviceKeyThumbprint: '' });
  for (const gone of ['decisions', 'fallbackEnabled', 'corsRelayUrl', 'lookups', 'crls']) expect(stored).not.toHaveProperty(gone);
});

test('demo issuer list: an offer of the reference issuer, authorization code flow', async ({ page }) => {
  await homeWithSnapshot(page);
  await page.getByTestId('nav-receive').click();
  await page.getByTestId('tab-issuers').click();
  await expect(page.getByTestId('demo-issuer-reference')).toContainText(ISSUER);
  await expect(page.getByTestId('demo-issuer-animo')).toContainText('https://playground.animo.id');
  await shot(page, 'demo-issuers');
  await page.getByTestId('demo-grant-reference-authorization_code').click();
  await page.getByTestId(`demo-offer-${CONFIGURATIONS.mdl}`).click();
  await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');
  await expect(page.getByTestId('offer-grant')).toHaveText('authorization_code');

  // The reference authorization server asks nobody: the new tab is redirected straight back to the wallet's callback page.
  const popup = page.waitForEvent('popup');
  await page.getByTestId('auth-begin').click();
  await expect((await popup).getByTestId('oauth-callback-done')).toBeVisible();
  await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
  await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
});

test('trust service outage with a snapshot: decisions from the snapshot, lookups from the issuer', async ({ page, request }) => {
  await homeWithSnapshot(page);
  await page.getByTestId('nav-settings').click();
  await page.getByTestId('settings-outage').click();
  await expect(page.getByTestId('settings-outage-state')).toHaveText('ON');
  await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: offline');
  await expect(page.getByTestId('status-service')).toContainText('offline');
  await expect(page.getByTestId('status-degraded')).toHaveText('from a current snapshot');
  await expect(page.getByTestId('status-sync-error')).toContainText('failed: ');

  await loadOffer(page, await createOffer(request, { configurationIds: [CONFIGURATIONS.identity] }));
  await expect(page.getByTestId('issuer-trust-decision')).toHaveText('TRUSTED');
  await expect(page.getByTestId('issuer-trust-source')).toHaveText(/decided on: device · snapshot of /);
  // The proxy could not serve: standard discovery at the issuer instead.
  await expect(page.getByTestId('issuer-metadata-source')).toHaveText('fallback');
  await acceptAndOpen(page);
  const checks = await reportChecks(page);
  expect(checks['sdjwt.status']).toBe('PASS');
  expect(Object.values(checks)).not.toContain('FAIL');
  await home(page);
  await expect(page.getByTestId('trust-status')).toHaveText('Trust service: offline');
  await expect(page.getByTestId('trust-status-outage')).toBeVisible();
  await shot(page, 'outage-with-snapshot');
});

test('no snapshot and no trust service: the issuer is unknown, needs explicit confirmation, and an mdoc is still refused', async ({ page, request }) => {
  const asked = requestsTo(page, ISSUER);

  await test.step('a wallet that cannot reach the service and holds no snapshot decides from pinned trust only', async () => {
    await homeWithSnapshot(page);
    await page.getByTestId('nav-settings').click();
    await page.getByTestId('settings-outage').click();
    await expect(page.getByTestId('settings-trust-status')).toHaveText('Trust service: offline');
    await page.getByTestId('settings-wipe').click();
    await page.getByTestId('settings-wipe').click();
    await expect(page.getByTestId('trust-status-basis')).toHaveText('Decisions on this device · no snapshot, pinned trust only');
    await page.getByTestId('nav-settings').click();
    await expect(page.getByTestId('snapshot-none')).toBeVisible();
    await expect(page.getByTestId('status-degraded')).toContainText('no usable snapshot, only pinned trust decides');
  });

  await test.step('an offer of the reference issuer: UNKNOWN, with a warning and nothing to accept', async () => {
    await loadOffer(page, await createOffer(request, { configurationIds: [CONFIGURATIONS.ecdsa] }));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('UNKNOWN');
    await expect(page.getByTestId('issuer-trust-source')).toHaveText('decided on: device · pinned trust, no snapshot');
    await expect(page.getByTestId('issuer-unknown-warning')).toContainText('Unknown issuer: no trust list vouches for http://localhost:8791');
    await expect(page.getByTestId('issuer-name-claimed')).toBeVisible();
    await expect(page.getByTestId('issuer-metadata-source')).toHaveText('fallback');
    await expect(page.getByTestId('offer-accept')).toHaveCount(0);
    await expect(page.getByTestId('issuer-section').locator('img')).toHaveCount(0);
    // Only the issuer's public metadata was read (the proxy is down, so from the issuer itself): no token, nonce or credential request.
    expect(asked).toContain('GET /.well-known/openid-credential-issuer');
    expect(asked.filter((r) => !r.includes('/.well-known/'))).toEqual([]);
    await shot(page, 'unknown-issuer-warning');
  });

  await test.step('after the explicit confirmation a DID-signed credential is kept, as UNKNOWN', async () => {
    await page.getByTestId('issuer-confirm-unknown').click();
    await expect(page.getByTestId('issuer-unknown-warning')).toContainText('You chose to continue');
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('UNKNOWN', { timeout: 60_000 });
    await expect(page.getByTestId('issued-trust-0-valid')).toHaveText('✓ valid signature');
    // Warnings stay visible: the JSON-LD context came from its own host, and nobody vouches for the issuer.
    const findings = page.getByTestId('issued-findings-0');
    await expect(findings.getByTestId('check-status-ldp.contexts')).toHaveText('WARN');
    await expect(findings.getByTestId('check-status-issuer.trust')).toHaveText('WARN');
    await page.getByTestId('receive-done').click();
    await expect(page.getByTestId('credential-count')).toHaveText('1 credential(s)');
    await expect(page.getByTestId('credential-trust-0-decision')).toHaveText('UNKNOWN');
  });

  await test.step('an mdoc is refused even after confirmation: its signer certificate chains to no trusted anchor', async () => {
    await loadOffer(page, await createOffer(request, { configurationIds: [CONFIGURATIONS.mdl] }));
    await expect(page.getByTestId('issuer-trust-decision')).toHaveText('UNKNOWN');
    await expect(page.getByTestId('offer-accept')).toHaveCount(0);
    await page.getByTestId('issuer-confirm-unknown').click();
    await page.getByTestId('offer-accept').click();
    await expect(page.getByTestId('refused-reason')).toContainText('signing certificate does not chain to a trusted anchor', { timeout: 60_000 });
    const report = page.getByTestId('refused-report');
    await expect(report.getByTestId('check-status-mdoc.signature')).toHaveText('PASS');
    await expect(report.getByTestId('check-status-issuer.trust')).toHaveText('WARN');
    await expect(page.getByTestId('issued-section')).toHaveCount(0);
    await shot(page, 'mdoc-refused');
    await home(page);
    await expect(page.getByTestId('credential-count')).toHaveText('1 credential(s)');
  });
});

test.describe('an issuer the trust service lists as suspended', () => {
  const ENTITY = 'e2e-suspended-issuer';
  test.beforeAll(async ({ request }) => {
    await managed(request, 'PUT', 'entities', ENTITY, { framework: 'reference', roles: ['CREDENTIAL_ISSUER'], name: 'Suspended issuer (e2e)',
      identifiers: [{ type: 'URL', value: SUSPENDED_ISSUER }], status: 'SUSPENDED' });
    await expect.poll(async () => (await snapshotEntities(request)).find((e) => e.id === ENTITY)?.status, { timeout: 30_000 }).toBe('SUSPENDED');
  });
  test.afterAll(async ({ request }) => {
    await managed(request, 'DELETE', 'entities', ENTITY);
  });

  test('is refused with the reason, and there is no way around it', async ({ page, request }) => {
    const asked = requestsTo(page, SUSPENDED_ISSUER);
    await homeWithSnapshot(page);
    await loadOffer(page, await createOffer(request, { configurationIds: [CONFIGURATIONS.identity] }, SUSPENDED_ISSUER));
    await expect(page.getByTestId('issuer-refused')).toContainText(`The issuer ${SUSPENDED_ISSUER} is not trusted`);
    await expect(page.getByTestId('issuer-refused')).toContainText('SUSPENDED');
    for (const id of ['offer-accept', 'auth-begin', 'issuer-confirm-unknown', 'issuer-section']) await expect(page.getByTestId(id)).toHaveCount(0);
    // The wallet asked the refused issuer for nothing at all.
    expect(asked).toEqual([]);
    await shot(page, 'issuer-refused');
    await page.getByTestId('receive-start-over').click();
    await expect(page.getByTestId('offer-input')).toBeVisible();
  });
});

test('a credential the verifier marks optional is shared only when the user adds it', async ({ page, request }) => {
  // A verifier of this test's own: an unsigned request (client identifier prefix redirect_uri) whose response it records.
  const received: Array<Record<string, unknown>> = [];
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS' };
  const server = createServer((req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(204, cors).end(); return; }
    let body = '';
    req.on('data', (d: Buffer) => { body += d.toString(); });
    req.on('end', () => {
      received.push(JSON.parse(new URLSearchParams(body).get('vp_token') ?? '{}') as Record<string, unknown>);
      res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }).end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const responseUri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/response`;
  const requestUri = (nonce: string) => `openid4vp://?${new URLSearchParams({
    client_id: `redirect_uri:${responseUri}`, response_type: 'vp_token', response_mode: 'direct_post', response_uri: responseUri, nonce,
    dcql_query: JSON.stringify({
      credentials: [
        { id: 'identity', format: 'dc+sd-jwt', meta: { vct_values: ['urn:reference:identity:1'] }, claims: [{ path: ['given_name'] }] },
        { id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' }, claims: [{ path: ['org.iso.18013.5.1', 'family_name'] }] },
      ],
      credential_sets: [{ options: [['identity']] }, { options: [['mdl']], required: false }],
    }),
  })}`;

  try {
    await homeWithSnapshot(page);
    for (const configuration of [CONFIGURATIONS.identity, CONFIGURATIONS.mdl]) {
      await loadOffer(page, await createOffer(request, { configurationIds: [configuration] }));
      await page.getByTestId('offer-accept').click();
      await expect(page.getByTestId('issued-trust-0-decision')).toHaveText('TRUSTED', { timeout: 60_000 });
    }

    await test.step('by default only the required credential is shared', async () => {
      await loadRequest(page, requestUri('nonce-one'));
      await expect(page.getByTestId('verifier-trust-decision')).toHaveText('UNKNOWN');
      await expect(page.getByTestId('dcql-status-identity')).toContainText('required');
      await expect(page.getByTestId('dcql-status-mdl')).toContainText('optional, not shared');
      await expect(page.getByTestId('dcql-include-mdl-state')).toHaveText('OFF');
      await shot(page, 'optional-credential-off');
      await page.getByTestId('present-share').click();
      await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200');
      expect(Object.keys(received[0]!)).toEqual(['identity']);
    });

    await test.step('with the toggle on, the optional credential is shared too', async () => {
      await loadRequest(page, requestUri('nonce-two'));
      await page.getByTestId('dcql-include-mdl').click();
      await expect(page.getByTestId('dcql-include-mdl-state')).toHaveText('ON');
      await expect(page.getByTestId('dcql-status-mdl')).toContainText('optional, will be shared');
      await page.getByTestId('present-share').click();
      await expect(page.getByTestId('present-result-status')).toContainText('HTTP 200');
      expect(Object.keys(received[1]!).sort()).toEqual(['identity', 'mdl']);
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
