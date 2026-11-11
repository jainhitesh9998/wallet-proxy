/** What the specs share: where the local services are, and the wallet's screens as a user walks them. */
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

export const TRUST_URL = process.env.TRUST_URL ?? 'http://localhost:8090';
export const ADMIN_KEY = process.env.TRUST_ADMIN_KEY ?? 'admin-key';
/** The reference issuer and verifier (test-ecosystem/), started and listed in the trust service by scripts/dev-up.sh. */
export const ISSUER = 'http://localhost:8791';
export const VERIFIER = 'http://localhost:8792';
/** A second reference issuer, started by Playwright (playwright.config.ts), which one test lists as suspended. */
export const SUSPENDED_ISSUER_PORT = 8793;
export const SUSPENDED_ISSUER = `http://localhost:${SUSPENDED_ISSUER_PORT}`;

/** The reference issuer's credential configurations (test-ecosystem/README.md). */
export const CONFIGURATIONS = {
  ecdsa: 'UniversityDegree_ldp_vc_ecdsa-rdfc-2019',
  eddsa: 'UniversityDegree_ldp_vc_eddsa-rdfc-2022',
  mdl: 'mDL_mso_mdoc',
  identity: 'Identity_dc_sd_jwt',
} as const;

export type RequestStatus = 'pending' | 'verified' | 'failed' | 'rejected' | 'expired';

/** An offer from a reference issuer's admin API. */
export async function createOffer(request: APIRequestContext, options: Record<string, unknown>, issuer = ISSUER): Promise<string> {
  const r = await request.post(`${issuer}/api/offers`, { data: options });
  expect(r.ok(), `offer creation at ${issuer}: HTTP ${r.status()}`).toBeTruthy();
  const { credentialOfferUri } = (await r.json()) as { credentialOfferUri: string };
  expect(credentialOfferUri).toMatch(/^openid-credential-offer:\/\//);
  return credentialOfferUri;
}

/** A presentation request from the reference verifier's admin API. */
export async function createRequest(request: APIRequestContext, credentials: Array<Record<string, unknown>>, responseMode = 'direct_post.jwt') {
  const r = await request.post(`${VERIFIER}/api/requests`, { data: { credentials, responseMode } });
  expect(r.ok(), `request creation: HTTP ${r.status()}`).toBeTruthy();
  return (await r.json()) as { id: string; authorizationRequestUri: string };
}

/** What the reference verifier made of the wallet's response. */
export async function requestState(request: APIRequestContext, id: string) {
  const r = await request.get(`${VERIFIER}/api/requests/${id}`);
  return (await r.json()) as { status: RequestStatus; error?: string; credentials?: Record<string, Array<{ format: string; claims: Record<string, unknown> }>> };
}

/** Full-page screenshot attached to the HTML report (and kept under test-results/). */
export async function shot(page: Page, name: string) {
  const path = test.info().outputPath(`${name}.png`);
  await page.screenshot({ path, fullPage: true });
  await test.info().attach(name, { path, contentType: 'image/png' });
}

/** Browser console errors, except those of the simulated outage (the trust client is pointed at 127.0.0.1:9). */
export function logConsoleErrors(page: Page) {
  page.on('console', (m) => { if (m.type() === 'error' && !/ERR_UNSAFE_PORT|ERR_CONNECTION_REFUSED/.test(m.text())) console.log(`[browser] ${m.text()}`); });
  page.on('pageerror', (e) => console.log(`[browser] uncaught: ${e.message}`));
}

export async function home(page: Page) {
  await page.goto('/');
  await expect(page.getByTestId('nav-receive')).toBeVisible();
}

/** Home, once the wallet holds a verified snapshot from the trust service. */
export async function homeWithSnapshot(page: Page) {
  await home(page);
  await expect(page.getByTestId('trust-status')).toHaveText('Trust service: online');
  await expect(page.getByTestId('trust-status-basis')).toContainText('snapshot of');
}

export async function settings(page: Page) {
  await home(page);
  await page.getByTestId('nav-settings').click();
  await expect(page.getByTestId('settings-screen')).toBeVisible();
}

/** Pastes an offer on the Receive screen and loads it. What is shown next depends on the issuer's trust. */
export async function loadOffer(page: Page, offer: string) {
  await home(page);
  await page.getByTestId('nav-receive').click();
  await page.getByTestId('offer-input').fill(offer);
  await page.getByTestId('offer-load').click();
}

/** Pastes a presentation request on the Present screen and loads it. */
export async function loadRequest(page: Page, uri: string) {
  await home(page);
  await page.getByTestId('nav-present').click();
  await page.getByTestId('present-input').fill(uri);
  await page.getByTestId('present-load').click();
}

/** The paths the page requested at an origin, in order (to see what the wallet asked a party for, and when). */
export function requestsTo(page: Page, origin: string): string[] {
  const seen: string[] = [];
  page.on('request', (r) => {
    if (r.url().startsWith(`${origin}/`) && r.method() !== 'OPTIONS') seen.push(`${r.method()} ${new URL(r.url()).pathname}`);
  });
  return seen;
}

/** Registers or removes an entity or anchor in the trust service through its admin API (the 'managed' source). */
export async function managed(request: APIRequestContext, method: 'PUT' | 'DELETE', kind: 'entities' | 'anchors', id: string, body?: unknown) {
  const r = await request.fetch(`${TRUST_URL}/admin/v1/managed/${kind}/${id}`, { method, headers: { Authorization: `Bearer ${ADMIN_KEY}` }, ...(body === undefined ? {} : { data: body }) });
  if (!r.ok() && !(method === 'DELETE' && r.status() === 404)) throw new Error(`${method} ${kind}/${id}: HTTP ${r.status()} ${(await r.text()).slice(0, 300)}`);
}

/** The entities of the snapshot the trust service serves the demo wallet now. */
export async function snapshotEntities(request: APIRequestContext): Promise<Array<{ id: string; status: string }>> {
  const r = await request.get(`${TRUST_URL}/api/v1/snapshot`, { headers: { Authorization: 'Bearer demo-wallet-key', Accept: 'application/jwt' } });
  const payload = JSON.parse(Buffer.from((await r.text()).split('.')[1]!, 'base64url').toString()) as { entities: Array<{ id: string; status: string }> };
  return payload.entities;
}
