/**
 * End-to-end Digital Credentials API test on an Android emulator: Animo's playground verifier in Chrome calls
 * navigator.credentials.get, Play services shows its picker with this wallet's registered credentials, the wallet's
 * DC API activity shows the request and shares (or declines), and the verifier reports the result.
 *
 * Needs: an emulator with Chrome >= 141 and Play services >= 24.31 (e.g. system image android-37.2 google_apis), the
 * wallet's release build installed (scripts/android-dcapi.sh build), the trust service on the host's :8090
 * (scripts/dev-up.sh), the internet (the Animo playground), and the wallet holding an mDL (mdl-mdoc-utopia) and a PID
 * (eudi-pid-sd-jwt-utopia) from the playground. The script sets up adb reverse for the trust service (8090) and the
 * reference issuer and verifier (8791, 8792), which the wallet reaches as localhost.
 *
 *   node e2e/dcapi-android.mjs issue [serial]  load the mDL and the PID into the wallet (pre-authorized offers, via its UI)
 *   node e2e/dcapi-android.mjs [serial]        run the scenarios (default emulator-5556; ANDROID_HOME defaults to ~/.local/tools/android-sdk)
 *   node e2e/dcapi-android.mjs --only=multi    only the scenarios whose name contains the text
 */
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createSign, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { chromium } from '@playwright/test';

const ISSUE = process.argv.includes('issue');
const SERIAL = process.argv.slice(2).find((a) => a !== 'issue' && !a.startsWith('--')) ?? 'emulator-5556';
const ONLY = process.argv.find((a) => a.startsWith('--only='))?.slice('--only='.length);
const ADB = `${process.env.ANDROID_HOME ?? `${homedir()}/.local/tools/android-sdk`}/platform-tools/adb`;
const CDP_PORT = 9333;
const PLAYGROUND = 'https://playground.animo.id/';

const adb = (...args) => execFileSync(ADB, ['-s', SERIAL, ...args], { encoding: 'utf8' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Host ports the wallet reaches as localhost: the trust service, the reference issuer, the reference verifier. */
const HOST_PORTS = [8090, 8791, 8792];
for (const port of HOST_PORTS) adb('reverse', `tcp:${port}`, `tcp:${port}`);

/** The on-screen nodes: resource-id (React Native testID), text / content-desc, bounds centre. */
function screen() {
  // A dump fails while a window animates; never read the previous one instead.
  adb('shell', 'rm', '-f', '/sdcard/ui.xml');
  if (!adb('shell', 'uiautomator', 'dump', '/sdcard/ui.xml').includes('dumped')) return [];
  const xml = adb('exec-out', 'cat', '/sdcard/ui.xml');
  return [...xml.matchAll(/<node [^>]*>/g)].map(([n]) => {
    const attr = (k) => (new RegExp(` ${k}="([^"]*)"`).exec(n)?.[1] ?? '').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
    const [l, t, r, b] = (attr('bounds').match(/\d+/g) ?? []).map(Number);
    return { id: attr('resource-id').split('/').pop(), text: attr('text') || attr('content-desc'), x: (l + r) >> 1, y: (t + b) >> 1 };
  });
}
const matches = (n, key) => n.id === key || n.text === key;
async function waitFor(key, ms = 20000) {
  for (const end = Date.now() + ms; Date.now() < end; await sleep(700)) {
    const n = screen().find((x) => matches(x, key));
    if (n) return n;
  }
  return undefined;
}
async function tap(key, ms) {
  const n = await waitFor(key, ms);
  if (!n) throw new Error(`Not on screen: ${key}`);
  adb('shell', 'input', 'tap', String(n.x), String(n.y));
}
/** Scrolls the wallet's screen until {@code key} is well inside the visible area (not under the nav bar). */
async function scrollTo(key) {
  for (let i = 0; i < 6; i++) {
    if (screen().some((x) => matches(x, key) && x.y < 2100)) return;
    adb('shell', 'input', 'swipe', '540', '1900', '540', '700', '300');
    await sleep(600);
  }
}

async function chromePage() {
  adb('shell', 'am', 'start', '-n', 'com.android.chrome/com.google.android.apps.chrome.Main');   // to the front, no new tab
  await sleep(3000);
  adb('forward', `tcp:${CDP_PORT}`, 'localabstract:chrome_devtools_remote');
  const browser = await chromium.connectOverCDP(`http://localhost:${CDP_PORT}`);
  const [page, ...others] = browser.contexts()[0].pages();
  for (const p of others) await p.close();               // one tab, the one on screen
  const tab = page ?? (await browser.contexts()[0].newPage());
  await tab.bringToFront();
  return { browser, page: tab };
}

/**
 * Decline: the wallet cancels. Play services may show its picker again, which the user closes. The page then gets the
 * same NotAllowedError as for any abort; nothing tells it the wallet was involved (OpenID4VP §15.9.2).
 */
async function decline() {
  await scrollTo('dcapi-decline');
  await tap('dcapi-decline');
  if (await waitFor('Close', 8000)) await tap('Close');
}

const SCENARIOS = [
  { name: 'PID (dc+sd-jwt), signed x509_hash request, dc_api.jwt', credential: 'eudi-pid', formats: ['dc+sd-jwt'], attributes: ['given_name', 'family_name'],
    signer: 'x5c', mode: 'dc_api.jwt', expect: 'success', protocol: 'openid4vp-v1-signed' },
  { name: 'mDL (mso_mdoc), signed x509_hash request, dc_api.jwt', credential: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name'],
    signer: 'x5c', mode: 'dc_api.jwt', expect: 'success', protocol: 'openid4vp-v1-signed' },
  { name: 'mDL (mso_mdoc), unsigned request, dc_api.jwt', credential: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name'],
    signer: 'none', mode: 'dc_api.jwt', expect: 'success', protocol: 'openid4vp-v1-unsigned' },
  { name: 'PID (dc+sd-jwt), unsigned request, dc_api (unencrypted)', credential: 'eudi-pid', formats: ['dc+sd-jwt'], attributes: ['given_name', 'family_name'],
    signer: 'none', mode: 'dc_api', expect: 'success', protocol: 'openid4vp-v1-unsigned' },
  { name: 'decline: the verifier learns only that the request ended', credential: 'mdl', formats: ['mso_mdoc'], attributes: ['given_name', 'family_name'],
    signer: 'x5c', mode: 'dc_api.jwt', expect: 'declined', protocol: 'openid4vp-v1-signed' },
];

async function run(s) {
  const { browser, page } = await chromePage();
  const request = { credentials: [{ id: s.credential, formats: s.formats, attributes: s.attributes }], combination: 'all' };
  const q = new URLSearchParams({ tab: 'verify', responseMode: s.mode, requestSignerType: s.signer, dcApiProtocol: 'openid4vp', request: JSON.stringify(request) });
  await page.goto(`${PLAYGROUND}?${q}`, { waitUntil: 'networkidle' });
  // What the page's navigator.credentials.get settles with (the playground's own status polling hides an abort).
  await page.evaluate(() => {
    const get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (o) => get(o).then((c) => { window.__dc = 'response'; return c; }, (e) => { window.__dc = `error ${e.name}`; throw e; });
  });
  await page.getByRole('button', { name: 'Verify Credential' }).click();

  // Chrome's one-time prompts, then its "share with this site?" interstitial, then the Play services picker.
  for (const prompt of ['No thanks']) if (await waitFor(prompt, 2500)) await tap(prompt);
  if (await waitFor('positive_button', 8000)) await tap('positive_button');
  await tap('continue_button', 20000);

  // The wallet's DC API activity
  if (!(await waitFor('dcapi-screen', 30000))) throw new Error('The wallet was not opened');
  await waitFor('verifier-section', 30000);
  const consent = screen();
  const protocol = consent.find((n) => n.id === 'dcapi-protocol')?.text ?? '';
  const origin = consent.find((n) => n.id === 'verifier-origin')?.text;
  const checks = consent.filter((n) => n.id.startsWith('verifier-check-')).map((n) => n.text);
  const trust = consent.find((n) => n.id === 'verifier-trust-decision')?.text;
  if (!protocol.includes(s.protocol)) throw new Error(`Expected ${s.protocol}, the wallet shows "${protocol}"`);
  // Signed: the x509_hash chain; unsigned: origin:https://playground.animo.id against the registry's URL identifier
  if (trust !== 'TRUSTED') throw new Error(`The wallet shows the verifier as ${trust}`);
  if (origin !== 'https://playground.animo.id') throw new Error(`Origin shown: ${origin}`);
  if (s.expect === 'declined') await decline();
  else {
    await scrollTo('dcapi-share');
    await tap('dcapi-share');
  }

  // The verifier's verdict
  const settled = await page.waitForFunction(() => window.__dc, undefined, { timeout: 45000 }).then((h) => h.jsonValue()).catch(() => 'nothing');
  const verdict = s.expect === 'declined' ? settled
    : await page.getByText(/^(Verification Successful|Verification Unsuccessful|Error creating request)$/).first().innerText({ timeout: 45000 }).catch(() => 'timeout');
  const detail = verdict === 'Verification Unsuccessful' ? (await page.getByRole('alert').innerText().catch(() => '')).replace(/\s+/g, ' ') : '';
  await browser.close();
  const ok = s.expect === 'success' ? settled === 'response' && verdict === 'Verification Successful' : settled === 'error NotAllowedError';
  return { ok, verdict, detail, protocol, checks: [...checks, `verifier ${trust}`] };
}

/**
 * Pre-authorized offers from the playground, accepted in the wallet's Receive screen. The wallet shows Accept only
 * for an issuer it trusts, so the trust service must list the playground (its default registry does).
 */
async function issue() {
  for (const id of ['mdl-mdoc-utopia', 'eudi-pid-sd-jwt-utopia']) {
    const r = await fetch(`${PLAYGROUND}api/offers/create`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credentialSupportedIds: [id], authorization: 'none', deferBy: 'none', requireDpop: true, requireWalletAttestation: false, requireKeyAttestation: false }) });
    const { credentialOffer } = await r.json();
    adb('shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', `'${credentialOffer}'`, 'dev.vctrust.wallet');
    await tap('offer-accept', 30000);
    if (!(await waitFor('issued-section', 60000))) throw new Error(`${id} was not issued`);
    const trust = screen().find((n) => n.id === 'issued-trust-0-decision')?.text;
    console.log(`issued ${id}: issuer ${trust}`);
    await scrollTo('receive-done');
    await tap('receive-done', 10000);
  }
}

if (ISSUE) {
  await issue();
  process.exit(0);
}

// ---- a multi-signed request (HAIP §5.2), which Animo does not send: a local verifier page on http://localhost (a
// secure context) through adb reverse, signed with the test PKI's relying-party key. No trust list contains that key,
// so the wallet must authenticate the request, show it, and block sharing.
const PKI = new URL('../conformance/pki/', import.meta.url);
const LOCAL_PORT = 8799;
const LOCAL = `http://localhost:${LOCAL_PORT}`;
const b64u = (b) => Buffer.from(b).toString('base64url');

function multiSignedRequest() {
  const der = Buffer.from(readFileSync(new URL('rp.pem', PKI), 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64');
  const clientId = `x509_hash:${b64u(createHash('sha256').update(der).digest())}`;
  const payload = b64u(JSON.stringify({ expected_origins: [LOCAL], response_type: 'vp_token', response_mode: 'dc_api', nonce: b64u(randomBytes(16)),
    dcql_query: { credentials: [{ id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' }, claims: [{ path: ['org.iso.18013.5.1', 'given_name'] }] }] } }));
  const prot = b64u(JSON.stringify({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [der.toString('base64')], client_id: clientId }));
  const sig = createSign('SHA256').update(`${prot}.${payload}`).sign({ key: createPrivateKey(readFileSync(new URL('rp.key', PKI))), dsaEncoding: 'ieee-p1363' });
  return { payload, signatures: [{ protected: prot, signature: b64u(sig) }] };
}

const PAGE = `<!doctype html><meta name="viewport" content="width=device-width"><button id="go">Request</button><pre id="out"></pre><script>
go.onclick = async () => {
  const request = await (await fetch('/request')).json();
  try {
    const c = await navigator.credentials.get({ digital: { requests: [{ protocol: 'openid4vp-v1-multisigned', data: { request } }] }, mediation: 'required' });
    out.textContent = 'response ' + JSON.stringify(c.data);
  } catch (e) { out.textContent = 'error ' + e.name; }
};
</script>`;

async function runMultiSigned() {
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', req.url === '/request' ? 'application/json' : 'text/html');
    res.end(req.url === '/request' ? JSON.stringify(multiSignedRequest()) : PAGE);
  }).listen(LOCAL_PORT);
  adb('reverse', `tcp:${LOCAL_PORT}`, `tcp:${LOCAL_PORT}`);
  const { browser, page } = await chromePage();
  try {
    await page.goto(LOCAL);
    await page.click('#go');
    if (await waitFor('positive_button', 8000)) await tap('positive_button');
    await tap('continue_button', 20000);
    if (!(await waitFor('verifier-section', 30000))) throw new Error('The wallet was not opened');
    const consent = screen();
    const protocol = consent.find((n) => n.id === 'dcapi-protocol')?.text ?? '';
    const checks = consent.filter((n) => n.id.startsWith('verifier-check-')).map((n) => n.text);
    const refusal = consent.find((n) => n.id === 'verifier-refusal')?.text;
    if (!protocol.includes('openid4vp-v1-multisigned')) throw new Error(`The wallet shows "${protocol}"`);
    if (!checks.some((c) => c.includes('Multi-signed request')) || !checks.some((c) => c.includes('x509_hash binding'))) throw new Error(`Checks: ${checks.join('; ')}`);
    if (!refusal) throw new Error('A verifier outside the trust lists was not blocked');
    await decline();
    await page.locator('#out').filter({ hasText: /^error NotAllowedError/ }).waitFor({ timeout: 30000 });
    return { ok: true, verdict: (await page.locator('#out').innerText()).trim(), protocol, checks: [...checks, refusal] };
  } finally {
    await browser.close();
    server.close();
  }
}

let failed = 0;
SCENARIOS.push({ name: 'multi-signed request from a verifier outside the trust lists (local page): authenticated, sharing blocked', run: runMultiSigned });
for (const s of SCENARIOS.filter((x) => !ONLY || x.name.includes(ONLY))) {
  try {
    const r = await (s.run ? s.run() : run(s));
    console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${s.name}: verifier ${r.verdict}${r.detail ? ` (${r.detail.trim().slice(0, 160)})` : ''}`);
    for (const c of r.checks) console.log(`        ${c}`);
    if (!r.ok) failed++;
  } catch (e) {
    failed++;
    console.log(`FAIL  ${s.name}: ${e.message}`);
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
  }
  await sleep(1500);
}
console.log(failed ? `${failed} of ${SCENARIOS.length} scenarios failed` : `All ${SCENARIOS.length} DC API scenarios passed`);
process.exit(failed ? 1 : 0);
