#!/usr/bin/env node
// Headless OpenID4VCI authorization-code issuance against MOSIP's public "collab" sandbox.
//
//   node issue.mjs <Land|Farmer|MockMdl>
//
// Flow: eSignet (esignet-mock) authorize + OTP login driven by headless Chromium
//   -> code exchanged at Mimoto's token proxy (Mimoto adds the private_key_jwt client assertion)
//   -> c_nonce from Certify's nonce endpoint
//   -> OpenID4VCI 1.0 credential request to Inji Certify with an ES256 proof JWT.
//
// stdout: the credential response JSON (verbatim). stderr: progress log.
// The raw response is also written to samples/<issuer>-<credential_configuration_id>.json.
//
// Env overrides:
//   MOSIP_INDIVIDUAL_ID (default 2154189532)  MOSIP_OTP (default 111111)
//   MOSIP_REDIRECT_URI  (default: the redirect_uri Mimoto publishes for the issuer)
//   HEADLESS=0 to watch the browser.  NO_SAVE=1 to skip writing samples/.

import { chromium } from 'playwright';
import * as jose from 'jose';
import { decode as cborDecode, Tag as CborTag } from 'cbor-x';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MIMOTO_ISSUERS_URL = 'https://api.collab.mosip.net/v1/mimoto/issuers';

/** The three issuers this tool supports; everything else is discovered at runtime. */
export const ISSUERS = {
  Land: {
    credentialIssuer: 'https://injicertify-landregistry.collab.mosip.net',
    credentialConfigurationId: 'LandStatementCredential_VCDM2.0',
  },
  Farmer: {
    credentialIssuer: 'https://injicertify-farmer.collab.mosip.net',
    credentialConfigurationId: 'FarmerCredential_VCDM2.0',
  },
  MockMdl: {
    credentialIssuer: 'https://injicertify-mdl.collab.mosip.net',
    credentialConfigurationId: 'DrivingLicenseCredential',
  },
};

export const DEFAULT_INDIVIDUAL_ID = '2154189532';
export const DEFAULT_OTP = '111111';

const log = (...a) => console.error('[issue]', ...a);
const b64u = (buf) => Buffer.from(buf).toString('base64url');

async function http(method, url, { headers = {}, body } = {}) {
  const res = await fetch(url, { method, headers, body });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, headers: Object.fromEntries(res.headers), text, json };
}

async function getJson(url) {
  const r = await http('GET', url, { headers: { accept: 'application/json' } });
  if (r.status !== 200 || !r.json) throw new Error(`GET ${url} -> ${r.status}: ${r.text.slice(0, 500)}`);
  return r.json;
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------
export function makePkce() {
  const codeVerifier = b64u(crypto.randomBytes(32));
  const codeChallenge = b64u(crypto.createHash('sha256').update(codeVerifier).digest());
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
}

// ---------------------------------------------------------------------------
// Browser login (exported for reuse by e2e suites)
// ---------------------------------------------------------------------------
/**
 * Drive the eSignet login UI headlessly and return the authorization code.
 *
 * Works for the collab eSignet mock UI (OTP login: "UIN/VID" -> Get OTP -> 6 OTP boxes -> Verify).
 * Any consent screen ("Allow"/"Proceed") is accepted. The code is captured from the navigation
 * to `redirectUri` (custom schemes like io.mosip.residentapp.inji:// never load; http(s) redirect
 * targets are intercepted and fulfilled locally so the real site is never hit). As a fallback it is
 * also read from eSignet's /authorization/auth-code XHR response, which carries {code, state}.
 *
 * @param {string} authorizeUrl  full eSignet /authorize URL
 * @param {string} redirectUri   redirect_uri used in authorizeUrl
 * @param {object} [opts]
 * @param {string} [opts.individualId]  UIN/VID to log in with (default 2154189532)
 * @param {string} [opts.otp]           OTP (collab mock accepts 111111)
 * @param {boolean} [opts.headless]     default true
 * @param {number} [opts.timeoutMs]     overall timeout, default 90s
 * @param {(msg:string)=>void} [opts.log]
 * @returns {Promise<{code: string, state: string|null, redirectUrl: string}>}
 */
export async function loginAndGetCode(authorizeUrl, redirectUri, opts = {}) {
  const individualId = opts.individualId ?? process.env.MOSIP_INDIVIDUAL_ID ?? DEFAULT_INDIVIDUAL_ID;
  const otp = String(opts.otp ?? process.env.MOSIP_OTP ?? DEFAULT_OTP);
  const timeoutMs = opts.timeoutMs ?? 90_000;
  const say = opts.log ?? ((m) => log(m));

  const browser = await chromium.launch({ headless: opts.headless ?? true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(30_000);

    let resolveCode;
    let rejectCode;
    const codePromise = new Promise((res, rej) => { resolveCode = res; rejectCode = rej; });
    let settled = false;
    const finish = (url) => {
      if (settled) return;
      const u = new URL(url);
      const code = u.searchParams.get('code');
      if (!code) {
        settled = true;
        rejectCode(new Error(`redirect without code: ${url}`));
        return;
      }
      settled = true;
      resolveCode({ code, state: u.searchParams.get('state'), redirectUrl: url });
    };
    const isRedirect = (url) => url.startsWith(redirectUri) && /[?&](code|error)=/.test(url);

    // 1) navigation/request to the redirect URI (fires for custom schemes as well)
    page.on('request', (req) => { if (isRedirect(req.url())) finish(req.url()); });
    // 2) http(s) redirect URIs: don't actually load the wallet site
    if (/^https?:/i.test(redirectUri)) {
      await context.route((url) => isRedirect(url.href), (route) => {
        finish(route.request().url());
        route.fulfill({ status: 200, contentType: 'text/plain', body: 'code captured' });
      });
    }
    // 3) eSignet API responses: fallback code capture + surface API errors
    const apiErrors = [];
    page.on('response', async (res) => {
      const url = res.url();
      if (!url.includes('/v1/esignet/authorization/')) return;
      let json;
      try { json = await res.json(); } catch { return; }
      if (json?.errors?.length) {
        apiErrors.push(`${url.split('/v1/esignet/')[1]}: ${JSON.stringify(json.errors)}`);
        say(`eSignet API error ${url}: ${JSON.stringify(json.errors)}`);
      }
      if (url.endsWith('/auth-code') && json?.response?.code) {
        const r = json.response;
        const sep = r.redirectUri.includes('?') ? '&' : '?';
        // give the real navigation a moment to win, then use the XHR payload
        setTimeout(() => finish(`${r.redirectUri}${sep}code=${encodeURIComponent(r.code)}` +
          (r.state ? `&state=${encodeURIComponent(r.state)}` : '')), 1500);
      }
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        rejectCode(new Error(`login timed out after ${timeoutMs}ms; eSignet errors: ${apiErrors.join(' | ') || 'none'}`));
      }
    }, timeoutMs);

    const flow = (async () => {
      say(`opening authorize URL`);
      const resp = await page.goto(authorizeUrl, { waitUntil: 'domcontentloaded' });
      if (resp && resp.status() >= 400) throw new Error(`authorize page HTTP ${resp.status()}`);

      // Login form: id input is "Otp_<login-id option>" (collab: Otp_vid), button #get_otp.
      const idInput = page.locator('input[id^="Otp_"], input[name^="Otp_"]').first();
      await Promise.race([
        idInput.waitFor({ state: 'visible' }),
        page.getByText(/invalid|error/i).first().waitFor({ state: 'visible' }).then(async () => {
          throw new Error(`eSignet showed an error: ${(await page.innerText('body')).slice(0, 500)}; ${apiErrors.join(' | ')}`);
        }),
      ]);
      say(`entering individual id ${individualId}`);
      await idInput.fill(individualId);
      await page.locator('#get_otp').click();

      // OTP boxes (6 x input[type=tel]) + #verify_otp
      const otpBoxes = page.locator('input[type="tel"]');
      await otpBoxes.first().waitFor({ state: 'visible' }).catch(async (e) => {
        throw new Error(`OTP screen did not appear (${e.message}); eSignet errors: ${apiErrors.join(' | ') || 'none'}`);
      });
      // The PIN widget auto-advances focus and re-renders, so type rather than fill box by box.
      await otpBoxes.first().click();
      await page.keyboard.type(otp, { delay: 50 });
      const verifyBtn = page.locator('#verify_otp');
      await page.waitForFunction(() => !document.querySelector('#verify_otp')?.disabled, null, { timeout: 10_000 })
        .catch(() => say('verify button still disabled after typing OTP; clicking anyway'));
      say('submitting OTP');
      await verifyBtn.click();

      // Optional consent screen (consentAction=CAPTURE). Collab clients return NOCAPTURE.
      const consent = page.getByRole('button', { name: /^(allow|proceed|accept|continue|confirm)$/i }).first();
      const deadline = Date.now() + 30_000;
      while (!settled && Date.now() < deadline) {
        if (await consent.isVisible().catch(() => false)) {
          say('consent screen: clicking allow');
          await consent.click().catch(() => {});
        }
        await page.waitForTimeout(500).catch(() => {});
      }
    })();
    flow.catch((e) => { if (!settled) { settled = true; rejectCode(e); } });

    const result = await codePromise;
    clearTimeout(timer);
    say(`got authorization code (state=${result.state})`);
    return result;
  } finally {
    await browser.close().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Holder key + proof JWT
// ---------------------------------------------------------------------------
export async function makeHolderKey() {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const full = await jose.exportJWK(publicKey);
  const publicJwk = { crv: full.crv, kty: full.kty, x: full.x, y: full.y };
  const didJwk = `did:jwk:${b64u(JSON.stringify(publicJwk))}`;
  return { privateKey, publicJwk, didJwk };
}

/**
 * OpenID4VCI 1.0 jwt proof. `binding` is 'did' (kid = did:jwk:...#0) or 'jwk' (jwk header).
 */
export async function makeProofJwt({ holder, binding, aud, nonce, iss }) {
  const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256' };
  if (binding === 'jwk') header.jwk = holder.publicJwk;
  else header.kid = `${holder.didJwk}#0`;
  const claims = { aud, iat: Math.floor(Date.now() / 1000), nonce };
  if (iss) claims.iss = iss;
  return new jose.SignJWT(claims).setProtectedHeader(header).sign(holder.privateKey);
}

// ---------------------------------------------------------------------------
// Flow steps (each exported so test suites can reuse / vary them)
// ---------------------------------------------------------------------------

/** Mimoto issuer entry + Certify issuer metadata + eSignet AS metadata for one issuer. */
export async function discover(issuerId, opts = {}) {
  const cfg = ISSUERS[issuerId];
  if (!cfg) throw new Error(`unknown issuer ${issuerId}; use one of ${Object.keys(ISSUERS).join(', ')}`);
  const mimoto = (await getJson(MIMOTO_ISSUERS_URL)).response.issuers.find((i) => i.issuer_id === issuerId);
  if (!mimoto) throw new Error(`Mimoto has no issuer ${issuerId}`);
  const meta = await getJson(`${cfg.credentialIssuer}/.well-known/openid-credential-issuer`);
  const cc = meta.credential_configurations_supported[cfg.credentialConfigurationId];
  if (!cc) throw new Error(`${cfg.credentialConfigurationId} not in ${cfg.credentialIssuer} metadata`);
  const as = await getJson(`${meta.authorization_servers[0]}/.well-known/openid-configuration`);
  return {
    issuerId,
    credentialConfigurationId: cfg.credentialConfigurationId,
    meta, cc, as, mimoto,
    clientId: mimoto.client_id,
    redirectUri: opts.redirectUri ?? process.env.MOSIP_REDIRECT_URI ?? mimoto.redirect_uri,
    tokenEndpoint: mimoto.token_endpoint,
  };
}

/** eSignet authorize URL, same parameter set Inji Web sends. */
export function buildAuthorizeUrl(d, { state, codeChallenge }) {
  return `${d.as.authorization_endpoint}?${new URLSearchParams({
    response_type: 'code',
    client_id: d.clientId,
    scope: d.cc.scope,
    redirect_uri: d.redirectUri,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    ui_locales: 'en',
  })}`;
}

/** Code -> token at Mimoto's proxy (/v1/mimoto/get-token/<issuer_id>). Returns the raw http result. */
export async function exchangeCode(d, { code, codeVerifier, includeClientId = true }) {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: d.redirectUri,
    code_verifier: codeVerifier,
  });
  if (includeClientId) form.set('client_id', d.clientId);
  return http('POST', d.tokenEndpoint, {
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: form.toString(),
  });
}

/** POST to Certify's nonce endpoint (no body, no auth). Returns c_nonce. */
export async function fetchNonce(d) {
  const r = await http('POST', d.meta.nonce_endpoint, { headers: { accept: 'application/json' } });
  if (r.status !== 200 || !r.json?.c_nonce) throw new Error(`nonce endpoint ${r.status}: ${r.text.slice(0, 300)}`);
  return r.json.c_nonce;
}

/** Holder binding the issuer metadata asks for: 'jwk' (mso_mdoc) or 'did' (ldp_vc: did:jwk/did:key). */
export const bindingFor = (cc) => ((cc.cryptographic_binding_methods_supported ?? []).includes('jwk') ? 'jwk' : 'did');

/** OpenID4VCI 1.0 credential request. Returns the raw http result. */
export async function requestCredential(d, { accessToken, holder, nonce, iss = d.clientId, binding = bindingFor(d.cc) }) {
  const proof = await makeProofJwt({ holder, binding, aud: d.meta.credential_issuer, nonce, iss });
  const body = { credential_configuration_id: d.credentialConfigurationId, proofs: { jwt: [proof] } };
  return http('POST', d.meta.credential_endpoint, {
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
}

/** Check that the issued credential is bound to our holder key. Returns a short description. */
export function checkHolderBinding(d, json, holder) {
  const cred = json?.credentials?.[0]?.credential;
  if (typeof cred === 'string') {
    // mso_mdoc: base64url CBOR {docType, issuerSigned}; MSO.deviceKeyInfo.deviceKey must be our key.
    const top = cborDecode(Buffer.from(cred, 'base64url'));
    const issuerSigned = top.issuerSigned ?? top;
    let mso = cborDecode(issuerSigned.issuerAuth[2]);
    if (mso instanceof CborTag && mso.tag === 24) mso = cborDecode(mso.value);
    const dk = mso.deviceKeyInfo.deviceKey;
    const get = (k) => (dk instanceof Map ? dk.get(k) : dk[k]);
    const ok = Buffer.from(get(-2)).toString('base64url') === holder.publicJwk.x
      && Buffer.from(get(-3)).toString('base64url') === holder.publicJwk.y;
    return `mdoc deviceKey ${ok ? 'matches' : 'DOES NOT match'} holder key`;
  }
  // Certify copies the proof's `kid` verbatim, so credentialSubject.id is the DID URL "did:jwk:...#0",
  // not the bare DID. Accept both, but say which one we got.
  const subj = cred?.credentialSubject?.id;
  if (subj === holder.didJwk) return 'credentialSubject.id matches holder did:jwk';
  if (subj === `${holder.didJwk}#0`) return 'credentialSubject.id matches holder key (as DID URL did:jwk:...#0, fragment included)';
  return `credentialSubject.id DOES NOT match holder did:jwk (${subj})`;
}

// ---------------------------------------------------------------------------
// Full flow
// ---------------------------------------------------------------------------
export async function issue(issuerId, opts = {}) {
  const d = await discover(issuerId, opts);
  log(`issuer=${d.meta.credential_issuer} config=${d.credentialConfigurationId} format=${d.cc.format} scope=${d.cc.scope}`);
  log(`AS=${d.as.authorization_endpoint} client_id=${d.clientId} redirect_uri=${d.redirectUri} token=${d.tokenEndpoint}`);

  // 1. Authorization request + 2. headless login.
  const pkce = makePkce();
  const state = b64u(crypto.randomBytes(16));
  const authorizeUrl = buildAuthorizeUrl(d, { state, codeChallenge: pkce.codeChallenge });
  const { code, state: returnedState } = await loginAndGetCode(authorizeUrl, d.redirectUri, opts);
  if (returnedState !== state) throw new Error(`state mismatch: sent ${state}, got ${returnedState}`);

  // 3. Token via Mimoto proxy.
  const tok = await exchangeCode(d, { code, codeVerifier: pkce.codeVerifier });
  log(`token proxy -> ${tok.status}; keys: ${tok.json ? Object.keys(tok.json).join(',') : tok.text.slice(0, 300)}`);
  if (tok.status !== 200 || !tok.json?.access_token) {
    throw new Error(`token exchange failed ${tok.status}: ${tok.text.slice(0, 1000)}`);
  }
  const accessToken = tok.json.access_token;
  try {
    const { sub, scope, aud, iss } = jose.decodeJwt(accessToken);
    log(`access_token claims: ${JSON.stringify({ iss, aud, sub, scope })}`);
  } catch { log('access_token is not a JWT'); }

  // 4. Nonce from Certify's nonce endpoint (the token response c_nonce is a fallback only).
  let cNonce;
  try { cNonce = await fetchNonce(d); } catch (e) { log(`nonce endpoint failed: ${e.message}`); }
  if (!cNonce && tok.json.c_nonce) { cNonce = tok.json.c_nonce; log('using c_nonce from token response'); }
  if (!cNonce) throw new Error('no c_nonce available');

  // 5. Credential request (OpenID4VCI 1.0 shape) with a fresh P-256 holder key.
  const holder = await makeHolderKey();
  let cr = await requestCredential(d, { accessToken, holder, nonce: cNonce });
  log(`credential endpoint -> ${cr.status}`);
  // Certify's invalid_nonce error carries no fresh c_nonce (1.0 behaviour): re-fetch and retry once.
  if (cr.status === 400 && cr.json?.error === 'invalid_nonce') {
    const fresh = cr.json.c_nonce ?? await fetchNonce(d);
    log(`invalid_nonce; retrying with a fresh nonce`);
    cr = await requestCredential(d, { accessToken, holder, nonce: fresh });
    log(`credential endpoint (retry) -> ${cr.status}`);
  }
  if (cr.status !== 200) throw new Error(`credential request failed ${cr.status}: ${cr.text.slice(0, 2000)}`);
  log(checkHolderBinding(d, cr.json, holder));

  let outPath;
  if (opts.save ?? process.env.NO_SAVE !== '1') {
    outPath = path.join(HERE, 'samples', `${issuerId}-${d.credentialConfigurationId}.json`);
    await fs.mkdir(path.dirname(outPath), { recursive: true });
    await fs.writeFile(outPath, cr.text); // verbatim response body
    log(`saved ${outPath}`);
  }
  return { response: cr.text, json: cr.json, holder, outPath };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const issuerId = process.argv[2];
  if (!ISSUERS[issuerId]) {
    console.error(`usage: node issue.mjs <${Object.keys(ISSUERS).join('|')}>`);
    process.exit(2);
  }
  issue(issuerId, { headless: process.env.HEADLESS !== '0' })
    .then(({ response, json }) => { console.log(json ? JSON.stringify(json, null, 2) : response); })
    .catch((e) => { console.error('[issue] FAILED:', e.message); process.exit(1); });
}
