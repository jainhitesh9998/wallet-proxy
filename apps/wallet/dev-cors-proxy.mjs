#!/usr/bin/env node
/**
 * DEV-ONLY CORS relay for the web build of the demo wallet.
 *
 * MOSIP collab endpoints (Inji Certify, the Mimoto token proxy, eSignet, inji.github.io DID documents / JSON-LD
 * contexts) do not send CORS headers, so a browser-hosted wallet cannot call them directly. This relay listens on
 * localhost only and forwards `GET|POST /proxy?url=<https URL>` to an explicit allowlist of those hosts, adding CORS
 * headers to the response. Native builds (Expo Go / dev builds) do not need or use it, and it must never be deployed.
 *
 *   node dev-cors-proxy.mjs            # http://127.0.0.1:8787
 *   PORT=9000 node dev-cors-proxy.mjs
 */
import http from 'node:http';

const PORT = Number(process.env.PORT ?? 8787);
const HOST = '127.0.0.1';

/** Only these upstream hosts (https only) are relayed. Keep in sync with src/wallet/net.ts. */
export const ALLOWED_HOSTS = [
  /^injicertify-[a-z0-9-]+\.collab\.mosip\.net$/,
  /^api\.collab\.mosip\.net$/,
  /^esignet-[a-z0-9-]+\.collab\.mosip\.net$/,
  /^inji\.github\.io$/,
];
/** Browser origins allowed to use the relay: local dev servers only. */
const ALLOWED_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

const HOP_BY_HOP = new Set(['host', 'origin', 'referer', 'connection', 'keep-alive', 'content-length', 'transfer-encoding',
  'accept-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'proxy-connection', 'cookie', 'sec-fetch-mode',
  'sec-fetch-site', 'sec-fetch-dest', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform']);
const STRIP_RESPONSE = new Set(['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'set-cookie', 'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-expose-headers', 'strict-transport-security']);

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGIN.test(origin)) return false;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Expose-Headers', 'DPoP-Nonce, WWW-Authenticate, Location, Content-Type, Cache-Control');
  return true;
}

function fail(res, status, message) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'relay_error', error_description: message }));
}

const server = http.createServer(async (req, res) => {
  if (!cors(req, res)) return fail(res, 403, 'origin not allowed');
  const u = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
  if (u.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end('{"status":"ok"}');
  }
  if (u.pathname !== '/proxy') return fail(res, 404, 'use /proxy?url=<https URL>');
  let target;
  try {
    target = new URL(u.searchParams.get('url') ?? '');
  } catch {
    return fail(res, 400, 'url parameter is not a URL');
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.some((re) => re.test(target.hostname))) {
    return fail(res, 403, `host ${target.hostname} is not on the relay allowlist`);
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] ?? '*');
    res.setHeader('Access-Control-Max-Age', '600');
    res.writeHead(204);
    return res.end();
  }
  if (req.method !== 'GET' && req.method !== 'POST') return fail(res, 405, 'only GET and POST are relayed');

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP_BY_HOP.has(k) && v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try {
    const upstream = await fetch(target, { method: req.method, headers, body: req.method === 'POST' ? Buffer.concat(chunks) : undefined, redirect: 'follow' });
    const body = Buffer.from(await upstream.arrayBuffer());
    for (const [k, v] of upstream.headers) if (!STRIP_RESPONSE.has(k)) res.setHeader(k, v);
    res.writeHead(upstream.status);
    res.end(body);
    console.log(`${req.method} ${target.href} -> ${upstream.status} (${body.length} bytes)`);
  } catch (e) {
    console.error(`${req.method} ${target.href} failed: ${e.message}`);
    fail(res, 502, `upstream request failed: ${e.message}`);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`DEV-ONLY CORS relay on http://${HOST}:${PORT}/proxy?url=... for ${ALLOWED_HOSTS.map((r) => r.source).join(', ')}`);
});
