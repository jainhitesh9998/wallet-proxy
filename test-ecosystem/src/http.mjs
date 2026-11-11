/**
 * A minimal node:http adapter for the issuer and verifier handlers: JSON and form bodies in, JSON, text or bytes out,
 * CORS for browser wallets. It listens on the loopback interfaces only (IPv4, and IPv6 when available).
 */
import { createServer } from 'node:http';

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Expose-Headers': '*' };

function parseBody(raw, type) {
  if (type.includes('json')) return JSON.parse(raw || '{}');
  if (type.includes('urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  return raw;
}

async function respond(handle, req, res) {
  if (req.method === 'OPTIONS') return res.writeHead(204, CORS).end();
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  let body;
  try { body = parseBody(Buffer.concat(chunks).toString(), req.headers['content-type'] ?? ''); }
  catch { return res.writeHead(400, CORS).end(); }
  const headers = new Headers(Object.entries(req.headers).filter(([, value]) => typeof value === 'string'));
  const result = await handle({ method: req.method, url: `http://${req.headers.host}${req.url}`, headers }, body);
  if (result.body === undefined) return res.writeHead(result.status, { ...CORS, ...result.headers }).end();
  const raw = typeof result.body === 'string' || result.body instanceof Uint8Array;
  res.writeHead(result.status, { 'Content-Type': 'application/json', ...CORS, ...result.headers }).end(raw ? result.body : JSON.stringify(result.body));
}

const listen = (server, port, host) => new Promise((resolve, reject) => server.once('error', reject).listen(port, host, () => resolve(server)));

/**
 * @param {(request: { method: string, url: string, headers: Headers }, body: unknown) =>
 *   Promise<{ status: number, body?: unknown, headers?: Record<string, string> }>} handle
 * @param {number} port 0 picks a free port
 * @returns {Promise<{ port: number, close(): Promise<void> }>}
 */
export async function serve(handle, port) {
  const listener = (req, res) => respond(handle, req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) res.writeHead(500, CORS).end();
  });
  const servers = [await listen(createServer(listener), port, '127.0.0.1')];
  const actual = servers[0].address().port;
  // `localhost` may resolve to ::1 first; a host without IPv6 loopback simply does without the second listener.
  await listen(createServer(listener), actual, '::1').then((server) => servers.push(server), () => {});
  return {
    port: actual,
    close: () => Promise.all(servers.map((server) => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }))).then(() => {}),
  };
}
