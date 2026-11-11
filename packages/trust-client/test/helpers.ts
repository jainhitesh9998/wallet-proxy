import { readFileSync } from 'node:fs';
import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
/** The shared test PKI (conformance/pki): certificates, keys and a CRL used by the client's, the wallet's and the service's tests. */
const PKI = join(here, '..', '..', '..', 'conformance', 'pki');
/** Credentials and certificates of public sandbox issuers, as they issued them (conformance/real-world). */
const REAL_WORLD = join(here, '..', '..', '..', 'conformance', 'real-world');
export const fixture = (name: string) => readFileSync(name.startsWith('pki/') ? join(PKI, name.slice(4)) : join(REAL_WORLD, name));
export const pem = (name: string) => readFileSync(join(PKI, `${name}.pem`), 'utf8');
export const b64 = (pemText: string) => pemText.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');

export function b64u(data: Uint8Array | string): string {
  return Buffer.from(typeof data === 'string' ? Buffer.from(data) : data).toString('base64url');
}

export function es256Key(): { privateKey: KeyObject; jwk: Record<string, string> } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, jwk: publicKey.export({ format: 'jwk' }) as Record<string, string> };
}

export function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>, key: KeyObject): string {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = createSign('SHA256').update(input).sign({ key, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64u(sig)}`;
}

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

/** A scripted fetch: route by URL prefix; records calls. */
export function fakeFetch(routes: Record<string, Handler>, fallback?: Handler) {
  const calls: string[] = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(`${init?.method ?? 'GET'} ${url}`);
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => url.startsWith(k));
    if (key) return routes[key]!(url, init);
    if (fallback) return fallback(url, init);
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  return { fetch: f, calls };
}

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

export const down = () => { throw new TypeError('fetch failed: ECONNREFUSED'); };
