/** Shared test material: the test PKI (conformance/pki), signing with its keys, and trust clients that never reach a network. */
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createTrustClient, MemoryCacheStore, type EntityView, type PinnedAnchor, type TrustClient } from '@vctrust/trust-client';
import { bytes } from '@vctrust/trust-client/primitives';

export const PKI = new URL('../../../conformance/pki/', import.meta.url);
export const pem = (name: string) => readFileSync(new URL(`${name}.pem`, PKI), 'utf8');
export const b64 = (pemText: string) => pemText.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
export const der = (name: string) => new Uint8Array(Buffer.from(b64(pem(name)), 'base64'));
export const enc = (o: unknown) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(o)));

/** ECDSA P-256 / SHA-256 signature (r||s) with a key of the test PKI. */
export const sign = (keyName: string, data: Uint8Array | string) => new Uint8Array(createSign('SHA256').update(data)
  .sign({ key: createPrivateKey(readFileSync(new URL(`${keyName}.key`, PKI))), dsaEncoding: 'ieee-p1363' }));

/** A compact ES256 JWS signed with a key of the test PKI. */
export function es256(header: object, payload: object, keyName: string): string {
  const input = `${enc(header)}.${enc(payload)}`;
  return `${input}.${bytes.base64UrlEncode(sign(keyName, input))}`;
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

export type Routes = Record<string, (url: string, init?: RequestInit) => Response | Promise<Response>>;

/** A fetch that serves the given URLs (exact, or the longest matching prefix) and fails like a dead network for everything else. */
export function fakeFetch(routes: Routes = {}): typeof fetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    calls.push(`${init?.method ?? 'GET'} ${url}`);
    const key = Object.keys(routes).filter((k) => url === k || url.startsWith(k)).sort((a, b) => b.length - a.length)[0];
    if (!key) throw new TypeError(`fetch failed: no route for ${url}`);
    return routes[key]!(url, init);
  }) as typeof fetch & { calls: string[] };
  f.calls = calls;
  return f;
}

/** A trust client without a service: the given anchors and entities pinned, the network served by {@code routes}. */
export function pinnedTrust(anchors: PinnedAnchor[], entities: EntityView[] = [], routes: Routes = {}): TrustClient {
  return createTrustClient({ pinned: { anchors, entities }, storage: new MemoryCacheStore(), http: { fetch: fakeFetch(routes), retries: 0 } });
}

export const entity = (id: string, roles: string[], identifiers: Array<{ type: string; value: string }>, extra: Partial<EntityView> = {}): EntityView =>
  ({ id, frameworkId: 'test', roles, status: 'ACTIVE', display: [{ locale: 'en', name: id }], identifiers, authorizations: [], ...extra }) as EntityView;
