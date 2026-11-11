/**
 * Live tests: a trust client for the running trust service (scripts/start-trust-server.sh), registered as the demo
 * wallet. The service's signing key is pinned by the thumbprint it publishes in its discovery document; an app ships
 * that thumbprint instead of fetching it.
 */
import { createTrustClient, MemoryCacheStore, type TrustClient, type TrustClientConfig } from '@vctrust/trust-client';

export const TRUST_URL = process.env.TRUST_URL ?? 'http://localhost:8090';
export const ADMIN_KEY = process.env.TRUST_ADMIN_KEY ?? 'admin-key';

export async function liveTrust(extra: Partial<TrustClientConfig> = {}): Promise<TrustClient> {
  const d = (await (await fetch(`${TRUST_URL}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string };
  const url = new URL(TRUST_URL);
  return createTrustClient({ service: { url: TRUST_URL, clientId: 'demo-wallet', apiKey: 'demo-wallet-key', keys: { thumbprints: [d.signing_key_thumbprint] } },
    storage: new MemoryCacheStore(), ...extra, http: { ...extra.http, insecureHosts: [...(url.protocol === 'http:' ? [url.hostname] : []), ...(extra.http?.insecureHosts ?? [])] } });
}

/** Registers or removes an entity or anchor through the service's admin API (the 'managed' source). */
export async function managed(method: 'PUT' | 'DELETE', kind: 'entities' | 'anchors', id: string, body?: unknown): Promise<void> {
  const r = await fetch(`${TRUST_URL}/admin/v1/managed/${kind}/${id}`, { method, headers: { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok && !(method === 'DELETE' && r.status === 404)) throw new Error(`${method} ${kind}/${id}: HTTP ${r.status} ${(await r.text()).slice(0, 300)}`);
}
