/**
 * Live tests: a trust client for the local trust service. The snapshot key is pinned by the thumbprint the service
 * publishes in its discovery document (production apps ship that thumbprint instead of fetching it).
 * TRUST_DECISIONS=service runs the same tests with the service deciding.
 */
import { createTrustClient, type DecisionMode, type TrustClient, type TrustClientConfig } from '@vctrust/trust-client';

export const TRUST_URL = process.env.TRUST_URL ?? 'http://localhost:8090';

export async function liveTrust(extra: Partial<TrustClientConfig> = {}): Promise<TrustClient> {
  const d = (await (await fetch(`${TRUST_URL}/.well-known/trust-service`)).json()) as { signing_key_thumbprint: string };
  return createTrustClient({ baseUrl: TRUST_URL, apiKey: 'demo-wallet-key', clientId: 'demo-wallet',
    decisions: (process.env.TRUST_DECISIONS as DecisionMode | undefined) ?? 'local',
    serviceKeys: { thumbprints: [d.signing_key_thumbprint] }, ...extra });
}
