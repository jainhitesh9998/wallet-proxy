/** The suite runs against services a developer starts once (scripts/dev-up.sh); say so instead of timing out in a test. */
import { ISSUER, TRUST_URL, VERIFIER } from './tests/support';

export default async function globalSetup(): Promise<void> {
  const needed: Array<[string, string]> = [
    ['trust service', `${TRUST_URL}/.well-known/trust-service`],
    ['reference issuer', `${ISSUER}/.well-known/openid-credential-issuer`],
    ['reference verifier', `${VERIFIER}/pki/verifier-ca.pem`],
  ];
  const down: string[] = [];
  for (const [name, url] of needed) {
    const ok = await fetch(url, { signal: AbortSignal.timeout(5000) }).then((r) => r.ok, () => false);
    if (!ok) down.push(`${name} (${url})`);
  }
  if (down.length) throw new Error(`Not running: ${down.join(', ')}. Start them with scripts/dev-up.sh.`);
}
