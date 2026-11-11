/** What requests to the credential issuer and to its authorization server share: where they go and how they fail. */
import { requireHttps } from '../net.js';
import { IssuanceError } from './types.js';

/** An endpoint from the issuer's or the authorization server's metadata; https only. */
export function endpointOf(md: Record<string, unknown>, name: string, insecureHosts?: readonly string[]): string | undefined {
  return md[name] === undefined ? undefined : requireHttps(md[name], name, insecureHosts);
}

export async function requestError(what: string, r: Response): Promise<IssuanceError> {
  const text = await r.text().catch(() => '');
  let code: string | undefined;
  let detail = text.slice(0, 300);
  try {
    const j = JSON.parse(text) as { error?: string; error_description?: string };
    code = j.error;
    detail = `${j.error ?? ''} ${j.error_description ?? ''}`.trim() || detail;
  } catch { /* not JSON */ }
  return new IssuanceError(`${what} failed (HTTP ${r.status}): ${detail}`, code, r.status);
}
