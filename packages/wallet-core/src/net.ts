/**
 * Where the wallet may connect. Every URL a counterparty names (issuer and verifier endpoints, offers and request
 * objects by reference) must be https; plain http is accepted only for hosts listed for local development, such as
 * an issuer on localhost. The rule is the trust client's, so the wallet and the library read a URL the same way.
 */
import { InsecureUrlError, redirectAllowed, requireSecureUrl } from '@vctrust/trust-client/primitives';

export { InsecureUrlError };

/** Returns {@code url} when it is https, or http to one of {@code insecureHosts}; throws otherwise. */
export const requireHttps: (url: unknown, what: string, insecureHosts?: readonly string[]) => string = requireSecureUrl;

/**
 * The fetch every wallet request goes through. The URL must pass {@link requireHttps}. A request with a body (a
 * token request, a credential request, a presentation) is never sent on to another location: a redirect is an
 * error. A GET may be redirected only while it stays as protected as it started (https stays https).
 */
export function guardedFetch(f: typeof fetch, insecureHosts: readonly string[] = []): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    requireSecureUrl(url, 'A request', insecureHosts);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const safe = method === 'GET' || method === 'HEAD';
    const res = await f(input, safe ? init : { ...init, redirect: 'error' });
    if (!redirectAllowed(url, res.url || undefined)) throw new InsecureUrlError('The location a request was redirected to', res.url);
    return res;
  }) as typeof fetch;
}
