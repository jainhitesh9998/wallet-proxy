/**
 * Which URLs may be fetched. Everything a counterparty names must be https; plain http is accepted only for hosts
 * the application listed for development (an issuer on localhost). The host is read by one strict rule, without a
 * URL parser: a URL with userinfo, a backslash or anything else between the host and the path is not read at all,
 * so `http://localhost@evil.example/` is not "localhost".
 */
export class InsecureUrlError extends Error {
  constructor(what: string, url: string) {
    super(`${what} must be an https URL: ${url.slice(0, 200)}`);
    this.name = 'InsecureUrlError';
  }
}

const HTTP_URL = /^(https?):\/\/(\[[0-9a-fA-F:.]+\]|[^/:?#@\\\s[\]]+)(?::\d{1,5})?(?:[/?#]|$)/;

/** Scheme and host of an http(s) URL of the plain shape above, or undefined for any other string. */
export function httpUrlHost(url: unknown): { scheme: 'http' | 'https'; host: string } | undefined {
  const m = typeof url === 'string' ? HTTP_URL.exec(url) : null;
  return m ? { scheme: m[1] as 'http' | 'https', host: m[2]! } : undefined;
}

/** https, or http to one of {@code insecureHosts}. */
export function isSecureUrl(url: unknown, insecureHosts: readonly string[] = []): boolean {
  const u = httpUrlHost(url);
  return !!u && (u.scheme === 'https' || insecureHosts.includes(u.host));
}

/** Returns {@code url} when {@link isSecureUrl}; throws {@link InsecureUrlError} otherwise. */
export function requireSecureUrl(url: unknown, what: string, insecureHosts: readonly string[] = []): string {
  if (!isSecureUrl(url, insecureHosts)) throw new InsecureUrlError(what, String(url));
  return url as string;
}

/**
 * A redirect must not make a request less protected than it started: one that began on https must end on https,
 * and one that began on plain http (a development host, a CRL distribution point) may only move to https or stay
 * on its host. Platforms that do not report the final URL (React Native) apply their own cleartext policy.
 */
export function redirectAllowed(requested: string, final: string | undefined): boolean {
  if (!final || final === requested) return true;
  const [from, to] = [httpUrlHost(requested), httpUrlHost(final)];
  if (!from || !to) return false;
  return to.scheme === 'https' || (from.scheme === 'http' && to.host === from.host);
}
