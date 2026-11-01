/**
 * Network plumbing. On web, MOSIP collab hosts do not allow CORS, so requests to them are sent through the
 * dev-only relay (dev-cors-proxy.mjs). Everything else, and every request on native, goes direct.
 */
import { Platform } from 'react-native';

/** Must match ALLOWED_HOSTS in dev-cors-proxy.mjs. */
const RELAYED_HOSTS = [
  /^injicertify-[a-z0-9-]+\.collab\.mosip\.net$/,
  /^api\.collab\.mosip\.net$/,
  /^esignet-[a-z0-9-]+\.collab\.mosip\.net$/,
  /^inji\.github\.io$/,
];

export function needsRelay(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && RELAYED_HOSTS.some((re) => re.test(u.hostname));
  } catch {
    return false;
  }
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return (input as Request).url;
}

/** fetch for the wallet and trust client: relays allowlisted hosts on web when a relay URL is configured. */
export function createAppFetch(relayBase: string | undefined): typeof fetch {
  const base: typeof fetch = globalThis.fetch.bind(globalThis);
  if (Platform.OS !== 'web' || !relayBase) return base;
  const relay = relayBase.replace(/\/$/, '');
  const f = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = urlOf(input);
    if (!needsRelay(url)) return base(input, init);
    return base(`${relay}/proxy?url=${encodeURIComponent(url)}`, typeof input === 'string' || input instanceof URL ? init : { ...init, method: (input as Request).method });
  };
  return f as typeof fetch;
}
