/** Standards-based OpenID4VCI 1.0 metadata discovery (§12.2) used as fallback when the trust service is down. */
import { fetchWithTimeout } from '../did/resolver.js';

export function wellKnownInserted(identifier: string, suffix: string): string {
  const u = new URL(identifier);
  const path = u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '');
  return `${u.protocol}//${u.host}/.well-known/${suffix}${path}`;
}

export function wellKnownAppended(identifier: string, suffix: string): string {
  return `${identifier.replace(/\/$/, '')}/.well-known/${suffix}`;
}

function normalize(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/$/, '')}${u.search}`;
  } catch {
    return url;
  }
}

export interface FetchedIssuerMetadata {
  credentialIssuer: string;
  credentialIssuerMetadata: Record<string, unknown>;
  authorizationServers: Record<string, Record<string, unknown>>;
  warnings: string[];
}

export async function fetchIssuerMetadata(credentialIssuer: string, f: typeof fetch, timeoutMs = 8000): Promise<FetchedIssuerMetadata> {
  const warnings: string[] = [];
  const get = async (url: string) => {
    const r = await fetchWithTimeout(f, url, { headers: { Accept: 'application/json' } }, timeoutMs);
    return r.ok ? ((await r.json()) as Record<string, unknown>) : null;
  };
  let md = await get(wellKnownInserted(credentialIssuer, 'openid-credential-issuer'));
  if (!md) {
    const legacy = wellKnownAppended(credentialIssuer, 'openid-credential-issuer');
    md = await get(legacy);
    if (md) warnings.push(`Metadata served only at the legacy appended location ${legacy}`);
  }
  if (!md) throw new Error(`No OpenID4VCI metadata for ${credentialIssuer}`);
  const declared = md.credential_issuer;
  if (typeof declared !== 'string') throw new Error('credential_issuer missing in metadata');
  if (declared !== credentialIssuer) {
    if (normalize(declared) !== normalize(credentialIssuer)) throw new Error(`credential_issuer ${declared} does not match ${credentialIssuer}`);
    warnings.push(`credential_issuer '${declared}' differs from '${credentialIssuer}' only by normalization`);
  }
  if (typeof md.credential_endpoint !== 'string') throw new Error('credential_endpoint missing in metadata');
  const servers = Array.isArray(md.authorization_servers) && md.authorization_servers.length > 0
    ? (md.authorization_servers as string[]) : [declared];
  const authorizationServers: Record<string, Record<string, unknown>> = {};
  for (const as of servers) {
    try {
      authorizationServers[as] = await fetchAuthorizationServerMetadata(as, f, timeoutMs);
    } catch (e) {
      warnings.push(`Authorization server ${as}: ${(e as Error).message}`);
    }
  }
  return { credentialIssuer: declared, credentialIssuerMetadata: md, authorizationServers, warnings };
}

export async function fetchAuthorizationServerMetadata(issuer: string, f: typeof fetch, timeoutMs = 8000): Promise<Record<string, unknown>> {
  for (const url of [wellKnownInserted(issuer, 'oauth-authorization-server'), wellKnownAppended(issuer, 'openid-configuration')]) {
    const r = await fetchWithTimeout(f, url, { headers: { Accept: 'application/json' } }, timeoutMs).catch(() => null);
    if (!r?.ok) continue;
    const md = (await r.json()) as Record<string, unknown>;
    if (typeof md.issuer !== 'string' || normalize(md.issuer) !== normalize(issuer)) {
      throw new Error(`AS metadata issuer ${String(md.issuer)} does not match ${issuer}`);
    }
    return md;
  }
  throw new Error(`No authorization server metadata for ${issuer}`);
}
