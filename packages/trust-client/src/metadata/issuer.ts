/** Standards-based OpenID4VCI 1.0 metadata discovery (§12.2): the direct path, and the fallback when the trust service is down. */
import { fetchWithTimeout } from '../did/resolver.js';
import { requireSecureUrl } from '../util/url.js';
import { decodeJws, verifyJws } from '../jose/jws.js';
import { parseCertificate } from '../x509/certificate.js';
import { applyMetadataPolicy, MetadataPolicyError } from './policy.js';

export function wellKnownInserted(identifier: string, suffix: string): string {
  const u = new URL(identifier);
  const path = u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '');
  return `${u.protocol}//${u.host}/.well-known/${suffix}${path}`;
}

export interface FetchedIssuerMetadata {
  credentialIssuer: string;
  credentialIssuerMetadata: Record<string, unknown>;
  authorizationServers: Record<string, Record<string, unknown>>;
  warnings: string[];
  policyApplied: boolean;
  /** the signed metadata JWT, when the issuer served one that verified */
  signedMetadata?: string;
  /** subject of the trusted certificate that signed it */
  signedBy?: string;
}

/**
 * Signed issuer metadata (OID4VCI §12.2.3; HAIP 1.0 §4.1 when an ecosystem requires it). 'verify' asks for it and
 * uses it when present; 'require' refuses unsigned metadata. Either way a signed answer whose signer is not trusted
 * is rejected.
 */
export interface SignedMetadataCheck {
  mode: 'verify' | 'require';
  /** trust in the signer's x5c chain (leaf first, base64 DER), e.g. path validation to a registry anchor */
  trustSigner: (x5c: string[]) => Promise<{ ok: boolean; detail: string }>;
  now?: Date;
}

const JWT_CLAIMS = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti'];
const SYMMETRIC = /^(none|HS\d+)$/i;

/**
 * Verifies {@code openidvci-issuer-metadata+jwt}: typ, an asymmetric alg, x5c key resolution with a signer certificate
 * that is not self-signed (HAIP §4.1) and is bound to the issuer (a SAN dNSName equal to its host, or a SAN URI equal
 * to its identifier), the signature, {@code sub} and {@code credential_issuer} = the Credential Issuer, {@code iat},
 * expiry, and trust in the signer. Returns the metadata parameters.
 */
export async function verifySignedMetadata(jwt: string, credentialIssuer: string, check: SignedMetadataCheck): Promise<{ metadata: Record<string, unknown>; signedBy: string }> {
  const jws = decodeJws<Record<string, unknown>>(jwt);
  if (jws.header.typ !== 'openidvci-issuer-metadata+jwt') throw new Error(`Signed metadata typ must be openidvci-issuer-metadata+jwt (got ${String(jws.header.typ)})`);
  if (typeof jws.header.alg !== 'string' || SYMMETRIC.test(jws.header.alg)) throw new Error(`Signed metadata alg ${String(jws.header.alg)} is not allowed`);
  const x5c = Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : [];
  if (x5c.length === 0) throw new Error('Signed metadata carries no x5c; its signer cannot be established');
  const leaf = parseCertificate(x5c[0]!);
  if (leaf.subject === leaf.issuer) throw new Error('Signed metadata is signed with a self-signed certificate');
  const host = new URL(credentialIssuer).hostname.toLowerCase();
  if (!leaf.dnsNames.some((n) => n.toLowerCase() === host) && !leaf.uriNames.includes(credentialIssuer)) {
    throw new Error(`Signed metadata signer ${leaf.subject} is not bound to ${credentialIssuer} (no matching SAN)`);
  }
  if (!leaf.publicKey || !verifyJws(jws, leaf.publicKey)) throw new Error('Signed metadata signature does not verify');
  const p = jws.payload;
  if (p.sub !== credentialIssuer) throw new Error(`Signed metadata sub ${String(p.sub)} is not ${credentialIssuer}`);
  if (typeof p.iat !== 'number') throw new Error('Signed metadata has no iat');
  if (p.credential_issuer !== credentialIssuer) throw new Error(`Signed metadata credential_issuer ${String(p.credential_issuer)} is not ${credentialIssuer}`);
  const now = Math.floor((check.now ?? new Date()).getTime() / 1000);
  if (typeof p.exp === 'number' && p.exp < now) throw new Error(`Signed metadata expired at ${new Date(p.exp * 1000).toISOString()}`);
  const trusted = await check.trustSigner(x5c);
  if (!trusted.ok) throw new Error(`Signed metadata signer is not trusted: ${trusted.detail}`);
  const metadata = Object.fromEntries(Object.entries(p).filter(([k]) => !JWT_CLAIMS.includes(k)));
  return { metadata, signedBy: leaf.subject };
}

/** Registry metadata policy keyed by metadata type ({@code openid_credential_issuer}, {@code oauth_authorization_server}). */
export type RegistryMetadataPolicy = Record<string, Record<string, unknown>>;

/** Authorization servers resolved per issuer: the issuer chooses the list, so it is capped (as on the service). */
const MAX_AUTHORIZATION_SERVERS = 3;

/**
 * Standard OpenID4VCI 1.0 discovery (section 12.2.2) with the same checks as the service's proxy; the registry's
 * metadata policy, when given, is applied as the service would.
 */
export async function fetchIssuerMetadata(credentialIssuer: string, f: typeof fetch, timeoutMs = 8000,
                                          policy?: RegistryMetadataPolicy, signed?: SignedMetadataCheck, insecureHosts: readonly string[] = []): Promise<FetchedIssuerMetadata> {
  requireSecureUrl(credentialIssuer, 'A credential issuer', insecureHosts);
  const warnings: string[] = [];
  let signedMetadata: string | undefined;
  let signedBy: string | undefined;
  const get = async (url: string, acceptSigned = false) => {
    const accept = acceptSigned ? 'application/jwt, application/json;q=0.9' : 'application/json';
    const r = await fetchWithTimeout(f, url, { headers: { Accept: accept } }, timeoutMs);
    if (!r.ok) return null;
    const type = (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    if (type !== 'application/jwt') return (await r.json()) as Record<string, unknown>;
    // Signed metadata only where it was asked for: the JSON retry below must not verify (and retry) again.
    if (!signed || !acceptSigned) throw new Error('Issuer answered with signed metadata that was not asked for');
    const jwt = (await r.text()).trim();
    try {
      const v = await verifySignedMetadata(jwt, credentialIssuer, signed);
      signedMetadata = jwt;
      signedBy = v.signedBy;
      return v.metadata;
    } catch (e) {
      // Signed metadata whose signer cannot be trusted is rejected (§12.2.3); like the service, fall back to the JSON form.
      if (signed.mode === 'require') throw e;
      warnings.push(`Signed metadata rejected: ${(e as Error).message}`);
      return get(url, false);
    }
  };
  let md = await get(wellKnownInserted(credentialIssuer, 'openid-credential-issuer'), !!signed);
  if (signed?.mode === 'require' && md && !signedMetadata) throw new Error(`${credentialIssuer} serves no signed metadata, which this ecosystem requires`);
  if (!md) throw new Error(`No OpenID4VCI metadata for ${credentialIssuer}`);
  const declared = md.credential_issuer;
  // Section 12.2.4: identical to the identifier the well-known URL was built from.
  if (declared !== credentialIssuer) throw new Error(`credential_issuer ${String(declared)} is not identical to ${credentialIssuer}`);
  let policyApplied = false;
  if (policy?.openid_credential_issuer) {
    try {
      md = applyMetadataPolicy(md, policy.openid_credential_issuer);
      policyApplied = true;
    } catch (e) {
      throw new Error(`Issuer metadata violates registry policy: ${(e as Error).message}`);
    }
  }
  if (typeof md.credential_endpoint !== 'string') throw new Error('credential_endpoint missing in metadata');
  if (!md.credential_configurations_supported || typeof md.credential_configurations_supported !== 'object') {
    throw new Error('credential_configurations_supported missing in metadata');
  }
  let servers = Array.isArray(md.authorization_servers) && md.authorization_servers.length > 0
    ? (md.authorization_servers as string[]) : [declared];
  if (servers.length > MAX_AUTHORIZATION_SERVERS) {
    warnings.push(`Only the first ${MAX_AUTHORIZATION_SERVERS} of ${servers.length} authorization servers were resolved`);
    servers = servers.slice(0, MAX_AUTHORIZATION_SERVERS);
  }
  const authorizationServers: Record<string, Record<string, unknown>> = {};
  for (const as of servers) {
    try {
      let asMd = await fetchAuthorizationServerMetadata(as, f, timeoutMs, insecureHosts);
      if (policy?.oauth_authorization_server) {
        asMd = applyMetadataPolicy(asMd, policy.oauth_authorization_server);
        policyApplied = true;
      }
      authorizationServers[as] = asMd;
    } catch (e) {
      const why = e instanceof MetadataPolicyError ? ` violates registry policy: ${e.message}` : `: ${(e as Error).message}`;
      warnings.push(`Authorization server ${as}${why}`);
    }
  }
  return { credentialIssuer: declared, credentialIssuerMetadata: md, authorizationServers, warnings, policyApplied, signedMetadata, signedBy };
}

/** RFC 8414 authorization server metadata; {@code issuer} must be identical to the requested one (section 3.3). */
export async function fetchAuthorizationServerMetadata(issuer: string, f: typeof fetch, timeoutMs = 8000,
                                                       insecureHosts: readonly string[] = []): Promise<Record<string, unknown>> {
  // The issuer's metadata names its authorization servers: each is a counterparty-chosen URL like any other.
  requireSecureUrl(issuer, 'An authorization server', insecureHosts);
  const r = await fetchWithTimeout(f, wellKnownInserted(issuer, 'oauth-authorization-server'), { headers: { Accept: 'application/json' } }, timeoutMs);
  if (!r.ok) throw new Error(`No authorization server metadata for ${issuer} (HTTP ${r.status})`);
  const md = (await r.json()) as Record<string, unknown>;
  if (md.issuer !== issuer) throw new Error(`AS metadata issuer ${String(md.issuer)} is not identical to ${issuer}`);
  return md;
}
