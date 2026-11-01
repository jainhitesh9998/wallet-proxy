/** Standards-based OpenID4VCI 1.0 metadata discovery (§12.2): the direct path, and the fallback when the trust service is down. */
import { fetchWithTimeout } from '../did/resolver.js';
import { decodeJws, verifyJws } from '../jose/jws.js';
import { parseCertificate } from '../x509/certificate.js';
import { applyMetadataPolicy, MetadataPolicyError } from './policy.js';

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
 * that is not self-signed (HAIP §4.1), the signature, {@code sub} = the Credential Issuer, {@code iat}, expiry, and
 * trust in the signer. Returns the metadata parameters.
 */
export async function verifySignedMetadata(jwt: string, credentialIssuer: string, check: SignedMetadataCheck): Promise<{ metadata: Record<string, unknown>; signedBy: string }> {
  const jws = decodeJws<Record<string, unknown>>(jwt);
  if (jws.header.typ !== 'openidvci-issuer-metadata+jwt') throw new Error(`Signed metadata typ must be openidvci-issuer-metadata+jwt (got ${String(jws.header.typ)})`);
  if (typeof jws.header.alg !== 'string' || SYMMETRIC.test(jws.header.alg)) throw new Error(`Signed metadata alg ${String(jws.header.alg)} is not allowed`);
  const x5c = Array.isArray(jws.header.x5c) ? (jws.header.x5c as string[]) : [];
  if (x5c.length === 0) throw new Error('Signed metadata carries no x5c; its signer cannot be established');
  const leaf = parseCertificate(x5c[0]!);
  if (leaf.subject === leaf.issuer) throw new Error('Signed metadata is signed with a self-signed certificate');
  if (!leaf.publicKey || !verifyJws(jws, leaf.publicKey)) throw new Error('Signed metadata signature does not verify');
  const p = jws.payload;
  if (typeof p.sub !== 'string' || normalize(p.sub) !== normalize(credentialIssuer)) throw new Error(`Signed metadata sub ${String(p.sub)} is not ${credentialIssuer}`);
  if (typeof p.iat !== 'number') throw new Error('Signed metadata has no iat');
  const now = Math.floor((check.now ?? new Date()).getTime() / 1000);
  if (typeof p.exp === 'number' && p.exp < now) throw new Error(`Signed metadata expired at ${new Date(p.exp * 1000).toISOString()}`);
  const trusted = await check.trustSigner(x5c);
  if (!trusted.ok) throw new Error(`Signed metadata signer is not trusted: ${trusted.detail}`);
  const metadata = Object.fromEntries(Object.entries(p).filter(([k]) => !JWT_CLAIMS.includes(k)));
  return { metadata, signedBy: leaf.subject };
}

/** Registry metadata policy keyed by metadata type ({@code openid_credential_issuer}, {@code oauth_authorization_server}). */
export type RegistryMetadataPolicy = Record<string, Record<string, unknown>>;

/**
 * Standard OpenID4VCI discovery (well-known insertion, then the legacy appended location) with the same checks
 * as the service's proxy; the registry's metadata policy, when given, is applied as the service would.
 */
export async function fetchIssuerMetadata(credentialIssuer: string, f: typeof fetch, timeoutMs = 8000,
                                          policy?: RegistryMetadataPolicy, signed?: SignedMetadataCheck): Promise<FetchedIssuerMetadata> {
  const warnings: string[] = [];
  let signedMetadata: string | undefined;
  let signedBy: string | undefined;
  const get = async (url: string, acceptSigned = false) => {
    const accept = acceptSigned ? 'application/jwt, application/json;q=0.9' : 'application/json';
    const r = await fetchWithTimeout(f, url, { headers: { Accept: accept } }, timeoutMs);
    if (!r.ok) return null;
    const type = (r.headers.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    if (type !== 'application/jwt') return (await r.json()) as Record<string, unknown>;
    if (!signed) throw new Error('Issuer answered with signed metadata that was not asked for');
    const jwt = (await r.text()).trim();
    const v = await verifySignedMetadata(jwt, credentialIssuer, signed);
    signedMetadata = jwt;
    signedBy = v.signedBy;
    return v.metadata;
  };
  let md = await get(wellKnownInserted(credentialIssuer, 'openid-credential-issuer'), !!signed);
  if (signed?.mode === 'require' && md && !signedMetadata) throw new Error(`${credentialIssuer} serves no signed metadata, which this ecosystem requires`);
  if (!md && signed?.mode !== 'require') {
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
  const servers = Array.isArray(md.authorization_servers) && md.authorization_servers.length > 0
    ? (md.authorization_servers as string[]) : [declared];
  const authorizationServers: Record<string, Record<string, unknown>> = {};
  for (const as of servers) {
    try {
      let asMd = await fetchAuthorizationServerMetadata(as, f, timeoutMs);
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
