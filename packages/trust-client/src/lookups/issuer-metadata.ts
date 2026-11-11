/**
 * OpenID4VCI issuer and authorization server metadata: from the service's proxy, signed by the service for this
 * client, or by standard discovery at the issuer. Signed metadata (OID4VCI §12.2.3) is verified against the issuer's
 * own signature on either route.
 */
import { TrustIntegrityError, TrustServiceError } from '../errors.js';
import { fetchAuthorizationServerMetadata, fetchIssuerMetadata, verifySignedMetadata, type SignedMetadataCheck } from '../metadata/issuer.js';
import { applyMetadataPolicy } from '../metadata/policy.js';
import type { HttpTransport } from '../transport/http.js';
import type { IssuerMetadataResult, PathValidationResult, TrustDecision, TrustQuery } from '../types.js';
import { requireSecureUrl } from '../util/url.js';
import { via, type LookupContext } from './context.js';

/** Metadata is cached per signed-metadata rule, so an unsigned copy never satisfies a stricter rule. */
const metadataKey = (credentialIssuer: string, check?: SignedMetadataCheck) => `md:${check?.mode ?? 'json'}:${credentialIssuer}`;

export class IssuerMetadataLookup {
  /**
   * @param signed the signed-metadata rule this client is configured with
   * @param evaluate this device's trust decision about the issuer
   * @param validateChain path validation of a metadata signer's chain in a trust domain
   */
  constructor(private readonly ctx: LookupContext, private readonly signed: 'off' | 'verify' | 'require',
              private readonly evaluate: (query: TrustQuery) => Promise<TrustDecision>,
              private readonly validateChain: (chain: string[], domain: string) => Promise<PathValidationResult>) {}

  async get(credentialIssuer: string): Promise<IssuerMetadataResult> {
    const { ctx } = this;
    requireSecureUrl(credentialIssuer, 'A credential issuer', ctx.insecureHosts);
    const check = await this.signedMetadataCheck();
    const key = metadataKey(credentialIssuer, check);
    const trust = await this.evaluate({ role: 'issuer', subject: { identifier: credentialIssuer }, context: { protocol: 'oid4vci' } });
    const cached = await ctx.cache.get<IssuerMetadataResult>(key);
    if (cached?.fresh) return { ...cached.value, trust, source: 'cache' };
    try {
      const result = await via(ctx, ctx.lookups.metadata, (t) => this.fromProxy(t, credentialIssuer, trust, check),
        (source) => this.fromIssuer(credentialIssuer, trust, check, source));
      await ctx.cache.set(key, result, Math.min(3600_000, Math.max(60_000, new Date(result.expiresAt).getTime() - ctx.now())));
      return result;
    } catch (e) {
      if (cached) return { ...cached.value, trust, stale: true, source: 'cache' };
      throw e;
    }
  }

  private async fromProxy(t: HttpTransport, credentialIssuer: string, trust: TrustDecision, check?: SignedMetadataCheck): Promise<IssuerMetadataResult> {
    const { ctx } = this;
    const r = await t.request<string>('GET', `/api/v1/proxy/issuer-metadata?issuer=${encodeURIComponent(credentialIssuer)}`, { accept: 'application/jwt' });
    const env = await ctx.snapshots.verifySigned<IssuerMetadataResult>(String(r.body).trim(), 'trust-metadata+jwt');
    if (env?.credentialIssuer !== credentialIssuer) throw new TrustIntegrityError('The proxied metadata is about another issuer');
    const result: IssuerMetadataResult = { ...env, trust, source: 'proxy' };
    if (check && (result.signedMetadata || check.mode === 'require')) {
      // Signed metadata is verified here, against the issuer's own signature, whoever relayed it.
      if (!result.signedMetadata) throw new TrustServiceError(`${credentialIssuer} serves no signed metadata, which this ecosystem requires`, 422, 'signed_metadata_required');
      const v = await verifySignedMetadata(result.signedMetadata, credentialIssuer, check);
      const policy = trust.entity?.metadataPolicy;
      result.credentialIssuerMetadata = policy?.openid_credential_issuer ? applyMetadataPolicy(v.metadata, policy.openid_credential_issuer) : v.metadata;
      result.signedMetadataVerified = true;
      // The authorization servers are the signed metadata's, fetched from them directly (the wallet talks to them next anyway).
      const servers = Array.isArray(v.metadata.authorization_servers) && v.metadata.authorization_servers.length
        ? (v.metadata.authorization_servers as string[]).slice(0, 3) : [credentialIssuer];
      result.authorizationServers = {};
      for (const as of servers) {
        const asMd = await fetchAuthorizationServerMetadata(as, ctx.fetch, ctx.timeoutMs, ctx.insecureHosts);
        result.authorizationServers[as] = policy?.oauth_authorization_server ? applyMetadataPolicy(asMd, policy.oauth_authorization_server) : asMd;
      }
    }
    return result;
  }

  /** Standard OpenID4VCI discovery from the issuer itself, with the registry's metadata policy from the snapshot applied. */
  private async fromIssuer(credentialIssuer: string, trust: TrustDecision, check: SignedMetadataCheck | undefined,
                           source: 'direct' | 'fallback'): Promise<IssuerMetadataResult> {
    const { ctx } = this;
    const { signedMetadata, signedBy, ...md } = await fetchIssuerMetadata(credentialIssuer, ctx.fetch, ctx.timeoutMs, trust.entity?.metadataPolicy, check, ctx.insecureHosts);
    if (signedBy) md.warnings.push(`Signed metadata verified (signer ${signedBy})`);
    const now = ctx.now();
    return { ...md, signedMetadata: signedMetadata ?? null, signedMetadataVerified: signedMetadata ? true : null, fetchedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(), stale: false, entityId: trust.entity?.id ?? null, trust, source };
  }

  /** The signed-metadata rule in force: the client profile's (snapshot policy) or this client's configuration. */
  private async signedMetadataCheck(): Promise<SignedMetadataCheck | undefined> {
    let mode = this.signed;
    const d = await this.ctx.snapshots.current().catch(() => null);
    if (d?.policy.requireSignedIssuerMetadata) mode = 'require';
    if (mode === 'off') return undefined;
    return { mode, now: new Date(this.ctx.now()), trustSigner: async (x5c) => {
      const r = await this.validateChain(x5c, 'credential-issuer');
      return r.valid ? { ok: true, detail: 'credential-issuer anchor' }
        : { ok: false, detail: r.issues.filter((i) => i.severity === 'ERROR').map((i) => i.message).join('; ') || 'no trusted anchor' };
    } };
  }
}
