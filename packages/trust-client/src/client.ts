/**
 * The TrustClient facade. Every operation follows the same chain:
 *   1. the trust service (authoritative, cached),
 *   2. on unavailability only: cached service answers, the verified offline snapshot, and standard
 *      mechanisms (direct OpenID4VCI discovery, local DID resolution, local X.509 validation).
 * Policy answers from the service (e.g. 403 issuer not registered) are never bypassed by fallback.
 */
import { CircuitBreaker } from './transport/circuit.js';
import { HttpTransport } from './transport/http.js';
import { ExpiringCache, MemoryCacheStore, type CacheStore } from './cache/store.js';
import { SnapshotManager, type ServiceKeyPolicy, type SnapshotData } from './snapshot/snapshot.js';
import { LocalEvaluator, type LocalTrustData, normalizeIdentifier } from './evaluation/local.js';
import { resolveDidLocally } from './did/resolver.js';
import { didError } from './did/did.js';
import { fetchIssuerMetadata } from './metadata/issuer.js';
import { parseCertificate } from './x509/certificate.js';
import { validateCertificateChain, type LocalAnchor } from './x509/validate.js';
import { extractIssuerInfo, issuerTrustQuery, type IssuerInfo } from './credential/extract.js';
import { TrustServiceError, TrustServiceUnavailableError } from './errors.js';
import type { DidResolutionResult, EntityFilter, EntityView, IssuerMetadataResult, Page, PathValidationResult,
  ServiceDiscovery, ServiceStatus, ServiceStatusEvent, TrustDecision, TrustFramework, TrustQuery, TrustedAuthorityQuery } from './types.js';

export interface Logger {
  debug?(msg: string, ...args: unknown[]): void;
  info?(msg: string, ...args: unknown[]): void;
  warn?(msg: string, ...args: unknown[]): void;
}

export interface LocalAnchorConfig {
  domain: string;
  /** PEM or base64 DER */
  certificate: string;
  frameworkId?: string;
  entityId?: string;
  constraints?: Record<string, unknown>;
}

export interface TrustClientConfig {
  /** Trust service base URL; omit to run purely on standard mechanisms and local configuration. */
  baseUrl?: string;
  apiKey?: string;
  /** Expected audience of signed snapshots (the client id the API key belongs to). */
  clientId?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  retries?: number;
  backoffMs?: number;
  circuitBreaker?: { failureThreshold?: number; resetAfterMs?: number };
  cache?: CacheStore;
  serviceKeys?: ServiceKeyPolicy;
  fallback?: {
    /** Use standard mechanisms when the service is unavailable (default true). */
    enabled?: boolean;
    /** Use the verified offline snapshot when unavailable (default true). */
    useSnapshot?: boolean;
    /** How long past its exp a snapshot may still be used offline (default 7 days). */
    snapshotGraceMs?: number;
    /** Trust anchors bundled with the app (pinned out of band). */
    localAnchors?: LocalAnchorConfig[];
    /** Static entities bundled with the app. */
    localEntities?: EntityView[];
    /** Hosts allowed over plain http for did:web (development only). */
    didWebHttpHosts?: string[];
  };
  /** Refresh the snapshot in the background after successful calls when older than this (default 1 h). */
  snapshotRefreshMs?: number;
  logger?: Logger;
}

export interface CredentialTrustResult {
  issuer: IssuerInfo;
  decision: TrustDecision;
}

export class TrustClient {
  private readonly transport: HttpTransport | null;
  private readonly cache: ExpiringCache;
  private readonly store: CacheStore;
  readonly snapshots: SnapshotManager;
  private readonly local: LocalEvaluator;
  private readonly fetchFn: typeof fetch;
  private readonly fallbackEnabled: boolean;
  private readonly localAnchors: LocalAnchor[];
  private _status: ServiceStatus = 'unknown';
  private readonly listeners = new Set<(e: ServiceStatusEvent) => void>();
  private lastSnapshotSync = 0;

  constructor(private readonly config: TrustClientConfig = {}) {
    const f = config.fetch ?? (globalThis.fetch?.bind(globalThis) as typeof fetch | undefined);
    if (!f) throw new Error('No fetch implementation available');
    this.fetchFn = f;
    this.store = config.cache ?? new MemoryCacheStore();
    this.cache = new ExpiringCache(this.store);
    this.fallbackEnabled = config.fallback?.enabled ?? true;
    this.transport = config.baseUrl ? new HttpTransport({
      baseUrl: config.baseUrl, apiKey: config.apiKey, fetch: f, timeoutMs: config.timeoutMs ?? 4000,
      retries: config.retries ?? 1, backoffMs: config.backoffMs ?? 200,
      breaker: new CircuitBreaker(config.circuitBreaker?.failureThreshold ?? 3, config.circuitBreaker?.resetAfterMs ?? 30_000),
      onAvailability: (ok, reason) => this.setStatus(ok ? 'online' : 'offline', reason),
    }) : null;
    this.snapshots = new SnapshotManager(this.transport, this.store, config.serviceKeys ?? {}, config.clientId,
      config.fallback?.snapshotGraceMs ?? 7 * 24 * 3600_000);
    this.local = new LocalEvaluator((did) => this.resolveDidLocal(did));
    this.localAnchors = (config.fallback?.localAnchors ?? []).map((a) => ({
      certificate: parseCertificate(a.certificate), domain: a.domain, frameworkId: a.frameworkId, entityId: a.entityId, constraints: a.constraints,
    }));
  }

  /** online / offline as observed from the last call; 'unknown' before the first call. */
  get status(): ServiceStatus {
    return this.transport ? this._status : 'offline';
  }

  onStatusChange(listener: (e: ServiceStatusEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private setStatus(s: ServiceStatus, reason?: string): void {
    if (s === this._status) return;
    this._status = s;
    this.config.logger?.info?.(`trust service ${s}${reason ? `: ${reason}` : ''}`);
    for (const l of this.listeners) l({ status: s, reason });
  }

  /** Runs {@code remote}; on unavailability (only) runs {@code fallback}. */
  private async withFallback<T>(remote: (t: HttpTransport) => Promise<T>, fallback: () => Promise<T>): Promise<T> {
    if (this.transport) {
      try {
        const r = await remote(this.transport);
        this.maybeRefreshSnapshot();
        return r;
      } catch (e) {
        if (!(e instanceof TrustServiceUnavailableError) || !this.fallbackEnabled) throw e;
        this.config.logger?.warn?.(`falling back: ${e.message}`);
      }
    } else if (!this.fallbackEnabled) {
      throw new TrustServiceUnavailableError('No trust service configured and fallback disabled');
    }
    return fallback();
  }

  private maybeRefreshSnapshot(): void {
    const every = this.config.snapshotRefreshMs ?? 3600_000;
    if (!this.transport || (this.config.fallback?.useSnapshot ?? true) === false || Date.now() - this.lastSnapshotSync < every) return;
    this.lastSnapshotSync = Date.now();
    this.snapshots.sync().catch((e) => this.config.logger?.warn?.(`snapshot sync failed: ${(e as Error).message}`));
  }

  /** Forces a snapshot download and verification. */
  async syncSnapshot(): Promise<SnapshotData> {
    this.lastSnapshotSync = Date.now();
    return this.snapshots.sync();
  }

  private async localData(): Promise<LocalTrustData> {
    const snap = (this.config.fallback?.useSnapshot ?? true) ? await this.snapshots.current().catch(() => null) : null;
    return {
      entities: [...(snap?.entities ?? []), ...(this.config.fallback?.localEntities ?? [])],
      anchors: [...(snap?.anchors ?? []), ...this.localAnchors],
      frameworks: snap?.frameworks ?? [],
      source: snap ? 'snapshot' : 'fallback',
      stale: snap?.stale,
    };
  }

  // ---- discovery & registry -------------------------------------------------------------------

  async discovery(): Promise<ServiceDiscovery> {
    if (!this.transport) throw new TrustServiceUnavailableError('No trust service configured');
    return (await this.transport.request<ServiceDiscovery>('GET', '/.well-known/trust-service')).body;
  }

  async frameworks(): Promise<TrustFramework[]> {
    return this.withFallback(
      async (t) => (await t.request<(TrustFramework & { entityCount: number })[]>('GET', '/api/v1/frameworks')).body,
      async () => (await this.localData()).frameworks);
  }

  issuers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('/api/v1/issuers', 'CREDENTIAL_ISSUER', filter);
  }

  verifiers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('/api/v1/verifiers', 'VERIFIER', filter);
  }

  private entities(path: string, role: string, filter: EntityFilter): Promise<Page<EntityView> & { source: string }> {
    const qs = new URLSearchParams(Object.entries(filter).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])).toString();
    return this.withFallback(
      async (t) => ({ ...(await t.request<Page<EntityView>>('GET', `${path}${qs ? `?${qs}` : ''}`)).body, source: 'trust-service' }),
      async () => {
        const d = await this.localData();
        const fmt = filter.format === 'vc+sd-jwt' ? 'dc+sd-jwt' : filter.format;
        const items = d.entities.filter((e) => e.roles.includes(role)
          && (!filter.framework || e.frameworkId === filter.framework)
          && (!fmt && !filter.type || e.authorizations.some((a) => (!fmt || a.format === fmt) && (!filter.type || a.type === filter.type)))
          && (!filter.q || JSON.stringify([e.id, e.display, e.identifiers]).toLowerCase().includes(filter.q.toLowerCase())));
        return { items, total: items.length, page: 0, size: items.length, registryVersion: -1, source: d.source };
      });
  }

  async lookup(identifier: string): Promise<EntityView[]> {
    return this.withFallback(
      async (t) => (await t.request<EntityView[]>('GET', `/api/v1/entities/lookup?identifier=${encodeURIComponent(identifier)}`)).body,
      async () => {
        const d = await this.localData();
        return d.entities.filter((e) => e.identifiers.some((i) => normalizeIdentifier(i.type, i.value) === normalizeIdentifier(i.type, identifier)));
      });
  }

  // ---- trust decisions -----------------------------------------------------------------------

  async evaluate(query: TrustQuery): Promise<TrustDecision> {
    return this.withFallback(
      async (t) => ({ ...(await t.request<TrustDecision>('POST', '/api/v1/evaluate', { body: query, idempotent: true })).body, source: 'trust-service' as const }),
      async () => this.local.evaluate(query, await this.localData()));
  }

  async evaluateIssuer(args: { credentialIssuer?: string; did?: string; kid?: string; x5c?: string[]; format?: string; type?: string }): Promise<TrustDecision> {
    return this.evaluate({ role: 'issuer', subject: { identifier: args.did ?? args.credentialIssuer, x5c: args.x5c, kid: args.kid },
      context: { protocol: 'oid4vci', credentialFormat: args.format, credentialType: args.type } });
  }

  /** OpenID4VP verifier trust: client_id (with prefix), request object x5c chain, response_uri. */
  async evaluateVerifier(args: { clientId: string; x5c?: string[]; kid?: string; responseUri?: string }): Promise<TrustDecision> {
    return this.evaluate({ role: 'verifier', subject: { identifier: args.clientId, x5c: args.x5c, kid: args.kid },
      context: { protocol: 'oid4vp', responseUri: args.responseUri } });
  }

  /** Extracts issuer material from a credential (any supported format) and evaluates the issuer. */
  async evaluateCredential(credential: unknown, format: string, opts: { credentialIssuer?: string; trustedAuthorities?: TrustedAuthorityQuery[] } = {}): Promise<CredentialTrustResult> {
    const issuer = extractIssuerInfo(credential, format);
    const q = issuerTrustQuery(issuer, opts.credentialIssuer);
    if (opts.trustedAuthorities) q.context = { ...q.context, trustedAuthorities: opts.trustedAuthorities };
    return { issuer, decision: await this.evaluate(q) };
  }

  // ---- metadata proxy --------------------------------------------------------------------------

  async getIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    const key = `md:${credentialIssuer}`;
    return this.withFallback<IssuerMetadataResult>(async (t) => {
      const r = await t.request<IssuerMetadataResult>('GET', `/api/v1/issuers/metadata?credential_issuer=${encodeURIComponent(credentialIssuer)}`);
      const result = { ...r.body, source: (r.body.stale ? 'cache' : 'trust-service') as IssuerMetadataResult['source'] };
      await this.cache.set(key, result, Math.max(60_000, new Date(result.expiresAt).getTime() - Date.now()));
      return result;
    }, async () => {
      const cached = await this.cache.get<IssuerMetadataResult>(key);
      const trust = await this.local.evaluate({ role: 'issuer', subject: { identifier: credentialIssuer }, context: { protocol: 'oid4vci' } }, await this.localData());
      if (cached?.fresh) return { ...cached.value, trust, source: 'cache' };
      try {
        const md = await fetchIssuerMetadata(credentialIssuer, this.fetchFn, this.config.timeoutMs ?? 8000);
        const now = new Date();
        return { ...md, policyApplied: false, fetchedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 300_000).toISOString(),
          stale: false, entityId: trust.entity?.id ?? null, trust, source: 'fallback' };
      } catch (e) {
        if (cached) return { ...cached.value, trust, stale: true, source: 'cache' };
        throw e;
      }
    });
  }

  // ---- X.509 -------------------------------------------------------------------------------------

  async validateChain(chain: string[], domain: string, opts: { docType?: string; expectedDnsName?: string; time?: string } = {}): Promise<PathValidationResult & { entity?: EntityView; source: string }> {
    return this.withFallback(async (t) => {
      const r = await t.request<{ result: PathValidationResult; entity?: EntityView }>('POST', '/api/v1/x509/validate',
        { body: { chain, domain, ...opts }, idempotent: true });
      return { ...r.body.result, entity: r.body.entity, source: 'trust-service' };
    }, async () => {
      const d = await this.localData();
      const { anchorRef, ...r } = validateCertificateChain(chain, d.anchors.filter((a) => a.domain === domain),
        { domain, docType: opts.docType, expectedDnsName: opts.expectedDnsName, time: opts.time ? new Date(opts.time) : undefined });
      const entity = anchorRef?.entityId ? d.entities.find((e) => e.id === anchorRef.entityId) : undefined;
      return { ...r, entity, source: d.source };
    });
  }

  // ---- DID resolution ----------------------------------------------------------------------------

  async resolveDid(did: string): Promise<DidResolutionResult> {
    const key = `did:${did.split('#')[0]}`;
    return this.withFallback(async (t) => {
      let body: DidResolutionResult;
      try {
        body = (await t.request<DidResolutionResult>('GET', `/api/v1/did/${did.split('#')[0]}`)).body;
      } catch (e) {
        // Resolution errors (404/400) are answers, not outages.
        if (e instanceof TrustServiceError && e.problem && 'didResolutionMetadata' in e.problem) body = e.problem as unknown as DidResolutionResult;
        else throw e;
      }
      if (body.didDocument) await this.cache.set(key, body, 15 * 60_000);
      return { ...body, didResolutionMetadata: { ...body.didResolutionMetadata, source: 'trust-service' } };
    }, async () => {
      const cached = await this.cache.get<DidResolutionResult>(key);
      if (cached?.fresh) return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache' } };
      const r = await this.resolveDidLocal(did);
      if (didError(r) && cached) return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache', stale: true } };
      return r;
    });
  }

  private async resolveDidLocal(did: string): Promise<DidResolutionResult> {
    const r = await resolveDidLocally(did, { fetch: this.fetchFn, httpHosts: this.config.fallback?.didWebHttpHosts, timeoutMs: this.config.timeoutMs ?? 8000 });
    return { ...r, didResolutionMetadata: { ...r.didResolutionMetadata, source: 'fallback' } };
  }
}

export function createTrustClient(config: TrustClientConfig = {}): TrustClient {
  return new TrustClient(config);
}
