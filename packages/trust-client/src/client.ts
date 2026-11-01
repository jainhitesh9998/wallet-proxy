/**
 * The TrustClient facade.
 *
 * decisions: 'local' (default; wallets). Trust decisions are made on this device from the signed trust snapshot
 * the service compiles for this client: the service never learns which credentials, issuers or verifiers the user
 * deals with. The client contacts the service only to refresh the snapshot, plus the lookups enabled in
 * {@link LookupPolicy} — each of which discloses a counterparty and is therefore opt-in. Certificates are checked
 * for revocation against the anchors' CRLs carried in the snapshot; other CRLs are fetched per the policy. OCSP is
 * never used: it would name the certificate being checked.
 *
 * decisions: 'service' (verifier backends, thin clients). The service evaluates; when it is unreachable the client
 * falls back to the same device-side evaluation over the snapshot and to standard mechanisms. Policy answers from
 * the service (e.g. 403 issuer not registered) are never bypassed by fallback.
 */
import { CircuitBreaker } from './transport/circuit.js';
import { HttpTransport } from './transport/http.js';
import { ExpiringCache, MemoryCacheStore, type CacheStore } from './cache/store.js';
import { SnapshotManager, snapshotRef, type ServiceKeyPolicy, type SnapshotData } from './snapshot/snapshot.js';
import { LocalEvaluator, type LocalTrustData, normalizeIdentifier, validateChainOnDevice, type CrlFetchResult } from './evaluation/local.js';
import { fetchWithTimeout, resolveDidLocally } from './did/resolver.js';
import { DID_ERRORS, didError, findVerificationMethod } from './did/did.js';
import { fetchAuthorizationServerMetadata, fetchIssuerMetadata, verifySignedMetadata, type SignedMetadataCheck } from './metadata/issuer.js';
import { applyMetadataPolicy } from './metadata/policy.js';
import { parseCertificate } from './x509/certificate.js';
import { type LocalAnchor } from './x509/validate.js';
import { parseCrl, type Crl } from './x509/crl.js';
import type { HeldCrl } from './x509/revocation.js';
import { base64Decode, base64Encode } from './util/bytes.js';
import { extractIssuerInfo, issuerTrustQuery, type IssuerInfo } from './credential/extract.js';
import { checkBitstringStatus, checkTokenStatus, type ListCredentialVerifier, type StatusContext, type StatusResult,
  type TokenStatusReference } from './status/status.js';
import { TrustServiceError, TrustServiceUnavailableError } from './errors.js';
import type { DataSource, DidResolutionResult, EntityFilter, EntityView, IssuerMetadataResult, Page, PathValidationResult,
  ServiceDiscovery, ServiceStatus, ServiceStatusEvent, SnapshotRef, TrustDecision, TrustFramework, TrustQuery, TrustedAuthorityQuery } from './types.js';

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

/** Where trust decisions are made. */
export type DecisionMode = 'local' | 'service';

/**
 * Online lookups beyond the snapshot refresh. Each one tells the trust service which party the user is dealing
 * with, so in 'local' mode they default to standard, direct mechanisms.
 */
export interface LookupPolicy {
  /** Issuer metadata from the issuer's well-known endpoints ('direct') or through the service proxy ('service'). */
  metadata?: 'direct' | 'service';
  /** DIDs not in the snapshot: resolved on this device ('direct': did:web, did:key, did:jwk) or by the service ('service'). */
  did?: 'direct' | 'service';
  /** Ask the service about parties absent from the snapshot (registries too large to ship, e.g. OpenID Federation, EBSI). */
  unknownParties?: boolean;
  /**
   * CRLs the snapshot does not carry (CAs below the trust anchors): from the CA's CRL distribution point ('direct'),
   * through the service's CRL relay ('service'), or not at all ('none'; their certificates' status stays unknown).
   */
  crl?: 'direct' | 'service' | 'none';
  /** Credential status lists: from the issuer ('direct') or through the service's relay ('service', which hides the device from the issuer). */
  statusLists?: 'direct' | 'service';
}

export interface TrustClientConfig {
  /** Trust service base URL; omit to run purely on standard mechanisms and local configuration. */
  baseUrl?: string;
  apiKey?: string;
  /** Expected audience of signed snapshots (the client id the API key belongs to). */
  clientId?: string;
  /** Where trust decisions are made (default 'local'). */
  decisions?: DecisionMode;
  /**
   * Online lookups; defaults: 'local' → metadata / did / crl 'direct', no unknown-party lookups; 'service' → metadata /
   * did / crl 'service'. Status lists default to 'direct' in both modes.
   */
  lookups?: LookupPolicy;
  /**
   * Signed issuer metadata (OID4VCI §12.2.3): 'off' (default) asks for JSON; 'verify' asks for signed metadata and
   * uses it when the issuer has it; 'require' refuses issuers without it. A client profile with
   * requireSignedIssuerMetadata (from the snapshot policy) forces 'require'. Signers must chain to a
   * 'credential-issuer' anchor and must not be self-signed.
   */
  issuerMetadata?: { signed?: 'off' | 'verify' | 'require' };
  fetch?: typeof fetch;
  timeoutMs?: number;
  retries?: number;
  backoffMs?: number;
  circuitBreaker?: { failureThreshold?: number; resetAfterMs?: number };
  cache?: CacheStore;
  /** Keys the snapshot must be signed with. Pin thumbprints in production; without any, no snapshot is accepted. */
  serviceKeys?: ServiceKeyPolicy;
  fallback?: {
    /** 'service' mode: use standard mechanisms when the service is unavailable (default true). */
    enabled?: boolean;
    /** Use the verified snapshot (default true). */
    useSnapshot?: boolean;
    /** How long past its exp a snapshot may still be used (default 7 days); decisions then carry a warning. */
    snapshotGraceMs?: number;
    /** Trust anchors bundled with the app (pinned out of band). */
    localAnchors?: LocalAnchorConfig[];
    /** Static entities bundled with the app. */
    localEntities?: EntityView[];
    /** Hosts allowed over plain http for did:web (development only). */
    didWebHttpHosts?: string[];
  };
  /** Refresh the snapshot when older than this (default 1 h); refreshes run in the background while one is usable. */
  snapshotRefreshMs?: number;
  /** Retry interval after a failed snapshot refresh (default 30 s). */
  snapshotRetryMs?: number;
  logger?: Logger;
}

export interface CredentialTrustResult {
  issuer: IssuerInfo;
  decision: TrustDecision;
}

export interface SnapshotInfo extends SnapshotRef {
  entities: number;
  anchors: number;
  didDocuments: number;
  crls: number;
  strictAuthorization: boolean;
  requireRevocationStatus: boolean;
  requireSignedIssuerMetadata: boolean;
  allowRelaxedProfiles: boolean;
}

/** A status list as fetched, before verification (it is signed by its issuer and verified by the caller). */
export interface FetchedStatusList {
  body: Uint8Array;
  contentType: string;
  source: DataSource;
}

/** What a status check needs to know about the credential; the trust client supplies fetching and chain validation. */
export type StatusCheckOptions = Omit<StatusContext, 'fetchList' | 'validateChain'>;

const ON_DEMAND_TTL_MS = 10 * 60_000;
/** How long a cached DID document may stand in for one that cannot be fetched (the service's limit too). */
const STALE_DID_MAX_MS = 24 * 3600_000;

/** Metadata is cached per signed-metadata rule, so an unsigned copy never satisfies a stricter rule. */
const metadataKey = (credentialIssuer: string, check?: SignedMetadataCheck) => `md:${check?.mode ?? 'json'}:${credentialIssuer}`;

export class TrustClient {
  readonly decisions: DecisionMode;
  readonly lookups: Required<LookupPolicy>;
  private readonly transport: HttpTransport | null;
  private readonly cache: ExpiringCache;
  private readonly store: CacheStore;
  readonly snapshots: SnapshotManager;
  private readonly local: LocalEvaluator;
  private readonly fetchFn: typeof fetch;
  private readonly fallbackEnabled: boolean;
  private readonly useSnapshot: boolean;
  private readonly localAnchors: LocalAnchor[];
  private _status: ServiceStatus = 'unknown';
  private readonly listeners = new Set<(e: ServiceStatusEvent) => void>();
  private nextSyncAt = 0;
  private readonly onDemand = new Map<string, { entities: EntityView[]; until: number }>();

  constructor(private readonly config: TrustClientConfig = {}) {
    const f = config.fetch ?? (globalThis.fetch?.bind(globalThis) as typeof fetch | undefined);
    if (!f) throw new Error('No fetch implementation available');
    this.fetchFn = f;
    this.decisions = config.decisions ?? 'local';
    const viaService = this.decisions === 'service';
    this.lookups = {
      metadata: config.lookups?.metadata ?? (viaService ? 'service' : 'direct'),
      did: config.lookups?.did ?? (viaService ? 'service' : 'direct'),
      unknownParties: config.lookups?.unknownParties ?? false,
      crl: config.lookups?.crl ?? (viaService ? 'service' : 'direct'),
      statusLists: config.lookups?.statusLists ?? 'direct',
    };
    this.store = config.cache ?? new MemoryCacheStore();
    this.cache = new ExpiringCache(this.store);
    this.fallbackEnabled = config.fallback?.enabled ?? true;
    this.useSnapshot = config.fallback?.useSnapshot ?? true;
    this.transport = config.baseUrl ? new HttpTransport({
      baseUrl: config.baseUrl, apiKey: config.apiKey, fetch: f, timeoutMs: config.timeoutMs ?? 4000,
      retries: config.retries ?? 1, backoffMs: config.backoffMs ?? 200,
      breaker: new CircuitBreaker(config.circuitBreaker?.failureThreshold ?? 3, config.circuitBreaker?.resetAfterMs ?? 30_000),
      onAvailability: (ok, reason) => this.setStatus(ok ? 'online' : 'offline', reason),
    }) : null;
    this.snapshots = new SnapshotManager(this.transport, this.store, config.serviceKeys ?? {}, config.clientId,
      config.fallback?.snapshotGraceMs ?? 7 * 24 * 3600_000);
    this.local = new LocalEvaluator((did) => this.resolveDidOnDevice(did), undefined, (urls, accept) => this.fetchCrls(urls, accept));
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

  /** 'service' mode: runs {@code remote}; on unavailability (only) runs {@code fallback}. */
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

  // ---- trust snapshot ------------------------------------------------------------------------------

  private maybeRefreshSnapshot(): void {
    if (this.transport && this.useSnapshot && Date.now() >= this.nextSyncAt) void this.refreshSnapshot();
  }

  /** Refreshes the snapshot, never throwing; schedules the next refresh (or retry). */
  private refreshSnapshot(): Promise<void> {
    this.nextSyncAt = Date.now() + (this.config.snapshotRetryMs ?? 30_000);
    return this.snapshots.sync().then(() => {
      this.nextSyncAt = Date.now() + (this.config.snapshotRefreshMs ?? 3600_000);
    }, (e: unknown) => {
      this.config.logger?.warn?.(`snapshot refresh failed: ${(e as Error).message}`);
    });
  }

  /**
   * Device-side decisions need a usable snapshot: wait for a refresh only when none is usable (missing or past its
   * expiry); otherwise refresh in the background when due.
   */
  private async ensureSnapshot(): Promise<void> {
    if (!this.transport || !this.useSnapshot || Date.now() < this.nextSyncAt) return;
    const cur = await this.snapshots.current().catch(() => null);
    if (cur && !cur.stale) void this.refreshSnapshot();
    else await this.refreshSnapshot();
  }

  /** Forces a snapshot download and verification. */
  async syncSnapshot(): Promise<SnapshotData> {
    const s = await this.snapshots.sync();
    this.nextSyncAt = Date.now() + (this.config.snapshotRefreshMs ?? 3600_000);
    return s;
  }

  /** The snapshot device-side decisions are made from (null when none is usable). */
  async snapshotInfo(): Promise<SnapshotInfo | null> {
    const s = await this.snapshots.current().catch(() => null);
    return s ? { ...snapshotRef(s), entities: s.entities.length, anchors: s.anchors.length,
      didDocuments: Object.keys(s.didDocuments).length, crls: s.crls.length, strictAuthorization: s.policy.strictAuthorization,
      requireRevocationStatus: s.policy.requireRevocationStatus,
      requireSignedIssuerMetadata: s.policy.requireSignedIssuerMetadata, allowRelaxedProfiles: s.policy.allowRelaxedProfiles } : null;
  }

  private async localData(mode: LocalTrustData['mode']): Promise<LocalTrustData> {
    const snap = this.useSnapshot ? await this.snapshots.current().catch(() => null) : null;
    const now = Date.now();
    const looked = [...this.onDemand.values()].filter((v) => v.until > now).flatMap((v) => v.entities);
    return {
      entities: [...(snap?.entities ?? []), ...looked, ...(this.config.fallback?.localEntities ?? [])],
      anchors: [...(snap?.anchors ?? []), ...this.localAnchors],
      crls: snap?.crls ?? [],
      frameworks: snap?.frameworks ?? [],
      source: snap ? 'snapshot' : 'fallback',
      mode, policy: snap?.policy, snapshot: snap ? snapshotRef(snap) : null, stale: snap?.stale,
    };
  }

  /** Runs {@code onDevice} in local mode, or the service call with device-side fallback in service mode. */
  private async decide<T>(remote: (t: HttpTransport) => Promise<T>, onDevice: (mode: LocalTrustData['mode']) => Promise<T>): Promise<T> {
    if (this.decisions === 'local') {
      await this.ensureSnapshot();
      return onDevice('local');
    }
    return this.withFallback(remote, () => onDevice('outage'));
  }

  // ---- discovery & registry -------------------------------------------------------------------

  async discovery(): Promise<ServiceDiscovery> {
    if (!this.transport) throw new TrustServiceUnavailableError('No trust service configured');
    return (await this.transport.request<ServiceDiscovery>('GET', '/.well-known/trust-service')).body;
  }

  async frameworks(): Promise<TrustFramework[]> {
    return this.decide(
      async (t) => (await t.request<(TrustFramework & { entityCount: number })[]>('GET', '/api/v1/frameworks')).body,
      async (mode) => (await this.localData(mode)).frameworks);
  }

  issuers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('/api/v1/issuers', 'CREDENTIAL_ISSUER', filter);
  }

  verifiers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('/api/v1/verifiers', 'VERIFIER', filter);
  }

  private entities(path: string, role: string, filter: EntityFilter): Promise<Page<EntityView> & { source: string }> {
    const qs = new URLSearchParams(Object.entries(filter).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])).toString();
    return this.decide(
      async (t) => ({ ...(await t.request<Page<EntityView>>('GET', `${path}${qs ? `?${qs}` : ''}`)).body, source: 'trust-service' }),
      async (mode) => {
        const d = await this.localData(mode);
        const fmt = filter.format === 'vc+sd-jwt' ? 'dc+sd-jwt' : filter.format;
        const items = d.entities.filter((e) => e.roles.includes(role)
          && (!filter.framework || e.frameworkId === filter.framework)
          && (!fmt && !filter.type || e.authorizations.some((a) => (!fmt || a.format === fmt) && (!filter.type || a.type === filter.type)))
          && (!filter.q || JSON.stringify([e.id, e.display, e.identifiers]).toLowerCase().includes(filter.q.toLowerCase())));
        return { items, total: items.length, page: 0, size: items.length, registryVersion: d.snapshot?.version ?? -1, source: d.source };
      });
  }

  async lookup(identifier: string): Promise<EntityView[]> {
    return this.decide(
      async (t) => (await t.request<EntityView[]>('GET', `/api/v1/entities/lookup?identifier=${encodeURIComponent(identifier)}`)).body,
      async (mode) => {
        const d = await this.localData(mode);
        const found = d.entities.filter((e) => e.identifiers.some((i) => normalizeIdentifier(i.type, i.value) === normalizeIdentifier(i.type, identifier)));
        return found.length > 0 || mode !== 'local' ? found : this.lookupOnDemand([identifier]);
      });
  }

  /**
   * Opt-in ({@code lookups.unknownParties}): asks the service's registries about identifiers absent from the
   * snapshot. Only identifiers are sent — never certificates or credential contents — and the answer is a signed
   * registry entry the device evaluates itself.
   */
  private async lookupOnDemand(identifiers: string[]): Promise<EntityView[]> {
    if (!this.lookups.unknownParties || !this.transport) return [];
    for (const id of identifiers) {
      const hit = this.onDemand.get(id);
      if (hit && hit.until > Date.now()) {
        if (hit.entities.length > 0) return hit.entities;
        continue;
      }
      try {
        const r = await this.transport.request<string>('GET', `/api/v1/entities/lookup?identifier=${encodeURIComponent(id)}&onDemand=true`,
          { accept: 'application/jwt' });
        const entities = await this.snapshots.verifySigned<EntityView[]>(String(r.body).trim(), 'trust-registry+jwt');
        this.onDemand.set(id, { entities, until: Date.now() + ON_DEMAND_TTL_MS });
        if (entities.length > 0) return entities;
      } catch (e) {
        this.config.logger?.warn?.(`on-demand lookup of ${id} failed: ${(e as Error).message}`);
      }
    }
    return [];
  }

  // ---- trust decisions -----------------------------------------------------------------------

  async evaluate(query: TrustQuery): Promise<TrustDecision> {
    return this.decide(
      async (t) => ({ ...(await t.request<TrustDecision>('POST', '/api/v1/evaluate', { body: query, idempotent: true })).body, source: 'trust-service' as const }),
      async (mode) => {
        const d = await this.local.evaluate(query, await this.localData(mode));
        if (mode !== 'local' || d.decision !== 'UNKNOWN') return d;
        const found = await this.lookupOnDemand(onDemandIdentifiers(query));
        if (found.length === 0) return d;
        const again = await this.local.evaluate(query, await this.localData(mode));
        again.reasons.push({ code: 'lookup.on_demand', message: 'Not in the trust snapshot; registry entry obtained by an on-demand lookup at the trust service', severity: 'INFO' });
        return again;
      });
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

  // ---- issuer metadata ---------------------------------------------------------------------------

  async getIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    if (this.lookups.metadata === 'direct') return this.metadataDirect(credentialIssuer, 'direct');
    const check = await this.signedMetadataCheck();
    return this.withFallback<IssuerMetadataResult>(async (t) => {
      const r = await t.request<IssuerMetadataResult>('GET', `/api/v1/issuers/metadata?credential_issuer=${encodeURIComponent(credentialIssuer)}`);
      const result = { ...r.body, source: (r.body.stale ? 'cache' : 'trust-service') as IssuerMetadataResult['source'] };
      if (this.decisions === 'local') result.trust = await this.evaluateIssuerUrl(credentialIssuer);
      if (check && (result.signedMetadata || check.mode === 'require')) {
        // The proxy is not trusted with signed metadata: verify the issuer's JWT here and use its claims.
        if (!result.signedMetadata) throw new TrustServiceError(`${credentialIssuer} serves no signed metadata, which this ecosystem requires`, 422, 'signed_metadata_required');
        const v = await verifySignedMetadata(result.signedMetadata, credentialIssuer, check);
        const policy = result.trust.entity?.metadataPolicy;
        result.credentialIssuerMetadata = policy?.openid_credential_issuer ? applyMetadataPolicy(v.metadata, policy.openid_credential_issuer) : v.metadata;
        result.signedMetadataVerified = true;
        // The authorization servers are the signed metadata's, fetched from them directly (the wallet talks to them next anyway).
        const servers = Array.isArray(v.metadata.authorization_servers) && v.metadata.authorization_servers.length
          ? (v.metadata.authorization_servers as string[]) : [credentialIssuer];
        result.authorizationServers = {};
        for (const as of servers) {
          const asMd = await fetchAuthorizationServerMetadata(as, this.fetchFn, this.config.timeoutMs ?? 8000);
          result.authorizationServers[as] = policy?.oauth_authorization_server ? applyMetadataPolicy(asMd, policy.oauth_authorization_server) : asMd;
        }
      }
      await this.cache.set(metadataKey(credentialIssuer, check), result, Math.max(60_000, new Date(result.expiresAt).getTime() - Date.now()));
      return result;
    }, () => this.metadataDirect(credentialIssuer, 'fallback'));
  }

  /** The signed-metadata rule in force: the client profile's (snapshot policy) or this client's configuration. */
  private async signedMetadataCheck(): Promise<SignedMetadataCheck | undefined> {
    let mode = this.config.issuerMetadata?.signed ?? 'off';
    // The client profile's policy applies in every mode, also when 'service' decisions fall back during an outage.
    if (this.snapshots) {
      const d = await this.snapshots.current().catch(() => null);
      if (d?.policy.requireSignedIssuerMetadata) mode = 'require';
    }
    if (mode === 'off') return undefined;
    return { mode, trustSigner: async (x5c) => {
      const r = await this.validateChain(x5c, 'credential-issuer');
      return r.valid ? { ok: true, detail: 'credential-issuer anchor' }
        : { ok: false, detail: r.issues.filter((i) => i.severity === 'ERROR').map((i) => i.message).join('; ') || 'no trusted anchor' };
    } };
  }

  private evaluateIssuerUrl(credentialIssuer: string, mode?: LocalTrustData['mode']): Promise<TrustDecision> {
    const q: TrustQuery = { role: 'issuer', subject: { identifier: credentialIssuer }, context: { protocol: 'oid4vci' } };
    return mode === 'outage' ? this.localData('outage').then((d) => this.local.evaluate(q, d)) : this.evaluate(q);
  }

  /**
   * Standard OpenID4VCI discovery from the issuer itself, with the registry's metadata policy from the snapshot
   * applied. {@code how}: 'direct' as the configured path, 'fallback' because the service proxy is unreachable.
   */
  private async metadataDirect(credentialIssuer: string, how: 'direct' | 'fallback'): Promise<IssuerMetadataResult> {
    const check = await this.signedMetadataCheck();
    const key = metadataKey(credentialIssuer, check);
    const cached = await this.cache.get<IssuerMetadataResult>(key);
    const trust = await this.evaluateIssuerUrl(credentialIssuer, how === 'fallback' ? 'outage' : undefined);
    if (cached?.fresh) return { ...cached.value, trust, source: 'cache' };
    try {
      const { signedMetadata, signedBy, ...md } = await fetchIssuerMetadata(credentialIssuer, this.fetchFn, this.config.timeoutMs ?? 8000,
        trust.entity?.metadataPolicy, check);
      if (signedBy) md.warnings.push(`Signed metadata verified (signer ${signedBy})`);
      const now = new Date();
      const result: IssuerMetadataResult = { ...md, signedMetadata: signedMetadata ?? null, signedMetadataVerified: signedMetadata ? true : null, fetchedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 300_000).toISOString(), stale: false, entityId: trust.entity?.id ?? null, trust, source: how };
      await this.cache.set(key, result, 300_000);
      return result;
    } catch (e) {
      if (cached) return { ...cached.value, trust, stale: true, source: 'cache' };
      throw e;
    }
  }

  // ---- X.509 -------------------------------------------------------------------------------------

  async validateChain(chain: string[], domain: string, opts: { docType?: string; expectedDnsName?: string; time?: string } = {}): Promise<PathValidationResult & { entity?: EntityView; source: string }> {
    return this.decide(async (t) => {
      const r = await t.request<{ result: PathValidationResult; entity?: EntityView }>('POST', '/api/v1/x509/validate',
        { body: { chain, domain, ...opts }, idempotent: true });
      return { ...r.body.result, entity: r.body.entity, source: 'trust-service' };
    }, async (mode) => {
      const d = await this.localData(mode);
      const { anchorRef, ...r } = await validateChainOnDevice(chain.map((c) => parseCertificate(c)), d.anchors.filter((a) => a.domain === domain),
        { domain, docType: opts.docType, expectedDnsName: opts.expectedDnsName, time: opts.time ? new Date(opts.time) : undefined }, d,
        (urls, accept) => this.fetchCrls(urls, accept));
      const entity = anchorRef?.entityId ? d.entities.find((e) => e.id === anchorRef.entityId) : undefined;
      return { ...r, entity, source: d.source };
    });
  }

  // ---- revocation ---------------------------------------------------------------------------------

  /**
   * CRLs the snapshot does not carry, per {@code lookups.crl}: from the CA's distribution point ('direct'), through
   * the service's relay ('service'; direct while it is unreachable), or not at all ('none'). Cached until their
   * nextUpdate. Callers verify each CRL against the issuing CA, so neither the cache nor the relay is trusted.
   */
  async fetchCrls(urls: string[], accept?: (url: string, crl: Crl) => boolean): Promise<CrlFetchResult> {
    const out: CrlFetchResult = { crls: [], failures: {} };
    for (const url of new Set(urls)) {
      if (this.lookups.crl === 'none') { out.failures[url] = 'CRL downloads are disabled on this device'; continue; }
      const key = `crl:${url}`;
      const cached = await this.cache.get<string>(key);
      const fromCache = (): HeldCrl | null => {
        try {
          const crl = cached ? parseCrl(base64Decode(cached.value)) : null;
          return crl && (!accept || accept(url, crl)) ? { crl, url, source: 'cache' } : null;
        } catch { return null; }
      };
      if (cached?.fresh) {
        const c = fromCache();
        if (c) { out.crls.push(c); continue; }
        await this.cache.delete(key);
      }
      try {
        const { der, source } = await this.downloadCrl(url);
        const crl = parseCrl(der);
        // Unverified CRLs are not kept: a forged one would otherwise mask the real CRL until it expired.
        if (accept && !accept(url, crl)) throw new Error('CRL is not signed by the issuing CA');
        const ttl = Math.min(24 * 3600_000, Math.max(60_000, (crl.nextUpdate?.getTime() ?? Date.now() + 3600_000) - Date.now()));
        await this.cache.set(key, base64Encode(crl.der), ttl);
        out.crls.push({ crl, url, source });
      } catch (e) {
        const stale = fromCache();
        if (stale) out.crls.push(stale);
        else out.failures[url] = (e as Error).message;
      }
    }
    return out;
  }

  private async downloadCrl(url: string): Promise<{ der: Uint8Array; source: DataSource }> {
    const direct = async (label: Extract<DataSource, 'direct' | 'fallback'>): Promise<{ der: Uint8Array; source: DataSource }> => {
      if (!/^https?:\/\//i.test(url)) throw new Error(`Unsupported CRL URL ${url}`);
      const res = await fetchWithTimeout(this.fetchFn, url, { headers: { Accept: 'application/pkix-crl' } }, this.config.timeoutMs ?? 8000);
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      return { der: new Uint8Array(await res.arrayBuffer()), source: label };
    };
    if (this.lookups.crl !== 'service' || !this.transport) return direct('direct');
    return this.withFallback(async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/revocation/crl?url=${encodeURIComponent(url)}`, { accept: 'application/pkix-crl', binary: true });
      return { der: r.body, source: 'trust-service' as const };
    }, () => direct('fallback'));
  }

  /**
   * Fetches a credential status list (IETF Token Status List, W3C Bitstring Status List credential) per
   * {@code lookups.statusLists}: from the issuer ('direct') or through the service's relay ('service'; direct while
   * it is unreachable). Status lists are signed by their issuer; the caller verifies them either way.
   */
  async fetchStatusList(uri: string, accept: string): Promise<FetchedStatusList> {
    const contentType = (h: Headers) => (h.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    const direct = async (label: Extract<DataSource, 'direct' | 'fallback'>): Promise<FetchedStatusList> => {
      const res = await fetchWithTimeout(this.fetchFn, uri, { headers: { Accept: accept } }, this.config.timeoutMs ?? 8000);
      if (!res.ok) throw new Error(`Status list ${uri}: HTTP ${res.status}`);
      return { body: new Uint8Array(await res.arrayBuffer()), contentType: contentType(res.headers), source: label };
    };
    if (this.lookups.statusLists !== 'service' || !this.transport) return direct('direct');
    return this.withFallback(async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/revocation/status-list?uri=${encodeURIComponent(uri)}`, { accept, binary: true });
      return { body: r.body, contentType: contentType(r.headers), source: 'trust-service' as const };
    }, () => direct('fallback'));
  }

  /**
   * Checks a Token Status List reference: {@code status.status_list} of an SD-JWT VC ({@code form: 'jwt'}) or of an
   * ISO mdoc MSO ({@code form: 'cwt'}). The list is fetched per {@code lookups.statusLists}, verified on this device
   * (signature, signer, subject, expiry) and reused for its {@code ttl} (5 min without one; at most 1 h, never past
   * its expiry). Only the list URI leaves the device, never the index.
   */
  async checkTokenStatus(ref: TokenStatusReference, opts: StatusCheckOptions & { form?: 'jwt' | 'cwt' } = {}): Promise<StatusResult> {
    const { form, ...ctx } = opts;
    return this.statusCheck(ref?.uri, ctx, (c) => checkTokenStatus(ref, c, form));
  }

  /**
   * Checks a W3C {@code BitstringStatusListEntry}. The list credential must verify ({@code verifyListCredential},
   * supplied by the JSON-LD verifier), come from {@code issuer} and carry the entry's purpose; cached like
   * {@link checkTokenStatus}, with the list's own {@code ttl}.
   */
  async checkBitstringStatus(entry: Record<string, unknown>, opts: StatusCheckOptions & { verifyListCredential?: ListCredentialVerifier } = {}): Promise<StatusResult> {
    const { verifyListCredential, ...ctx } = opts;
    return this.statusCheck(String(entry?.statusListCredential ?? ''), ctx, (c) => checkBitstringStatus(entry, { ...c, verifyListCredential }));
  }

  /** Runs a check over the cached list when fresh, else over a fetched one; a list that verified is kept for its ttl. */
  private async statusCheck(uri: string, opts: StatusCheckOptions, check: (ctx: StatusContext) => Promise<StatusResult>): Promise<StatusResult> {
    const base = { ...opts, validateChain: (chain: string[], domain: string) => this.validateChain(chain, domain) };
    const key = `status:${uri}`;
    const cached = uri ? await this.cache.get<{ body: string; contentType: string }>(key) : null;
    if (cached?.fresh) {
      const r = await check({ ...base, fetchList: async () => ({ body: base64Decode(cached.value.body), contentType: cached.value.contentType, source: 'cache' }) });
      if (r.value !== undefined) return r;
    }
    let fetched: FetchedStatusList | undefined;
    const r = await check({ ...base, fetchList: async (u, accept) => (fetched = await this.fetchStatusList(u, accept)) });
    if (fetched && r.value !== undefined && (r.ttlMs ?? 0) > 0) {
      await this.cache.set(key, { body: base64Encode(fetched.body), contentType: fetched.contentType }, r.ttlMs!);
    }
    return r;
  }

  // ---- DID resolution ----------------------------------------------------------------------------

  /**
   * Resolves a DID (a DID URL is accepted; its fragment selects the verification method the caller needs).
   * Local mode: the snapshot's document first — unless it lacks the requested verification method (key rotation) —
   * then the cache, then the DID's own method on this device ({@code lookups.did: 'direct'}) or the service.
   */
  async resolveDid(didUrl: string): Promise<DidResolutionResult> {
    if (this.decisions === 'local') {
      await this.ensureSnapshot();
      const fromSnapshot = await this.didFromSnapshot(didUrl);
      if (fromSnapshot) return fromSnapshot;
    }
    if (this.lookups.did === 'direct') return this.resolveDidDirect(didUrl.split('#')[0]!, 'direct');
    const did = didUrl.split('#')[0]!;
    const key = `did:${did}`;
    return this.withFallback(async (t) => {
      let body: DidResolutionResult;
      try {
        body = (await t.request<DidResolutionResult>('GET', `/api/v1/did/${did}`)).body;
      } catch (e) {
        // Resolution errors (404/400) are answers, not outages.
        if (e instanceof TrustServiceError && e.problem && 'didResolutionMetadata' in e.problem) body = e.problem as unknown as DidResolutionResult;
        else throw e;
      }
      if (body.didDocument) await this.cache.set(key, body, 15 * 60_000);
      return { ...body, didResolutionMetadata: { ...body.didResolutionMetadata, source: 'trust-service' } };
    }, () => this.resolveDidDirect(did, 'fallback'));
  }

  /** The snapshot's DID document, when the snapshot is fresh and the document has the requested verification method. */
  private async didFromSnapshot(didUrl: string): Promise<DidResolutionResult | null> {
    const snap = this.useSnapshot ? await this.snapshots.current().catch(() => null) : null;
    const doc = snap && !snap.stale ? snap.didDocuments[didUrl.split('#')[0]!] : undefined;
    if (!doc || (didUrl.includes('#') && !findVerificationMethod(doc, didUrl))) return null;
    return { didDocument: doc, didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+ld+json', source: 'snapshot', snapshotVersion: snap!.version } };
  }

  /** Device-side resolution used by the local evaluator: snapshot, then cache / direct (never the service). */
  private async resolveDidOnDevice(didUrl: string): Promise<DidResolutionResult> {
    return (await this.didFromSnapshot(didUrl)) ?? this.resolveDidDirect(didUrl.split('#')[0]!, this.decisions === 'local' ? 'direct' : 'fallback');
  }

  private async resolveDidDirect(did: string, label: Extract<DataSource, 'direct' | 'fallback'>): Promise<DidResolutionResult> {
    const key = `did:${did}`;
    const cached = await this.cache.get<DidResolutionResult>(key);
    if (cached?.fresh) return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache' } };
    const r = await resolveDidLocally(did, { fetch: this.fetchFn, httpHosts: this.config.fallback?.didWebHttpHosts, timeoutMs: this.config.timeoutMs ?? 8000 });
    if (didError(r)) {
      // A stale document only stands in for a transient failure, for a day at most: never after notFound (a 404 or 410
      // means the DID is gone) or an invalid document.
      const transient = didError(r) === DID_ERRORS.INTERNAL_ERROR;
      if (cached && transient && Date.now() - cached.storedAt < STALE_DID_MAX_MS) {
        return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache', stale: true } };
      }
      if (cached) await this.cache.delete(key);
    } else if (r.didDocument) {
      await this.cache.set(key, r, 15 * 60_000);
    }
    return { ...r, didResolutionMetadata: { ...r.didResolutionMetadata, source: label } };
  }
}

/**
 * Identifiers an on-demand registry lookup may be asked about: the party's own identifiers, never key material. With
 * key material only the key's DID can identify the party (as in the service), else the identifier.
 */
function onDemandIdentifiers(q: TrustQuery): string[] {
  const kidDid = q.subject.kid?.startsWith('did:') ? q.subject.kid.split('#')[0]! : undefined;
  if ((q.subject.x5c?.length ?? 0) > 0 || Object.keys(q.subject.jwk ?? {}).length > 0) return [];
  if (kidDid) return [kidDid];
  const ident = q.subject.identifier;
  if (!ident) return [];
  if (q.role === 'verifier') {
    const m = /^(decentralized_identifier|openid_federation):(.+)$/.exec(ident);
    return m ? [m[2]!] : [];
  }
  return ident.startsWith('did:') || /^https:\/\//.test(ident) ? [ident.split('#')[0]!] : [];
}

export function createTrustClient(config: TrustClientConfig = {}): TrustClient {
  return new TrustClient(config);
}
