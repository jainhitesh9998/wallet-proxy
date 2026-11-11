/**
 * The TrustClient: what a wallet or verifier uses the trust service through.
 *
 * Trust decisions are made on this device, from the signed trust snapshot the service compiles for this client. The
 * service never learns which credentials, issuers or verifiers the user deals with: the client contacts it to
 * refresh the snapshot and nothing else, unless a lookup below is routed through its proxy.
 *
 * Documents a counterparty would otherwise be asked for (issuer metadata, DID documents, CRLs, status lists) come
 * through the service's proxy first, and from the counterparty by the standard mechanism when the proxy cannot
 * serve them ({@code lookups: 'proxy'}, the default), or always from the counterparty ({@code 'direct'}). A proxied
 * document is either signed by its own issuer and verified here (CRLs, status lists, signed issuer metadata), or
 * signed by the service and verified with the pinned service keys (issuer metadata, DID documents).
 *
 * Without a usable snapshot the client decides from the trust pinned in the app, and says so in every decision; it
 * never answers TRUSTED without verified data.
 */
import { CircuitBreaker } from './transport/circuit.js';
import { HttpTransport } from './transport/http.js';
import { ExpiringCache, MemoryCacheStore, type CacheStore } from './cache/store.js';
import { SnapshotManager, snapshotRef, type ServiceKeyPolicy, type SnapshotData } from './snapshot/snapshot.js';
import { LocalEvaluator, type LocalTrustData, identifierKey, validateChainOnDevice, type CrlFetchResult } from './evaluation/local.js';
import { fetchWithTimeout, resolveDidLocally } from './did/resolver.js';
import { httpUrlHost, requireSecureUrl } from './util/url.js';
import { DID_ERRORS, didError, findVerificationMethod } from './did/did.js';
import { fetchAuthorizationServerMetadata, fetchIssuerMetadata, verifySignedMetadata, type SignedMetadataCheck } from './metadata/issuer.js';
import { applyMetadataPolicy } from './metadata/policy.js';
import { parseCertificate } from './x509/certificate.js';
import { type LocalAnchor } from './x509/validate.js';
import { parseCrl, type Crl } from './x509/crl.js';
import type { HeldCrl } from './x509/revocation.js';
import { base64Decode, base64Encode, base64UrlEncode } from './util/bytes.js';
import { sha256 } from './crypto/hash.js';
import { checkBitstringStatus, checkTokenStatus, type ListCredentialVerifier, type StatusContext, type StatusResult,
  type TokenStatusReference } from './status/status.js';
import { TrustIntegrityError, TrustServiceError } from './errors.js';
import type { DataSource, DidResolutionResult, EntityFilter, EntityView, IssuerMetadataResult, Page, PathValidationResult,
  ServiceDiscovery, ServiceStatus, ServiceStatusEvent, SnapshotRef, TrustDecision, TrustFramework, TrustQuery } from './types.js';

export interface Logger {
  debug?(msg: string, ...args: unknown[]): void;
  info?(msg: string, ...args: unknown[]): void;
  warn?(msg: string, ...args: unknown[]): void;
}

/** A trust anchor bundled with the app. */
export interface PinnedAnchor {
  domain: string;
  /** PEM or base64 DER */
  certificate: string;
  frameworkId?: string;
  entityId?: string;
  constraints?: Record<string, unknown>;
}

/** Through the service's proxy, with the standard mechanism when the proxy cannot serve; or always the standard mechanism. */
export type LookupVia = 'proxy' | 'direct';

/**
 * Where each kind of lookup goes. A proxied lookup tells the service which party the user is dealing with and hides
 * the device from that party; a direct one does the opposite.
 */
export interface LookupPolicy {
  /** OpenID4VCI issuer and authorization server metadata. */
  metadata?: LookupVia;
  /** DID documents the snapshot does not carry (did:key and did:jwk never leave the device). */
  did?: LookupVia;
  /** CRLs the snapshot does not carry (CAs below the trust anchors); 'none' leaves their certificates' status unknown. */
  crl?: LookupVia | 'none';
  /** Credential status lists. */
  statusLists?: LookupVia;
  /** Ask the service about parties absent from the snapshot (registries too large to ship: OpenID Federation, EBSI). */
  unknownParties?: boolean;
}

export interface TrustClientConfig {
  /** The trust service. Without it the client runs on the standard mechanisms and the trust pinned below. */
  service?: {
    url: string;
    /** The client this app is registered as: the audience of everything the service signs for it. */
    clientId: string;
    apiKey?: string;
    /** The keys the service signs with, pinned out of band (see /.well-known/trust-service). */
    keys: ServiceKeyPolicy;
  };
  /** Trust bundled with the app: decides only while no snapshot is usable. With a snapshot, the service is the authority. */
  pinned?: { anchors?: PinnedAnchor[]; entities?: EntityView[] };
  /** Default 'proxy' with a service, 'direct' without. One value for every kind, or one per kind. */
  lookups?: LookupVia | LookupPolicy;
  /**
   * Signed issuer metadata (OID4VCI §12.2.3): 'off' (default) asks for JSON; 'verify' asks for signed metadata and
   * uses it when the issuer has it; 'require' refuses issuers without it. A client profile with
   * requireSignedIssuerMetadata (from the snapshot policy) forces 'require'. Signers must chain to a
   * 'credential-issuer' anchor and must not be self-signed.
   */
  issuerMetadata?: { signed?: 'off' | 'verify' | 'require' };
  snapshot?: {
    /** Refresh when older than this (default 1 h); refreshes run in the background while a snapshot is usable. */
    refreshMs?: number;
    /** Wait this long after a failed refresh before trying again (default 30 s). */
    retryMs?: number;
    /** How long past its expiry a snapshot may still be used (default 7 days); decisions then carry a warning. */
    graceMs?: number;
  };
  http?: {
    fetch?: typeof fetch;
    timeoutMs?: number;
    retries?: number;
    backoffMs?: number;
    circuitBreaker?: { failureThreshold?: number; resetAfterMs?: number };
    /** Hosts that may be reached over plain http (loopback development only); everything else must be https. */
    insecureHosts?: string[];
  };
  /** Where the snapshot, pinned service keys and cached documents are kept (AsyncStorage, localStorage, ...). */
  storage?: CacheStore;
  clock?: () => Date;
  logger?: Logger;
}

export interface SnapshotInfo extends SnapshotRef {
  entities: number;
  anchors: number;
  didDocuments: number;
  contexts: number;
  crls: number;
  strictAuthorization: boolean;
  requireRevocationStatus: boolean;
  requireSignedIssuerMetadata: boolean;
}

/** What the client currently stands on. */
export interface TrustStatus {
  service: ServiceStatus;
  /** The snapshot decisions are made from; null when none is usable (decisions then rest on pinned trust only). */
  snapshot: SnapshotInfo | null;
  /** Why the last snapshot refresh failed; cleared by a successful one. */
  lastSyncError?: string;
  /** No usable snapshot, or one past its expiry: decisions carry a warning. */
  degraded: boolean;
}

/** A JSON-LD context with where it came from; {@code vouched}: the snapshot carries its digest. */
export interface ContextDocument {
  document: Record<string, unknown>;
  sha256: string;
  source: DataSource;
  vouched: boolean;
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
/** A forced snapshot refresh (a key the snapshot's DID document lacks) happens at most this often. */
const FORCED_REFRESH_MIN_MS = 60_000;
const CONTEXT_TTL_MS = 24 * 3600_000;
const MAX_CONTEXT_BYTES = 1024 * 1024;

/** Metadata is cached per signed-metadata rule, so an unsigned copy never satisfies a stricter rule. */
const metadataKey = (credentialIssuer: string, check?: SignedMetadataCheck) => `md:${check?.mode ?? 'json'}:${credentialIssuer}`;

export class TrustClient {
  readonly lookups: Required<LookupPolicy>;
  private readonly transport: HttpTransport | null;
  private readonly cache: ExpiringCache;
  private readonly snapshots: SnapshotManager;
  private readonly local: LocalEvaluator;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly insecureHosts: string[];
  private readonly now: () => number;
  private readonly pinnedAnchors: LocalAnchor[];
  private serviceStatus: ServiceStatus;
  private lastSyncError: string | undefined;
  /** id of the snapshot last taken into use, to tell a listener when it changes */
  private snapshotInUse: string | undefined;
  private readonly listeners = new Set<(e: ServiceStatusEvent) => void>();
  private refreshing: Promise<void> | null = null;
  private nextSyncAt = 0;
  private lastForcedSyncAt = 0;
  private readonly onDemand = new Map<string, { entities: EntityView[]; until: number }>();

  constructor(private readonly config: TrustClientConfig = {}) {
    const f = config.http?.fetch ?? (globalThis.fetch?.bind(globalThis) as typeof fetch | undefined);
    if (!f) throw new Error('No fetch implementation available');
    this.fetchFn = f;
    this.timeoutMs = config.http?.timeoutMs ?? 8000;
    this.insecureHosts = config.http?.insecureHosts ?? [];
    this.now = config.clock ? () => config.clock!().getTime() : Date.now;
    const service = config.service;
    if (service) {
      // Nothing the service signs is accepted without knowing for whom and by which key: a missing value here would
      // silently accept another client's snapshot, or none at all.
      if (!service.clientId) throw new Error('service.clientId is required: it is the audience of everything the service signs for this client');
      const keys = service.keys ?? {};
      if (!keys.thumbprints?.length && !keys.jwks?.length && !keys.trustOnFirstUse) {
        throw new Error('service.keys is required: pin the service key thumbprints (or set trustOnFirstUse for development)');
      }
      this.requireSecure(service.url, 'The trust service');
    }
    const via: LookupVia = service ? 'proxy' : 'direct';
    const l = typeof config.lookups === 'string' ? { metadata: config.lookups, did: config.lookups, crl: config.lookups, statusLists: config.lookups }
      : config.lookups ?? {};
    this.lookups = { metadata: l.metadata ?? via, did: l.did ?? via, crl: l.crl ?? via, statusLists: l.statusLists ?? via, unknownParties: l.unknownParties ?? false };
    const store = config.storage ?? new MemoryCacheStore();
    this.cache = new ExpiringCache(store, this.now);
    this.serviceStatus = service ? 'unknown' : 'unconfigured';
    this.transport = service ? new HttpTransport({
      baseUrl: service.url, apiKey: service.apiKey, fetch: f, timeoutMs: config.http?.timeoutMs ?? 4000,
      retries: config.http?.retries ?? 1, backoffMs: config.http?.backoffMs ?? 200,
      breaker: new CircuitBreaker(config.http?.circuitBreaker?.failureThreshold ?? 3, config.http?.circuitBreaker?.resetAfterMs ?? 30_000),
      onAvailability: (ok, reason) => this.setServiceStatus(ok ? 'online' : 'offline', reason),
    }) : null;
    this.snapshots = new SnapshotManager(this.transport, store, service?.keys ?? {}, service?.clientId,
      config.snapshot?.graceMs ?? 7 * 24 * 3600_000, this.now);
    this.local = new LocalEvaluator((did) => this.resolveDid(did), () => new Date(this.now()), (urls, accept) => this.fetchCrls(urls, accept));
    this.pinnedAnchors = (config.pinned?.anchors ?? []).map((a) => ({
      certificate: parseCertificate(a.certificate), domain: a.domain, frameworkId: a.frameworkId, entityId: a.entityId, constraints: a.constraints,
    }));
  }

  // ---- status ----------------------------------------------------------------------------------------

  /** What decisions currently rest on, and why the snapshot is not fresh when it is not. */
  async status(): Promise<TrustStatus> {
    const s = await this.snapshots.current().catch(() => null);
    return { service: this.serviceStatus, snapshot: s ? snapshotInfo(s) : null, lastSyncError: this.lastSyncError, degraded: !s || s.stale };
  }

  /**
   * Called when what {@link status} reports changes: the service is seen to come up or go down, another snapshot
   * comes into use, or a refresh starts or stops failing. The listener reads {@link status} for the details.
   */
  onStatusChange(listener: (e: ServiceStatusEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(reason?: string): void {
    for (const l of this.listeners) {
      try { l({ status: this.serviceStatus, reason }); } catch { /* a listener's failure is its own */ }
    }
  }

  private setServiceStatus(s: ServiceStatus, reason?: string): void {
    if (s === this.serviceStatus) return;
    this.serviceStatus = s;
    this.config.logger?.info?.(`trust service ${s}${reason ? `: ${reason}` : ''}`);
    this.notify(reason);
  }

  // ---- trust snapshot ------------------------------------------------------------------------------

  /** Downloads and verifies the snapshot now; throws when that fails (the previous snapshot stays in use). */
  async sync(): Promise<SnapshotInfo> {
    try {
      const s = await this.snapshots.sync();
      const changed = this.lastSyncError !== undefined || s.id !== this.snapshotInUse;
      this.lastSyncError = undefined;
      this.snapshotInUse = s.id;
      this.nextSyncAt = this.now() + (this.config.snapshot?.refreshMs ?? 3600_000);
      if (changed) this.notify('snapshot');
      return snapshotInfo(s);
    } catch (e) {
      const message = (e as Error).message;
      const changed = message !== this.lastSyncError;
      this.lastSyncError = message;
      this.nextSyncAt = this.now() + (this.config.snapshot?.retryMs ?? 30_000);
      if (changed) this.notify(message);
      throw e;
    }
  }

  /** One refresh at a time, never throwing; callers that need its outcome await the same promise. */
  private refresh(): Promise<void> {
    this.refreshing ??= this.sync().then(() => undefined, (e: unknown) => {
      this.config.logger?.warn?.(`snapshot refresh failed: ${(e as Error).message}`);
    }).finally(() => { this.refreshing = null; });
    return this.refreshing;
  }

  /**
   * The snapshot to decide from. A usable one is returned at once and refreshed in the background when due. With
   * none, the caller waits for the refresh in flight (every caller the same one), or for a new one when the retry
   * interval allows; after that it proceeds without.
   */
  private async snapshot(): Promise<SnapshotData | null> {
    const current = await this.snapshots.current().catch(() => null);
    if (!this.transport) return current;
    const due = this.now() >= this.nextSyncAt;
    if (current) {
      if (due || this.refreshing) void this.refresh();
      return current;
    }
    if (this.refreshing || due) await this.refresh();
    return this.snapshots.current().catch(() => null);
  }

  private async localData(): Promise<LocalTrustData> {
    const snap = await this.snapshot();
    if (!snap) {
      return { entities: this.config.pinned?.entities ?? [], anchors: this.pinnedAnchors, frameworks: [], source: 'pinned', snapshot: null };
    }
    // Parties found on demand are not snapshot entries: the evaluator meets them only where the service's would.
    const onDemand = this.lookups.unknownParties && this.transport
      ? async (ids: Array<{ type: string; value: string }>) => {
        const hit = await this.lookupOnDemand(ids);
        return hit ? { entity: hit.entities[0]!, identifier: hit.identifier as { type: string; value: string } } : undefined;
      } : undefined;
    return { onDemand, entities: snap.entities, anchors: snap.anchors, crls: snap.crls, frameworks: snap.frameworks, source: 'snapshot',
      policy: snap.policy, snapshot: snapshotRef(snap), stale: snap.stale };
  }

  // ---- the trusted list ------------------------------------------------------------------------------

  /** The service's description of itself (public; includes the key thumbprints to pin). */
  async discovery(): Promise<ServiceDiscovery> {
    if (!this.transport) throw new Error('No trust service configured');
    return (await this.transport.request<ServiceDiscovery>('GET', '/.well-known/trust-service')).body;
  }

  async frameworks(): Promise<TrustFramework[]> {
    return (await this.localData()).frameworks;
  }

  issuers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('CREDENTIAL_ISSUER', filter);
  }

  verifiers(filter: EntityFilter = {}): Promise<Page<EntityView> & { source: string }> {
    return this.entities('VERIFIER', filter);
  }

  private async entities(role: string, filter: EntityFilter): Promise<Page<EntityView> & { source: string }> {
    const d = await this.localData();
    const fmt = filter.format === 'vc+sd-jwt' ? 'dc+sd-jwt' : filter.format;
    const items = d.entities.filter((e) => e.roles.includes(role)
      && (!filter.framework || e.frameworkId === filter.framework)
      && (!fmt && !filter.type || e.authorizations.some((a) => (!fmt || a.format === fmt) && (!filter.type || a.type === filter.type)))
      && (!filter.q || JSON.stringify([e.id, e.display, e.identifiers]).toLowerCase().includes(filter.q.toLowerCase())));
    return { items, total: items.length, page: 0, size: items.length, source: d.source };
  }

  /** The listed parties that carry this identifier (compared exactly). */
  async lookup(identifier: string): Promise<EntityView[]> {
    const d = await this.localData();
    const found = d.entities.filter((e) => e.identifiers.some((i) => identifierKey(i.type, i.value) === identifierKey(i.type, identifier)));
    return found.length > 0 ? found : (await this.lookupOnDemand([{ value: identifier }]))?.entities ?? [];
  }

  /**
   * Opt-in ({@code lookups.unknownParties}): asks the service's registries about identifiers absent from the
   * snapshot. Only identifiers are sent — never certificates or credential contents — and the answer is a signed
   * registry entry the device evaluates itself.
   */
  private async lookupOnDemand(identifiers: Array<{ type?: string; value: string }>):
      Promise<{ identifier: { type?: string; value: string }; entities: EntityView[] } | undefined> {
    if (!this.lookups.unknownParties || !this.transport) return undefined;
    const seen = new Set<string>();
    for (const id of identifiers) {
      const key = `${id.type ?? ''}|${id.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hit = this.onDemand.get(key);
      if (hit && hit.until > this.now()) {
        if (hit.entities.length > 0) return { identifier: id, entities: hit.entities };
        continue;
      }
      try {
        const r = await this.transport.request<string>('GET', `/api/v1/entities/lookup?identifier=${encodeURIComponent(id.value)}`
          + `${id.type ? `&type=${id.type}` : ''}&onDemand=true`, { accept: 'application/jwt' });
        // The signed answer does not name the identifier it answers: keep only entries that carry it, so a replayed
        // answer about another party cannot stand in for this one.
        const entities = (await this.snapshots.verifySigned<EntityView[]>(String(r.body).trim(), 'trust-registry+jwt'))
          .filter((e) => namesIdentifier(e, id));
        this.onDemand.set(key, { entities, until: this.now() + ON_DEMAND_TTL_MS });
        if (entities.length > 0) return { identifier: id, entities };
      } catch (e) {
        this.config.logger?.warn?.(`on-demand lookup of ${id.value} failed: ${(e as Error).message}`);
      }
    }
    return undefined;
  }

  // ---- trust decisions -----------------------------------------------------------------------

  async evaluate(query: TrustQuery): Promise<TrustDecision> {
    return this.local.evaluate(query, await this.localData());
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

  /** Validates a certificate chain (leaf first) against the anchors of a trust domain, with revocation. */
  async validateChain(chain: string[], domain: string, opts: { docType?: string; expectedDnsName?: string; time?: string } = {}): Promise<PathValidationResult & { entity?: EntityView; source: string }> {
    const d = await this.localData();
    const { anchorRef, ...r } = await validateChainOnDevice(chain.map((c) => parseCertificate(c)), d.anchors.filter((a) => a.domain === domain),
      { domain, docType: opts.docType, expectedDnsName: opts.expectedDnsName, time: opts.time ? new Date(opts.time) : new Date(this.now()) }, d,
      (urls, accept) => this.fetchCrls(urls, accept));
    const entity = anchorRef?.entityId ? d.entities.find((e) => e.id === anchorRef.entityId) : undefined;
    return { ...r, entity, source: d.source };
  }

  // ---- the proxy, and the standard mechanisms behind it ----------------------------------------------

  /**
   * Runs a lookup through the service's proxy, and by the standard mechanism when the proxy cannot serve it: because
   * it is unreachable, because it declines (an issuer its registry does not list), or because its answer does not
   * verify. The standard mechanism never depends on the proxy, so falling back to it is always safe.
   */
  private async via<T>(route: LookupVia | 'none', proxied: (t: HttpTransport) => Promise<T>, direct: (source: 'direct' | 'fallback') => Promise<T>): Promise<T> {
    if (route !== 'proxy' || !this.transport) return direct('direct');
    try {
      return await proxied(this.transport);
    } catch (e) {
      this.config.logger?.info?.(`proxy could not serve (${(e as Error).message}); using the standard mechanism`);
      return direct('fallback');
    }
  }

  /** Everything but named development hosts must be https. */
  private requireSecure(url: string, what: string): void {
    requireSecureUrl(url, what, this.insecureHosts);
  }

  // ---- issuer metadata ---------------------------------------------------------------------------

  /**
   * OpenID4VCI issuer and authorization server metadata, with this device's trust decision about the issuer and the
   * registry's metadata policy applied.
   */
  async getIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    this.requireSecure(credentialIssuer, 'A credential issuer');
    const check = await this.signedMetadataCheck();
    const key = metadataKey(credentialIssuer, check);
    const trust = await this.evaluate({ role: 'issuer', subject: { identifier: credentialIssuer }, context: { protocol: 'oid4vci' } });
    const cached = await this.cache.get<IssuerMetadataResult>(key);
    if (cached?.fresh) return { ...cached.value, trust, source: 'cache' };
    try {
      const result = await this.via(this.lookups.metadata, (t) => this.metadataFromProxy(t, credentialIssuer, trust, check),
        (source) => this.metadataFromIssuer(credentialIssuer, trust, check, source));
      await this.cache.set(key, result, Math.min(3600_000, Math.max(60_000, new Date(result.expiresAt).getTime() - this.now())));
      return result;
    } catch (e) {
      if (cached) return { ...cached.value, trust, stale: true, source: 'cache' };
      throw e;
    }
  }

  private async metadataFromProxy(t: HttpTransport, credentialIssuer: string, trust: TrustDecision, check?: SignedMetadataCheck): Promise<IssuerMetadataResult> {
    const r = await t.request<string>('GET', `/api/v1/proxy/issuer-metadata?issuer=${encodeURIComponent(credentialIssuer)}`, { accept: 'application/jwt' });
    const env = await this.snapshots.verifySigned<IssuerMetadataResult>(String(r.body).trim(), 'trust-metadata+jwt');
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
        const asMd = await fetchAuthorizationServerMetadata(as, this.fetchFn, this.timeoutMs, this.insecureHosts);
        result.authorizationServers[as] = policy?.oauth_authorization_server ? applyMetadataPolicy(asMd, policy.oauth_authorization_server) : asMd;
      }
    }
    return result;
  }

  /** Standard OpenID4VCI discovery from the issuer itself, with the registry's metadata policy from the snapshot applied. */
  private async metadataFromIssuer(credentialIssuer: string, trust: TrustDecision, check: SignedMetadataCheck | undefined,
                                   source: 'direct' | 'fallback'): Promise<IssuerMetadataResult> {
    const { signedMetadata, signedBy, ...md } = await fetchIssuerMetadata(credentialIssuer, this.fetchFn, this.timeoutMs, trust.entity?.metadataPolicy, check, this.insecureHosts);
    if (signedBy) md.warnings.push(`Signed metadata verified (signer ${signedBy})`);
    const now = this.now();
    return { ...md, signedMetadata: signedMetadata ?? null, signedMetadataVerified: signedMetadata ? true : null, fetchedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(), stale: false, entityId: trust.entity?.id ?? null, trust, source };
  }

  /** The signed-metadata rule in force: the client profile's (snapshot policy) or this client's configuration. */
  private async signedMetadataCheck(): Promise<SignedMetadataCheck | undefined> {
    let mode = this.config.issuerMetadata?.signed ?? 'off';
    const d = await this.snapshots.current().catch(() => null);
    if (d?.policy.requireSignedIssuerMetadata) mode = 'require';
    if (mode === 'off') return undefined;
    return { mode, now: new Date(this.now()), trustSigner: async (x5c) => {
      const r = await this.validateChain(x5c, 'credential-issuer');
      return r.valid ? { ok: true, detail: 'credential-issuer anchor' }
        : { ok: false, detail: r.issues.filter((i) => i.severity === 'ERROR').map((i) => i.message).join('; ') || 'no trusted anchor' };
    } };
  }

  // ---- revocation ---------------------------------------------------------------------------------

  /**
   * CRLs the snapshot does not carry, per {@code lookups.crl}. Cached until their nextUpdate. Callers verify each CRL
   * against the issuing CA, so neither the cache nor the proxy is trusted for them.
   */
  private async fetchCrls(urls: string[], accept?: (url: string, crl: Crl) => boolean): Promise<CrlFetchResult> {
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
        const ttl = Math.min(24 * 3600_000, Math.max(60_000, (crl.nextUpdate?.getTime() ?? this.now() + 3600_000) - this.now()));
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

  private downloadCrl(url: string): Promise<{ der: Uint8Array; source: DataSource }> {
    return this.via<{ der: Uint8Array; source: DataSource }>(this.lookups.crl, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/crl?url=${encodeURIComponent(url)}`, { accept: 'application/pkix-crl', binary: true });
      return { der: r.body, source: 'proxy' as const };
    }, async (source) => {
      // CRL distribution points are conventionally plain http: a CRL is signed, and verified against its CA here.
      if (!httpUrlHost(url)) throw new Error(`Unsupported CRL URL ${url}`);
      const res = await fetchWithTimeout(this.fetchFn, url, { headers: { Accept: 'application/pkix-crl' } }, this.timeoutMs);
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      return { der: new Uint8Array(await res.arrayBuffer()), source };
    });
  }

  /** A credential status list per {@code lookups.statusLists}. Status lists are signed by their issuer; the caller verifies them. */
  private fetchStatusList(uri: string, accept: string): Promise<FetchedStatusList> {
    const contentType = (h: Headers) => (h.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    return this.via<FetchedStatusList>(this.lookups.statusLists, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/status-list?uri=${encodeURIComponent(uri)}`, { accept, binary: true });
      return { body: r.body, contentType: contentType(r.headers), source: 'proxy' as const };
    }, async (source) => {
      this.requireSecure(uri, 'A status list');
      const res = await fetchWithTimeout(this.fetchFn, uri, { headers: { Accept: accept } }, this.timeoutMs);
      if (!res.ok) throw new Error(`Status list ${uri}: HTTP ${res.status}`);
      return { body: new Uint8Array(await res.arrayBuffer()), contentType: contentType(res.headers), source };
    });
  }

  /**
   * Checks a Token Status List reference: {@code status.status_list} of an SD-JWT VC ({@code form: 'jwt'}) or of an
   * ISO mdoc MSO ({@code form: 'cwt'}). The list is fetched per {@code lookups.statusLists}, verified on this device
   * (signature, signer, subject, expiry) and reused for its {@code ttl}. Only the list URI leaves the device, never
   * the index.
   */
  async checkTokenStatus(ref: TokenStatusReference, opts: StatusCheckOptions & { form?: 'jwt' | 'cwt' } = {}): Promise<StatusResult> {
    const { form, ...ctx } = opts;
    return this.statusCheck(ref?.uri, ctx, (c) => checkTokenStatus(ref, c, form));
  }

  /**
   * Checks a W3C {@code BitstringStatusListEntry}. The list credential must verify ({@code verifyListCredential},
   * supplied by the JSON-LD verifier), come from {@code issuer} and carry the entry's purpose; without both the
   * status is unknown, never valid.
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
   * Resolves a DID (a DID URL is accepted; its fragment names the verification method the caller needs).
   *
   * did:key and did:jwk are computed on the device. For a DID the snapshot carries, the snapshot's document is the
   * answer: the service is the one resolver for the parties it lists. When that document lacks the key asked for,
   * the snapshot is refreshed once; if a fresh snapshot still lacks it, the document is returned as it is (the key
   * is not the listed party's as far as the service knows). Only when no fresh snapshot can be had, and for DIDs
   * the snapshot does not carry, is the DID looked up per {@code lookups.did}.
   */
  async resolveDid(didUrl: string): Promise<DidResolutionResult> {
    const did = didUrl.split('#')[0]!;
    if (/^did:(key|jwk):/.test(did)) return resolveDidLocally(did, { fetch: this.fetchFn });
    let snap = await this.snapshot();
    const has = (s: SnapshotData | null) => !!s?.didDocuments[did] && (!didUrl.includes('#') || !!findVerificationMethod(s.didDocuments[did]!, didUrl));
    if (snap?.didDocuments[did] && !has(snap) && this.transport && this.now() - this.lastForcedSyncAt >= FORCED_REFRESH_MIN_MS) {
      this.lastForcedSyncAt = this.now();
      await this.refresh();
      snap = await this.snapshots.current().catch(() => null);
    }
    const doc = snap?.didDocuments[did];
    if (doc && (has(snap) || !snap!.stale)) {
      return { didDocument: doc, didDocumentMetadata: {}, didResolutionMetadata: { contentType: 'application/did+ld+json', source: 'snapshot', snapshot: snap!.id } };
    }
    return this.via(this.lookups.did, async (t) => {
      const cached = await this.cache.get<DidResolutionResult>(`did:${did}`);
      if (cached?.fresh) return withSource(cached.value, 'cache');
      const r = await t.request<string>('GET', `/api/v1/proxy/did/${did}`, { accept: 'application/jwt' });
      const body = await this.snapshots.verifySigned<DidResolutionResult>(String(r.body).trim(), 'trust-did-resolution+jwt');
      if (body?.didDocument?.id !== did) throw new TrustIntegrityError('The proxied DID document is about another DID');
      await this.cache.set(`did:${did}`, body, 15 * 60_000);
      return withSource(body, 'proxy');
    }, (source) => this.resolveDidDirect(did, source));
  }

  private async resolveDidDirect(did: string, source: 'direct' | 'fallback'): Promise<DidResolutionResult> {
    const key = `did:${did}`;
    const cached = await this.cache.get<DidResolutionResult>(key);
    if (cached?.fresh) return withSource(cached.value, 'cache');
    const r = await resolveDidLocally(did, { fetch: this.fetchFn, httpHosts: this.insecureHosts, timeoutMs: this.timeoutMs });
    if (didError(r)) {
      // A stale document only stands in for a transient failure, for a day at most: never after notFound (a 404 or 410
      // means the DID is gone) or an invalid document.
      const transient = didError(r) === DID_ERRORS.INTERNAL_ERROR;
      if (cached && transient && this.now() - cached.storedAt < STALE_DID_MAX_MS) {
        return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache', stale: true } };
      }
      if (!transient) await this.cache.delete(key);
      return r;
    }
    await this.cache.set(key, r, 15 * 60_000);
    return withSource(r, source);
  }

  // ---- JSON-LD contexts --------------------------------------------------------------------------

  /**
   * A JSON-LD context document. Contexts decide what a Data Integrity signature covers, so the ones the listed
   * parties use travel in the snapshot with their digests. One the snapshot does not ship is fetched from its host
   * and checked against the snapshot's digest when there is one; a context the snapshot does not know at all is
   * returned with {@code vouched: false}, for the caller to refuse or to flag.
   */
  async context(url: string): Promise<ContextDocument> {
    const known = (await this.snapshot())?.contexts[url];
    if (known?.document) return { document: known.document, sha256: known.sha256, source: 'snapshot', vouched: true };
    const cached = await this.cache.get<{ document: Record<string, unknown>; sha256: string }>(`ctx:${url}`);
    if (cached?.fresh && (!known || known.sha256 === cached.value.sha256)) return { ...cached.value, source: 'cache', vouched: !!known };
    this.requireSecure(url, 'A JSON-LD context');
    const res = await fetchWithTimeout(this.fetchFn, url, { headers: { Accept: 'application/ld+json, application/json;q=0.9' } }, this.timeoutMs, MAX_CONTEXT_BYTES);
    if (!res.ok) throw new Error(`JSON-LD context ${url}: HTTP ${res.status}`);
    const body = new Uint8Array(await res.arrayBuffer());
    const digest = base64UrlEncode(sha256(body));
    if (known && known.sha256 !== digest) {
      throw new TrustIntegrityError(`JSON-LD context ${url} is not the document the trust service vouches for (digest ${digest}, expected ${known.sha256})`);
    }
    const document = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
    if (typeof document !== 'object' || document === null || !('@context' in document)) throw new Error(`${url} is not a JSON-LD context document`);
    await this.cache.set(`ctx:${url}`, { document, sha256: digest }, CONTEXT_TTL_MS);
    return { document, sha256: digest, source: 'direct', vouched: !!known };
  }
}

function snapshotInfo(s: SnapshotData): SnapshotInfo {
  return { ...snapshotRef(s), entities: s.entities.length, anchors: s.anchors.length, didDocuments: Object.keys(s.didDocuments).length,
    contexts: Object.keys(s.contexts).length, crls: s.crls.length, strictAuthorization: s.policy.strictAuthorization,
    requireRevocationStatus: s.policy.requireRevocationStatus, requireSignedIssuerMetadata: s.policy.requireSignedIssuerMetadata };
}

function withSource(r: DidResolutionResult, source: DataSource): DidResolutionResult {
  return { ...r, didResolutionMetadata: { ...r.didResolutionMetadata, source } };
}

/** Whether a registry entry carries the identifier: the given type, or the types the service reads an untyped one as. */
function namesIdentifier(e: EntityView, id: { type?: string; value: string }): boolean {
  const types = id.type ? [id.type] : id.value.startsWith('did:') ? ['DID']
    : id.value.startsWith('https://') || id.value.startsWith('http://') ? ['URL', 'FEDERATION_ENTITY'] : ['CLIENT_ID', 'OTHER'];
  return e.identifiers.some((i) => types.includes(i.type) && identifierKey(i.type, i.value) === identifierKey(i.type, id.value));
}

export function createTrustClient(config: TrustClientConfig = {}): TrustClient {
  return new TrustClient(config);
}
