/**
 * The TrustClient: what a wallet or verifier uses the trust service through.
 *
 * Trust decisions are made on this device, from the signed trust snapshot the service compiles for this client. The
 * service never learns which credentials, issuers or verifiers the user deals with: the client contacts it to
 * refresh the snapshot and nothing else, unless a lookup below is routed through its proxy.
 *
 * Documents a counterparty would otherwise be asked for (issuer metadata, DID documents, CRLs, status lists, JSON-LD
 * contexts) come through the service's proxy first, and from the counterparty by the standard mechanism when the
 * proxy cannot serve them ({@code lookups: 'proxy'}, the default), or always from the counterparty ({@code 'direct'}).
 * A proxied document is either signed by its own issuer and verified here (CRLs, status lists, signed issuer
 * metadata), signed by the service and verified with the pinned service keys (issuer metadata, DID documents), or
 * held to the digest the snapshot carries (JSON-LD contexts).
 *
 * Without a usable snapshot the client decides from the trust pinned in the app, and says so in every decision; it
 * never answers TRUSTED without verified data. The rules do not lapse with the data: the app's own minimum, and the
 * client profile and trust mechanisms of the last snapshot that verified, stay in force (evaluation/rules.ts).
 */
import { CircuitBreaker } from './transport/circuit.js';
import { HttpTransport } from './transport/http.js';
import { ExpiringCache, MemoryCacheStore, type CacheStore } from './cache/store.js';
import { SnapshotManager, snapshotInfo, snapshotRef, type ServiceKeyPolicy, type SnapshotInfo } from './snapshot/snapshot.js';
import { SnapshotRefresher } from './snapshot/refresh.js';
import { LocalEvaluator, type LocalTrustData, identifierKey, validateChainOnDevice } from './evaluation/local.js';
import { minimumRules, NO_MECHANISMS, RulesInForce, type MinimumRules, type TrustRules } from './evaluation/rules.js';
import { parseMechanisms, type TrustMechanism } from './evaluation/mechanisms.js';
import type { LookupContext } from './lookups/context.js';
import { CrlLookup } from './lookups/crl.js';
import { DidLookup } from './lookups/did.js';
import { IssuerMetadataLookup } from './lookups/issuer-metadata.js';
import { JsonLdContextLookup, type ContextDocument } from './lookups/json-ld.js';
import { StatusListLookup, type StatusCheckOptions } from './lookups/status-list.js';
import { UnknownPartyLookup } from './lookups/unknown-party.js';
import { requireSecureUrl } from './util/url.js';
import { parseCertificate } from './x509/certificate.js';
import { type LocalAnchor } from './x509/validate.js';
import type { ListCredentialVerifier, StatusResult, TokenStatusReference } from './status/status.js';
import type { DidResolutionResult, EntityFilter, EntityView, IssuerMetadataResult, Page, PathValidationResult,
  ServiceDiscovery, ServiceStatus, ServiceStatusEvent, TrustDecision, TrustFramework, TrustQuery } from './types.js';

export type { SnapshotInfo } from './snapshot/snapshot.js';
export type { MinimumRules, TrustRules } from './evaluation/rules.js';
export type { TrustMechanism } from './evaluation/mechanisms.js';
export type { ContextDocument } from './lookups/json-ld.js';
export type { FetchedStatusList, StatusCheckOptions } from './lookups/status-list.js';

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
  /** JSON-LD context documents the snapshot does not carry; held either way to the digest the snapshot carries. */
  contexts?: LookupVia;
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
  /**
   * Trust bundled with the app: decides only while no snapshot is usable. With a snapshot, the service is the authority.
   * Pinned trust has no rules of its own: the rules in force apply to it (see {@link policy}).
   */
  pinned?: { anchors?: PinnedAnchor[]; entities?: EntityView[] };
  /**
   * The app's own minimum rules, in force for every decision this client makes, with or without a snapshot. Each rule
   * in force is the stricter of this and the client profile the service states in its snapshots; the profile of the
   * last snapshot that verified stays in force once that snapshot can no longer be used, also after a restart (with the
   * same storage). A key that is not one of these is an error.
   */
  policy?: MinimumRules;
  /**
   * The app's own trust mechanisms, in the shape of the snapshot claim {@code mechanisms} (camelCase, the order they are
   * tried in), read as strictly: a member or a value this client does not know is an error. They are in force only while
   * no snapshot has ever verified (with the same storage): once the service has spoken, its list is the list, also when
   * it is empty. Unlike the flags of {@link policy}, an ordered list does not combine with the service's.
   */
  mechanisms?: TrustMechanism[];
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

/** What the client currently stands on. */
export interface TrustStatus {
  service: ServiceStatus;
  /** The snapshot decisions are made from; null when none is usable (decisions then rest on pinned trust only). */
  snapshot: SnapshotInfo | null;
  /** Why the last snapshot refresh failed; cleared by a successful one. */
  lastSyncError?: string;
  /** No usable snapshot, or one past its expiry: decisions carry a warning. */
  degraded: boolean;
  /**
   * The rule flags decisions are made under now: the app's minimum, made stricter by the client profile of the last
   * snapshot that verified (also when that snapshot is no longer usable). The three flags and nothing else. Always set
   * by {@link TrustClient.status}; optional so that a TrustStatus an app writes itself (a placeholder before the first
   * call) still type-checks.
   */
  rules?: TrustRules;
  /**
   * The trust mechanisms decisions are made under now, in the order they are tried: those of the last snapshot that
   * verified (also when it is no longer usable, and empty when it states none), or the app's own while none has
   * verified. Frozen: changing the list or a mechanism in it puts nothing in force. Always set by
   * {@link TrustClient.status}; optional for the same reason as {@link rules}.
   */
  mechanisms?: readonly TrustMechanism[];
}

export class TrustClient {
  readonly lookups: Required<LookupPolicy>;
  private readonly transport: HttpTransport | null;
  private readonly snapshots: SnapshotManager;
  private readonly refresher: SnapshotRefresher;
  private readonly rules: RulesInForce;
  private readonly local: LocalEvaluator;
  private readonly now: () => number;
  private readonly pinnedAnchors: LocalAnchor[];
  private readonly metadata: IssuerMetadataLookup;
  private readonly dids: DidLookup;
  private readonly crls: CrlLookup;
  private readonly statusLists: StatusListLookup;
  private readonly contexts: JsonLdContextLookup;
  private readonly unknownParties: UnknownPartyLookup;
  private serviceStatus: ServiceStatus;
  private readonly listeners = new Set<(e: ServiceStatusEvent) => void>();

  constructor(private readonly config: TrustClientConfig = {}) {
    const f = config.http?.fetch ?? (globalThis.fetch?.bind(globalThis) as typeof fetch | undefined);
    if (!f) throw new Error('No fetch implementation available');
    const insecureHosts = config.http?.insecureHosts ?? [];
    this.now = config.clock ? () => config.clock!().getTime() : Date.now;
    const minimum = minimumRules(config.policy);
    // Read strictly and frozen (parseMechanisms): what the app passed in cannot change the rules in force afterwards.
    const appMechanisms = config.mechanisms === undefined ? NO_MECHANISMS : parseMechanisms(config.mechanisms);
    const service = config.service;
    if (service) {
      // Nothing the service signs is accepted without knowing for whom and by which key: a missing value here would
      // silently accept another client's snapshot, or none at all.
      if (!service.clientId) throw new Error('service.clientId is required: it is the audience of everything the service signs for this client');
      const keys = service.keys ?? {};
      if (!keys.thumbprints?.length && !keys.jwks?.length && !keys.trustOnFirstUse) {
        throw new Error('service.keys is required: pin the service key thumbprints (or set trustOnFirstUse for development)');
      }
      requireSecureUrl(service.url, 'The trust service', insecureHosts);
    }
    const via: LookupVia = service ? 'proxy' : 'direct';
    const l: LookupPolicy = typeof config.lookups === 'string'
      ? { metadata: config.lookups, did: config.lookups, crl: config.lookups, statusLists: config.lookups, contexts: config.lookups }
      : config.lookups ?? {};
    this.lookups = { metadata: l.metadata ?? via, did: l.did ?? via, crl: l.crl ?? via, statusLists: l.statusLists ?? via,
      contexts: l.contexts ?? via, unknownParties: l.unknownParties ?? false };
    const store = config.storage ?? new MemoryCacheStore();
    this.serviceStatus = service ? 'unknown' : 'unconfigured';
    this.transport = service ? new HttpTransport({
      baseUrl: service.url, apiKey: service.apiKey, fetch: f, timeoutMs: config.http?.timeoutMs ?? 4000,
      retries: config.http?.retries ?? 1, backoffMs: config.http?.backoffMs ?? 200,
      breaker: new CircuitBreaker(config.http?.circuitBreaker?.failureThreshold ?? 3, config.http?.circuitBreaker?.resetAfterMs ?? 30_000),
      onAvailability: (ok, reason) => this.setServiceStatus(ok ? 'online' : 'offline', reason),
    }) : null;
    this.snapshots = new SnapshotManager(this.transport, store, service?.keys ?? {}, service?.clientId,
      config.snapshot?.graceMs ?? 7 * 24 * 3600_000, this.now);
    this.rules = new RulesInForce(minimum, () => this.snapshots.lastRules(), appMechanisms);
    this.refresher = new SnapshotRefresher(this.snapshots, {
      service: !!this.transport, refreshMs: config.snapshot?.refreshMs ?? 3600_000, retryMs: config.snapshot?.retryMs ?? 30_000,
      now: this.now, logger: config.logger, onChange: (reason) => this.notify(reason),
    });
    const ctx: LookupContext = {
      transport: this.transport, snapshots: this.snapshots, refresher: this.refresher, rules: this.rules, cache: new ExpiringCache(store, this.now),
      lookups: this.lookups, fetch: f, timeoutMs: config.http?.timeoutMs ?? 8000, insecureHosts, now: this.now, logger: config.logger,
    };
    const validateChain = (chain: string[], domain: string) => this.validateChain(chain, domain);
    this.metadata = new IssuerMetadataLookup(ctx, config.issuerMetadata?.signed ?? 'off', (query) => this.evaluate(query), validateChain);
    this.dids = new DidLookup(ctx);
    this.crls = new CrlLookup(ctx);
    this.statusLists = new StatusListLookup(ctx, validateChain);
    this.contexts = new JsonLdContextLookup(ctx);
    this.unknownParties = new UnknownPartyLookup(ctx);
    this.local = new LocalEvaluator((did) => this.resolveDid(did), () => new Date(this.now()), (urls, accept) => this.crls.fetch(urls, accept));
    this.pinnedAnchors = (config.pinned?.anchors ?? []).map((a) => ({
      certificate: parseCertificate(a.certificate), domain: a.domain, frameworkId: a.frameworkId, entityId: a.entityId, constraints: a.constraints,
    }));
  }

  // ---- status ----------------------------------------------------------------------------------------

  /** What decisions currently rest on and the rules they are made under, and why the snapshot is not fresh when it is not. */
  async status(): Promise<TrustStatus> {
    const s = await this.snapshots.current().catch(() => null);
    const { rules, mechanisms } = await this.rules.inForce(s);
    return { service: this.serviceStatus, snapshot: s ? snapshotInfo(s) : null, lastSyncError: this.refresher.lastSyncError, degraded: !s || s.stale,
      rules, mechanisms };
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
  sync(): Promise<SnapshotInfo> {
    return this.refresher.sync();
  }

  private async localData(): Promise<LocalTrustData> {
    const snap = await this.refresher.snapshot();
    // The rules outlive the data: without a usable snapshot, the app's minimum and the last verified profile still hold.
    const { rules: policy, mechanisms } = await this.rules.inForce(snap);
    if (!snap) {
      return { entities: this.config.pinned?.entities ?? [], anchors: this.pinnedAnchors, frameworks: [], source: 'pinned', policy, mechanisms, snapshot: null };
    }
    // Parties found on demand are not snapshot entries: the evaluator meets them only where the service's would.
    const onDemand = this.lookups.unknownParties && this.transport
      ? async (ids: Array<{ type: string; value: string }>) => {
        const hit = await this.unknownParties.find(ids);
        return hit ? { entity: hit.entities[0]!, identifier: hit.identifier as { type: string; value: string } } : undefined;
      } : undefined;
    return { onDemand, entities: snap.entities, anchors: snap.anchors, crls: snap.crls, frameworks: snap.frameworks, source: 'snapshot',
      policy, mechanisms, snapshot: snapshotRef(snap), stale: snap.stale };
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
    return found.length > 0 ? found : (await this.unknownParties.find([{ value: identifier }]))?.entities ?? [];
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
      (urls, accept) => this.crls.fetch(urls, accept));
    const entity = anchorRef?.entityId ? d.entities.find((e) => e.id === anchorRef.entityId) : undefined;
    return { ...r, entity, source: d.source };
  }

  // ---- lookups: the proxy, and the standard mechanisms behind it (./lookups) -------------------------

  /**
   * OpenID4VCI issuer and authorization server metadata, with this device's trust decision about the issuer and the
   * registry's metadata policy applied.
   */
  getIssuerMetadata(credentialIssuer: string): Promise<IssuerMetadataResult> {
    return this.metadata.get(credentialIssuer);
  }

  /**
   * Checks a Token Status List reference: {@code status.status_list} of an SD-JWT VC ({@code form: 'jwt'}) or of an
   * ISO mdoc MSO ({@code form: 'cwt'}). The list is fetched per {@code lookups.statusLists}, verified on this device
   * (signature, signer, subject, expiry) and reused for its {@code ttl}. Only the list URI leaves the device, never
   * the index.
   */
  checkTokenStatus(ref: TokenStatusReference, opts: StatusCheckOptions & { form?: 'jwt' | 'cwt' } = {}): Promise<StatusResult> {
    return this.statusLists.checkToken(ref, opts);
  }

  /**
   * Checks a W3C {@code BitstringStatusListEntry}. The list credential must verify ({@code verifyListCredential},
   * supplied by the JSON-LD verifier), come from {@code issuer} and carry the entry's purpose; without both the
   * status is unknown, never valid.
   */
  checkBitstringStatus(entry: Record<string, unknown>, opts: StatusCheckOptions & { verifyListCredential?: ListCredentialVerifier } = {}): Promise<StatusResult> {
    return this.statusLists.checkBitstring(entry, opts);
  }

  /**
   * Resolves a DID (a DID URL is accepted; its fragment names the verification method the caller needs).
   *
   * did:key and did:jwk are computed on the device. For a DID the snapshot carries, the snapshot's document is the
   * answer: the service is the one resolver for the parties it lists. When that document lacks the key asked for,
   * the snapshot is refreshed once; if a fresh snapshot still lacks it, the document is returned as it is (the key
   * is not the listed party's as far as the service knows). Only when no fresh snapshot can be had, and for DIDs
   * the snapshot does not carry, is the DID looked up per {@code lookups.did}.
   */
  resolveDid(didUrl: string): Promise<DidResolutionResult> {
    return this.dids.resolve(didUrl);
  }

  /**
   * A JSON-LD context document. Contexts decide what a Data Integrity signature covers, so the ones the listed
   * parties use travel in the snapshot with their digests. One the snapshot does not ship is looked up per
   * {@code lookups.contexts} (the service's relay, then its own URL) and must have the snapshot's digest when there is
   * one; a context the snapshot does not know at all is returned with {@code vouched: false}, whichever way it came,
   * for the caller to refuse or to flag.
   */
  context(url: string): Promise<ContextDocument> {
    return this.contexts.get(url);
  }
}

export function createTrustClient(config: TrustClientConfig = {}): TrustClient {
  return new TrustClient(config);
}
