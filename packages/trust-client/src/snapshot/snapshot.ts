/**
 * The signed trust snapshot ({@code typ: trust-snapshot+jwt}): the frameworks, entities, trust anchors, evaluation
 * policy, DID documents and the anchors' CRLs visible to this client. It is what device-side trust decisions are
 * made from.
 *
 * Integrity: verified against service keys pinned by JWK thumbprint (or trust-on-first-use, when enabled), bound
 * to this client's audience, and never replaced by an older snapshot (rollback protection by {@code iat}).
 * Persisted in the cache store and re-verified on load.
 */
import { decodeJws, verifyJws } from '../jose/jws.js';
import { jwkThumbprint, type Jwk } from '../crypto/keys.js';
import { parseCertificate } from '../x509/certificate.js';
import type { LocalAnchor } from '../x509/validate.js';
import { parseCrl } from '../x509/crl.js';
import type { HeldCrl } from '../x509/revocation.js';
import type { CacheStore } from '../cache/store.js';
import type { HttpTransport } from '../transport/http.js';
import { TrustIntegrityError } from '../errors.js';
import type { DidDocument, EntityView, SnapshotRef, TrustFramework } from '../types.js';

export interface ServiceKeyPolicy {
  /** JWK thumbprints (RFC 7638) of acceptable service signing keys. */
  thumbprints?: string[];
  /** Full public JWKs, alternatively. */
  jwks?: Jwk[];
  /** Accept and pin the first key seen from /.well-known/jwks.json (convenient, weaker). */
  trustOnFirstUse?: boolean;
}

/** The client policy the service evaluates with; carried in the snapshot so device-side decisions match. */
export interface SnapshotPolicy {
  frameworks: string[];
  strictAuthorization: boolean;
  /** a certificate whose revocation status cannot be determined is not trusted */
  requireRevocationStatus: boolean;
}

export interface SnapshotData {
  format: number;
  version: number;
  issuedAt: Date;
  expiresAt: Date;
  policy: SnapshotPolicy;
  frameworks: TrustFramework[];
  entities: EntityView[];
  anchors: LocalAnchor[];
  /** DID documents of registered DID identifiers, resolved by the service. */
  didDocuments: Record<string, DidDocument>;
  /**
   * The trust anchors' current CRLs, fetched by the service. Each is signed by its CA and is verified again on
   * this device before use.
   */
  crls: HeldCrl[];
  /** true when past exp but within the configured grace period */
  stale: boolean;
}

export function snapshotRef(s: SnapshotData): SnapshotRef {
  return { version: s.version, issuedAt: s.issuedAt.toISOString(), expiresAt: s.expiresAt.toISOString(), stale: s.stale };
}

const KEY = 'snapshot';
const PINNED = 'service-keys';

export class SnapshotManager {
  private cached: { jwt: string; etag?: string } | null = null;
  private parsed: SnapshotData | null = null;
  private inflight: Promise<SnapshotData> | null = null;

  constructor(private readonly transport: HttpTransport | null, private readonly store: CacheStore,
              private readonly keys: ServiceKeyPolicy, private readonly clientId: string | undefined,
              private readonly graceMs: number, private readonly now: () => number = Date.now) {}

  /** Fetches the latest snapshot (conditional GET); concurrent callers share one request. */
  sync(): Promise<SnapshotData> {
    this.inflight ??= this.doSync().finally(() => { this.inflight = null; });
    return this.inflight;
  }

  private async doSync(): Promise<SnapshotData> {
    if (!this.transport) throw new Error('No trust service configured');
    await this.load();
    const r = await this.transport.request<string>('GET', '/api/v1/snapshot', {
      accept: 'application/jwt', headers: this.cached?.etag ? { 'If-None-Match': this.cached.etag } : {},
    });
    if (r.status === 304 && this.parsed) return this.parsed;
    const jwt = String(r.body).trim();
    const data = await this.verify(jwt);
    if (data.expiresAt.getTime() <= this.now()) throw new TrustIntegrityError('The service returned an expired snapshot');
    // Rollback protection: never replace the held snapshot with an older one (a replay, or a lagging replica).
    if (this.parsed && data.issuedAt.getTime() < this.parsed.issuedAt.getTime()) return this.parsed;
    this.cached = { jwt, etag: r.headers.get('ETag') ?? undefined };
    this.parsed = data;
    await this.store.set(KEY, JSON.stringify(this.cached));
    return data;
  }

  /** The current usable snapshot (verified, not beyond its grace period), or null. */
  async current(): Promise<SnapshotData | null> {
    await this.load();
    if (!this.parsed) return null;
    const t = this.now();
    if (t > this.parsed.expiresAt.getTime() + this.graceMs) return null;
    return { ...this.parsed, stale: t > this.parsed.expiresAt.getTime() };
  }

  private async load(): Promise<void> {
    if (this.cached) return;
    const raw = await this.store.get(KEY).catch(() => null);
    if (!raw) return;
    try {
      const c = JSON.parse(raw) as { jwt: string; etag?: string };
      this.parsed = await this.verify(c.jwt, true);
      this.cached = c;
    } catch {
      await this.store.delete(KEY).catch(() => undefined);
    }
  }

  private async serviceKeys(kid: string | undefined, offline: boolean): Promise<Jwk[]> {
    const pinned: Jwk[] = [...(this.keys.jwks ?? [])];
    const stored = await this.store.get(PINNED).catch(() => null);
    if (stored) pinned.push(...(JSON.parse(stored) as Jwk[]));
    const thumbs = new Set(this.keys.thumbprints ?? []);
    const matching = pinned.filter((k) => !kid || k.kid === kid || jwkThumbprint(k) === kid);
    if (matching.length > 0 || offline || !this.transport) return matching.length > 0 ? matching : pinned;
    // Fetch the JWKS and accept keys whose thumbprint is pinned (or TOFU).
    const r = await this.transport.request<{ keys: Jwk[] }>('GET', '/.well-known/jwks.json', { accept: 'application/jwk-set+json, application/json' });
    const keys = (typeof r.body === 'string' ? JSON.parse(r.body) : r.body).keys as Jwk[];
    const accepted = keys.filter((k) => thumbs.has(jwkThumbprint(k)) || (this.keys.trustOnFirstUse && thumbs.size === 0 && pinned.length === 0));
    if (accepted.length > 0) await this.store.set(PINNED, JSON.stringify([...pinned, ...accepted]));
    return accepted.filter((k) => !kid || k.kid === kid || jwkThumbprint(k) === kid);
  }

  /** Verifies a signed response from the service (e.g. an on-demand lookup) with the pinned service keys. */
  async verifySigned<T>(jwt: string, typ: string): Promise<T> {
    const jws = decodeJws<Record<string, unknown>>(jwt);
    if (jws.header.typ !== typ) throw new TrustIntegrityError(`Unexpected typ ${String(jws.header.typ)}`);
    const keys = await this.serviceKeys(jws.header.kid as string | undefined, false);
    if (keys.length === 0 || !keys.some((k) => verifyJws(jws, k))) throw new TrustIntegrityError(`${typ} signature is invalid or the key is not pinned`);
    this.checkAudience(jws.payload.aud);
    const exp = Number(jws.payload.exp);
    if (Number.isFinite(exp) && exp * 1000 < this.now()) throw new TrustIntegrityError(`${typ} has expired`);
    return jws.payload.data as T;
  }

  private checkAudience(aud: unknown): void {
    if (this.clientId && aud !== this.clientId && !(Array.isArray(aud) && aud.includes(this.clientId))) {
      throw new TrustIntegrityError(`Audience ${String(aud)} is not this client`);
    }
  }

  private async verify(jwt: string, offline = false): Promise<SnapshotData> {
    const jws = decodeJws<Record<string, unknown>>(jwt);
    if (jws.header.typ !== 'trust-snapshot+jwt') throw new TrustIntegrityError(`Unexpected snapshot typ ${String(jws.header.typ)}`);
    const keys = await this.serviceKeys(jws.header.kid as string | undefined, offline);
    if (keys.length === 0) throw new TrustIntegrityError('No pinned trust-service key matches the snapshot signature key');
    if (!keys.some((k) => verifyJws(jws, k))) throw new TrustIntegrityError('Snapshot signature is invalid');
    const p = jws.payload;
    this.checkAudience(p.aud);
    const anchors: LocalAnchor[] = [];
    for (const a of (p.anchors as Record<string, unknown>[] | undefined) ?? []) {
      try {
        anchors.push({ certificate: parseCertificate(String(a.certificate)), domain: String(a.domain), id: a.id as string,
          frameworkId: a.frameworkId as string | undefined, entityId: a.entityId as string | undefined,
          status: a.status as string | undefined, constraints: (a.constraints as Record<string, unknown>) ?? {},
          provenance: a.provenance as LocalAnchor['provenance'] });
      } catch { /* skip unparseable anchor */ }
    }
    const crls: HeldCrl[] = [];
    for (const c of (p.crls as Record<string, unknown>[] | undefined) ?? []) {
      try {
        crls.push({ crl: parseCrl(String(c.crl)), url: c.url as string | undefined, source: 'snapshot' });
      } catch { /* skip unparseable CRL */ }
    }
    const policy = (p.policy ?? {}) as Partial<SnapshotPolicy>;
    return {
      format: Number(p.format ?? 1), version: Number(p.version),
      issuedAt: new Date(Number(p.iat) * 1000), expiresAt: new Date(Number(p.exp) * 1000),
      policy: { frameworks: policy.frameworks ?? [], strictAuthorization: policy.strictAuthorization === true,
        requireRevocationStatus: policy.requireRevocationStatus === true },
      frameworks: (p.frameworks as TrustFramework[]) ?? [], entities: (p.entities as EntityView[]) ?? [], anchors,
      didDocuments: (p.didDocuments as Record<string, DidDocument>) ?? {}, crls, stale: false,
    };
  }
}
