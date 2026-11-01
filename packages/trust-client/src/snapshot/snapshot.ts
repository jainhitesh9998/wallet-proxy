/**
 * The signed offline trust snapshot ({@code typ: trust-snapshot+jwt}). Verified against service keys pinned by
 * JWK thumbprint (or trust-on-first-use, when enabled), persisted, and used for decisions while offline.
 */
import { decodeJws, verifyJws } from '../jose/jws.js';
import { jwkThumbprint, type Jwk } from '../crypto/keys.js';
import { parseCertificate } from '../x509/certificate.js';
import type { LocalAnchor } from '../x509/validate.js';
import type { CacheStore } from '../cache/store.js';
import type { HttpTransport } from '../transport/http.js';
import { TrustIntegrityError } from '../errors.js';
import type { EntityView, TrustFramework } from '../types.js';

export interface ServiceKeyPolicy {
  /** JWK thumbprints (RFC 7638) of acceptable service signing keys. */
  thumbprints?: string[];
  /** Full public JWKs, alternatively. */
  jwks?: Jwk[];
  /** Accept and pin the first key seen from /.well-known/jwks.json (convenient, weaker). */
  trustOnFirstUse?: boolean;
}

export interface SnapshotData {
  version: number;
  issuedAt: Date;
  expiresAt: Date;
  frameworks: TrustFramework[];
  entities: EntityView[];
  anchors: LocalAnchor[];
  /** true when past exp but within the configured grace period */
  stale: boolean;
}

const KEY = 'snapshot';
const PINNED = 'service-keys';

export class SnapshotManager {
  private cached: { jwt: string; etag?: string } | null = null;
  private parsed: SnapshotData | null = null;

  constructor(private readonly transport: HttpTransport | null, private readonly store: CacheStore,
              private readonly keys: ServiceKeyPolicy, private readonly clientId: string | undefined,
              private readonly graceMs: number, private readonly now: () => number = Date.now) {}

  /** Fetches the latest snapshot (conditional GET); returns its version. */
  async sync(): Promise<SnapshotData> {
    if (!this.transport) throw new Error('No trust service configured');
    await this.load();
    const r = await this.transport.request<string>('GET', '/api/v1/snapshot', {
      accept: 'application/jwt', headers: this.cached?.etag ? { 'If-None-Match': this.cached.etag } : {},
    });
    if (r.status === 304 && this.parsed) return this.parsed;
    const jwt = String(r.body).trim();
    const data = await this.verify(jwt);
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

  private async verify(jwt: string, offline = false): Promise<SnapshotData> {
    const jws = decodeJws<Record<string, unknown>>(jwt);
    if (jws.header.typ !== 'trust-snapshot+jwt') throw new TrustIntegrityError(`Unexpected snapshot typ ${String(jws.header.typ)}`);
    const keys = await this.serviceKeys(jws.header.kid as string | undefined, offline);
    if (keys.length === 0) throw new TrustIntegrityError('No pinned trust-service key matches the snapshot signature key');
    if (!keys.some((k) => verifyJws(jws, k))) throw new TrustIntegrityError('Snapshot signature is invalid');
    const p = jws.payload;
    const aud = p.aud;
    if (this.clientId && aud !== this.clientId && !(Array.isArray(aud) && aud.includes(this.clientId))) {
      throw new TrustIntegrityError(`Snapshot audience ${String(aud)} is not this client`);
    }
    const anchors: LocalAnchor[] = [];
    for (const a of (p.anchors as Record<string, unknown>[] | undefined) ?? []) {
      try {
        anchors.push({ certificate: parseCertificate(String(a.certificate)), domain: String(a.domain), id: a.id as string,
          frameworkId: a.frameworkId as string | undefined, entityId: a.entityId as string | undefined,
          status: a.status as string | undefined, constraints: (a.constraints as Record<string, unknown>) ?? {} });
      } catch { /* skip unparseable anchor */ }
    }
    return {
      version: Number(p.version), issuedAt: new Date(Number(p.iat) * 1000), expiresAt: new Date(Number(p.exp) * 1000),
      frameworks: (p.frameworks as TrustFramework[]) ?? [], entities: (p.entities as EntityView[]) ?? [], anchors, stale: false,
    };
  }
}
