/**
 * DID resolution (a DID URL is accepted; its fragment names the verification method the caller needs).
 *
 * did:key and did:jwk are computed on the device. For a DID the snapshot carries, the snapshot's document is the
 * answer: the service is the one resolver for the parties it lists. When that document lacks the key asked for,
 * the snapshot is refreshed once; if a fresh snapshot still lacks it, the document is returned as it is (the key
 * is not the listed party's as far as the service knows). Only when no fresh snapshot can be had, and for DIDs
 * the snapshot does not carry, is the DID looked up per {@code lookups.did}.
 */
import { DID_ERRORS, didError, findVerificationMethod } from '../did/did.js';
import { resolveDidLocally } from '../did/resolver.js';
import { TrustIntegrityError } from '../errors.js';
import type { SnapshotData } from '../snapshot/snapshot.js';
import type { DataSource, DidResolutionResult } from '../types.js';
import { via, type LookupContext } from './context.js';

/** How long a cached DID document may stand in for one that cannot be fetched (the service's limit too). */
const STALE_DID_MAX_MS = 24 * 3600_000;
/** A forced snapshot refresh (a key the snapshot's DID document lacks) happens at most this often. */
const FORCED_REFRESH_MIN_MS = 60_000;

export class DidLookup {
  private lastForcedSyncAt = 0;

  constructor(private readonly ctx: LookupContext) {}

  async resolve(didUrl: string): Promise<DidResolutionResult> {
    const { ctx } = this;
    const did = didUrl.split('#')[0]!;
    if (/^did:(key|jwk):/.test(did)) return resolveDidLocally(did, { fetch: ctx.fetch });
    let snap = await ctx.refresher.snapshot();
    const has = (s: SnapshotData | null) => !!s?.didDocuments[did] && (!didUrl.includes('#') || !!findVerificationMethod(s.didDocuments[did]!, didUrl));
    if (snap?.didDocuments[did] && !has(snap) && ctx.transport && ctx.now() - this.lastForcedSyncAt >= FORCED_REFRESH_MIN_MS) {
      this.lastForcedSyncAt = ctx.now();
      await ctx.refresher.refresh();
      snap = await ctx.snapshots.current().catch(() => null);
    }
    const doc = snap?.didDocuments[did];
    if (doc && (has(snap) || !snap!.stale)) {
      return { didDocument: doc, didDocumentMetadata: {}, didResolutionMetadata: { contentType: 'application/did+ld+json', source: 'snapshot', snapshot: snap!.id } };
    }
    return via(ctx, ctx.lookups.did, async (t) => {
      const cached = await ctx.cache.get<DidResolutionResult>(`did:${did}`);
      if (cached?.fresh) return withSource(cached.value, 'cache');
      const r = await t.request<string>('GET', `/api/v1/proxy/did/${did}`, { accept: 'application/jwt' });
      const body = await ctx.snapshots.verifySigned<DidResolutionResult>(String(r.body).trim(), 'trust-did-resolution+jwt');
      if (body?.didDocument?.id !== did) throw new TrustIntegrityError('The proxied DID document is about another DID');
      await ctx.cache.set(`did:${did}`, body, 15 * 60_000);
      return withSource(body, 'proxy');
    }, (source) => this.direct(did, source));
  }

  private async direct(did: string, source: 'direct' | 'fallback'): Promise<DidResolutionResult> {
    const { ctx } = this;
    const key = `did:${did}`;
    const cached = await ctx.cache.get<DidResolutionResult>(key);
    if (cached?.fresh) return withSource(cached.value, 'cache');
    const r = await resolveDidLocally(did, { fetch: ctx.fetch, httpHosts: ctx.insecureHosts, timeoutMs: ctx.timeoutMs });
    if (didError(r)) {
      // A stale document only stands in for a transient failure, for a day at most: never after notFound (a 404 or 410
      // means the DID is gone) or an invalid document.
      const transient = didError(r) === DID_ERRORS.INTERNAL_ERROR;
      if (cached && transient && ctx.now() - cached.storedAt < STALE_DID_MAX_MS) {
        return { ...cached.value, didResolutionMetadata: { ...cached.value.didResolutionMetadata, source: 'cache', stale: true } };
      }
      if (!transient) await ctx.cache.delete(key);
      return r;
    }
    await ctx.cache.set(key, r, 15 * 60_000);
    return withSource(r, source);
  }
}

function withSource(r: DidResolutionResult, source: DataSource): DidResolutionResult {
  return { ...r, didResolutionMetadata: { ...r.didResolutionMetadata, source } };
}
