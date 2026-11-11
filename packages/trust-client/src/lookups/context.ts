/** What the lookups have in common: what the client hands each of them, and the rule "proxy first, then the standard mechanism". */
import type { ExpiringCache } from '../cache/store.js';
import type { Logger, LookupPolicy, LookupVia } from '../client.js';
import type { SnapshotRefresher } from '../snapshot/refresh.js';
import type { SnapshotManager } from '../snapshot/snapshot.js';
import type { HttpTransport } from '../transport/http.js';

export interface LookupContext {
  /** Requests to the trust service; null when none is configured. */
  transport: HttpTransport | null;
  /** The held snapshot, and verification of what the service signs. */
  snapshots: SnapshotManager;
  /** The snapshot to decide from, refreshed when due. */
  refresher: SnapshotRefresher;
  cache: ExpiringCache;
  lookups: Required<LookupPolicy>;
  /** For requests to a counterparty. */
  fetch: typeof fetch;
  timeoutMs: number;
  /** Hosts that may be reached over plain http (loopback development only); everything else must be https. */
  insecureHosts: string[];
  now: () => number;
  logger?: Logger;
}

/**
 * Runs a lookup through the service's proxy, and by the standard mechanism when the proxy cannot serve it: because
 * it is unreachable, because it declines (an issuer its registry does not list), or because its answer does not
 * verify. The standard mechanism never depends on the proxy, so falling back to it is always safe.
 */
export async function via<T>(ctx: LookupContext, route: LookupVia | 'none', proxied: (t: HttpTransport) => Promise<T>,
                             direct: (source: 'direct' | 'fallback') => Promise<T>): Promise<T> {
  if (route !== 'proxy' || !ctx.transport) return direct('direct');
  try {
    return await proxied(ctx.transport);
  } catch (e) {
    ctx.logger?.info?.(`proxy could not serve (${(e as Error).message}); using the standard mechanism`);
    return direct('fallback');
  }
}
