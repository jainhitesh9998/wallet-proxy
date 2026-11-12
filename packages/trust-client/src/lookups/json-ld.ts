/**
 * JSON-LD context documents. Contexts decide what a Data Integrity signature covers, so the ones the listed parties
 * use travel in the snapshot with their digests. One the snapshot does not ship is looked up per
 * {@code lookups.contexts}: through the service's relay, and at its own URL when the relay cannot serve it or answers
 * with something that does not count. Either way it must have the snapshot's digest when there is one; a context the
 * snapshot does not know at all is returned with {@code vouched: false}, for the caller to refuse or to flag.
 */
import { sha256 } from '../crypto/hash.js';
import { fetchWithTimeout } from '../did/resolver.js';
import { TrustIntegrityError } from '../errors.js';
import type { DataSource } from '../types.js';
import { base64UrlEncode } from '../util/bytes.js';
import { requireSecureUrl } from '../util/url.js';
import { via, type LookupContext } from './context.js';

/** A JSON-LD context with where it came from; {@code vouched}: the snapshot carries its digest. */
export interface ContextDocument {
  document: Record<string, unknown>;
  sha256: string;
  source: DataSource;
  vouched: boolean;
}

const CONTEXT_TTL_MS = 24 * 3600_000;
const MAX_CONTEXT_BYTES = 1024 * 1024;
const ACCEPT = 'application/ld+json, application/json;q=0.9';

export class JsonLdContextLookup {
  constructor(private readonly ctx: LookupContext) {}

  async get(url: string): Promise<ContextDocument> {
    const { ctx } = this;
    const known = (await ctx.refresher.snapshot())?.contexts[url];
    if (known?.document) return { document: known.document, sha256: known.sha256, source: 'snapshot', vouched: true };
    const cached = await ctx.cache.get<{ document: Record<string, unknown>; sha256: string }>(`ctx:${url}`);
    if (cached?.fresh && (!known || known.sha256 === cached.value.sha256)) return { ...cached.value, source: 'cache', vouched: !!known };
    requireSecureUrl(url, 'A JSON-LD context', ctx.insecureHosts);
    // What a route hands over counts only when it is a context within the size allowed and, when the snapshot knows
    // the context, has exactly the snapshot's digest. The relay neither signs nor vouches: a relayed document that does
    // not count has not served the lookup, and the URL itself is asked next, as for every lookup the relay cannot
    // serve. Only when that has another digest too does the lookup end, with the integrity error.
    const usable = (body: Uint8Array): { document: Record<string, unknown>; sha256: string } => {
      if (body.length > MAX_CONTEXT_BYTES) throw new Error(`JSON-LD context ${url} is larger than ${MAX_CONTEXT_BYTES} bytes`);
      const digest = base64UrlEncode(sha256(body));
      if (known && known.sha256 !== digest) {
        throw new TrustIntegrityError(`JSON-LD context ${url} is not the document the trust service vouches for (digest ${digest}, expected ${known.sha256})`);
      }
      let document: unknown;
      try {
        document = JSON.parse(new TextDecoder().decode(body));
      } catch {
        throw new Error(`${url} is not JSON`);
      }
      if (typeof document !== 'object' || document === null || Array.isArray(document) || !('@context' in document)) {
        throw new Error(`${url} is not a JSON-LD context document`);
      }
      return { document: document as Record<string, unknown>, sha256: digest };
    };
    const { document, sha256: digest, source } = await via(ctx, ctx.lookups.contexts, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/context?url=${encodeURIComponent(url)}`, { accept: ACCEPT, binary: true });
      return { ...usable(r.body), source: 'proxy' as DataSource };
    }, async (source) => {
      const res = await fetchWithTimeout(ctx.fetch, url, { headers: { Accept: ACCEPT } }, ctx.timeoutMs, MAX_CONTEXT_BYTES);
      if (!res.ok) throw new Error(`JSON-LD context ${url}: HTTP ${res.status}`);
      return { ...usable(new Uint8Array(await res.arrayBuffer())), source: source as DataSource };
    });
    await ctx.cache.set(`ctx:${url}`, { document, sha256: digest }, CONTEXT_TTL_MS);
    return { document, sha256: digest, source, vouched: !!known };
  }
}
