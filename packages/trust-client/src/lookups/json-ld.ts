/**
 * JSON-LD context documents. Contexts decide what a Data Integrity signature covers, so the ones the listed parties
 * use travel in the snapshot with their digests. One the snapshot does not ship is fetched from its host and checked
 * against the snapshot's digest when there is one; a context the snapshot does not know at all is returned with
 * {@code vouched: false}, for the caller to refuse or to flag.
 */
import { sha256 } from '../crypto/hash.js';
import { fetchWithTimeout } from '../did/resolver.js';
import { TrustIntegrityError } from '../errors.js';
import type { DataSource } from '../types.js';
import { base64UrlEncode } from '../util/bytes.js';
import { requireSecureUrl } from '../util/url.js';
import type { LookupContext } from './context.js';

/** A JSON-LD context with where it came from; {@code vouched}: the snapshot carries its digest. */
export interface ContextDocument {
  document: Record<string, unknown>;
  sha256: string;
  source: DataSource;
  vouched: boolean;
}

const CONTEXT_TTL_MS = 24 * 3600_000;
const MAX_CONTEXT_BYTES = 1024 * 1024;

export class JsonLdContextLookup {
  constructor(private readonly ctx: LookupContext) {}

  async get(url: string): Promise<ContextDocument> {
    const { ctx } = this;
    const known = (await ctx.refresher.snapshot())?.contexts[url];
    if (known?.document) return { document: known.document, sha256: known.sha256, source: 'snapshot', vouched: true };
    const cached = await ctx.cache.get<{ document: Record<string, unknown>; sha256: string }>(`ctx:${url}`);
    if (cached?.fresh && (!known || known.sha256 === cached.value.sha256)) return { ...cached.value, source: 'cache', vouched: !!known };
    requireSecureUrl(url, 'A JSON-LD context', ctx.insecureHosts);
    const res = await fetchWithTimeout(ctx.fetch, url, { headers: { Accept: 'application/ld+json, application/json;q=0.9' } }, ctx.timeoutMs, MAX_CONTEXT_BYTES);
    if (!res.ok) throw new Error(`JSON-LD context ${url}: HTTP ${res.status}`);
    const body = new Uint8Array(await res.arrayBuffer());
    const digest = base64UrlEncode(sha256(body));
    if (known && known.sha256 !== digest) {
      throw new TrustIntegrityError(`JSON-LD context ${url} is not the document the trust service vouches for (digest ${digest}, expected ${known.sha256})`);
    }
    const document = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
    if (typeof document !== 'object' || document === null || !('@context' in document)) throw new Error(`${url} is not a JSON-LD context document`);
    await ctx.cache.set(`ctx:${url}`, { document, sha256: digest }, CONTEXT_TTL_MS);
    return { document, sha256: digest, source: 'direct', vouched: !!known };
  }
}
