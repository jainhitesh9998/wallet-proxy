/**
 * CRLs the snapshot does not carry, per {@code lookups.crl}. Cached until their nextUpdate. Callers verify each CRL
 * against the issuing CA, so neither the cache nor the proxy is trusted for them. A CRL older than the one held does
 * not replace it.
 */
import { fetchWithTimeout } from '../did/resolver.js';
import type { CrlFetchResult } from '../evaluation/local.js';
import type { DataSource } from '../types.js';
import { base64Decode, base64Encode } from '../util/bytes.js';
import { httpUrlHost } from '../util/url.js';
import { parseCrl, type Crl } from '../x509/crl.js';
import type { HeldCrl } from '../x509/revocation.js';
import { via, type LookupContext } from './context.js';

export class CrlLookup {
  constructor(private readonly ctx: LookupContext) {}

  async fetch(urls: string[], accept?: (url: string, crl: Crl) => boolean): Promise<CrlFetchResult> {
    const { ctx } = this;
    const out: CrlFetchResult = { crls: [], failures: {} };
    for (const url of new Set(urls)) {
      if (ctx.lookups.crl === 'none') { out.failures[url] = 'CRL downloads are disabled on this device'; continue; }
      const key = `crl:${url}`;
      const cached = await ctx.cache.get<string>(key);
      const fromCache = (): HeldCrl | null => {
        try {
          const crl = cached ? parseCrl(base64Decode(cached.value)) : null;
          return crl && (!accept || accept(url, crl)) ? { crl, url, source: 'cache' } : null;
        } catch { return null; }
      };
      if (cached?.fresh) {
        const c = fromCache();
        if (c) { out.crls.push(c); continue; }
        await ctx.cache.delete(key);
      }
      try {
        // What a route hands over counts only when it is a CRL the issuing CA signed (a forged one would otherwise mask
        // the real CRL until it expired) and not older than the CRL held (a CRL from before a revocation, served again,
        // would undo that revocation). A relay that answers with anything else has not served the lookup: the URL itself
        // is asked next, as for every lookup the proxy cannot serve.
        const usable = (der: Uint8Array): Crl => {
          const crl = parseCrl(der);
          if (accept && !accept(url, crl)) throw new Error('CRL is not signed by the issuing CA');
          const held = fromCache();
          if (held && crl.thisUpdate.getTime() < held.crl.thisUpdate.getTime()) throw new Error('CRL is older than the one already held');
          return crl;
        };
        const { crl, source } = await this.download(url, usable);
        const ttl = Math.min(24 * 3600_000, Math.max(60_000, (crl.nextUpdate?.getTime() ?? ctx.now() + 3600_000) - ctx.now()));
        await ctx.cache.set(key, base64Encode(crl.der), ttl);
        out.crls.push({ crl, url, source });
      } catch (e) {
        const stale = fromCache();
        if (stale) out.crls.push(stale);
        else out.failures[url] = (e as Error).message;
      }
    }
    return out;
  }

  /** The CRL at {@code url} by the configured route; {@code usable} throws for an answer that does not count. */
  private download(url: string, usable: (der: Uint8Array) => Crl): Promise<{ crl: Crl; source: DataSource }> {
    const { ctx } = this;
    return via<{ crl: Crl; source: DataSource }>(ctx, ctx.lookups.crl, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/crl?url=${encodeURIComponent(url)}`, { accept: 'application/pkix-crl', binary: true });
      return { crl: usable(r.body), source: 'proxy' as const };
    }, async (source) => {
      // CRL distribution points are conventionally plain http: a CRL is signed, and verified against its CA here.
      if (!httpUrlHost(url)) throw new Error(`Unsupported CRL URL ${url}`);
      const res = await fetchWithTimeout(ctx.fetch, url, { headers: { Accept: 'application/pkix-crl' } }, ctx.timeoutMs);
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      return { crl: usable(new Uint8Array(await res.arrayBuffer())), source };
    });
  }
}
