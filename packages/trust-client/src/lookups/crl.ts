/**
 * CRLs the snapshot does not carry, per {@code lookups.crl}. Cached until their nextUpdate. Callers verify each CRL
 * against the issuing CA, so neither the cache nor the proxy is trusted for them.
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
        const { der, source } = await this.download(url);
        const crl = parseCrl(der);
        // Unverified CRLs are not kept: a forged one would otherwise mask the real CRL until it expired.
        if (accept && !accept(url, crl)) throw new Error('CRL is not signed by the issuing CA');
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

  private download(url: string): Promise<{ der: Uint8Array; source: DataSource }> {
    const { ctx } = this;
    return via<{ der: Uint8Array; source: DataSource }>(ctx, ctx.lookups.crl, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/crl?url=${encodeURIComponent(url)}`, { accept: 'application/pkix-crl', binary: true });
      return { der: r.body, source: 'proxy' as const };
    }, async (source) => {
      // CRL distribution points are conventionally plain http: a CRL is signed, and verified against its CA here.
      if (!httpUrlHost(url)) throw new Error(`Unsupported CRL URL ${url}`);
      const res = await fetchWithTimeout(ctx.fetch, url, { headers: { Accept: 'application/pkix-crl' } }, ctx.timeoutMs);
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      return { der: new Uint8Array(await res.arrayBuffer()), source };
    });
  }
}
