/**
 * Credential status lists (Token Status List, Bitstring Status List), per {@code lookups.statusLists}. A list is
 * verified on this device and reused for its ttl; only the list URI leaves the device, never the index.
 */
import { fetchWithTimeout } from '../did/resolver.js';
import { checkBitstringStatus, checkTokenStatus, type ListCredentialVerifier, type StatusContext, type StatusResult,
  type TokenStatusReference } from '../status/status.js';
import type { DataSource, PathValidationResult } from '../types.js';
import { base64Decode, base64Encode } from '../util/bytes.js';
import { requireSecureUrl } from '../util/url.js';
import { via, type LookupContext } from './context.js';

/** A status list as fetched, before verification (it is signed by its issuer and verified by the caller). */
export interface FetchedStatusList {
  body: Uint8Array;
  contentType: string;
  source: DataSource;
}

/** What a status check needs to know about the credential; the trust client supplies fetching and chain validation. */
export type StatusCheckOptions = Omit<StatusContext, 'fetchList' | 'validateChain'>;

export class StatusListLookup {
  /** @param validateChain path validation of a list signer's chain in a trust domain */
  constructor(private readonly ctx: LookupContext,
              private readonly validateChain: (chain: string[], domain: string) => Promise<PathValidationResult>) {}

  async checkToken(ref: TokenStatusReference, opts: StatusCheckOptions & { form?: 'jwt' | 'cwt' }): Promise<StatusResult> {
    const { form, ...credential } = opts;
    return this.check(ref?.uri, credential, (c) => checkTokenStatus(ref, c, form));
  }

  async checkBitstring(entry: Record<string, unknown>, opts: StatusCheckOptions & { verifyListCredential?: ListCredentialVerifier }): Promise<StatusResult> {
    const { verifyListCredential, ...credential } = opts;
    return this.check(String(entry?.statusListCredential ?? ''), credential, (c) => checkBitstringStatus(entry, { ...c, verifyListCredential }));
  }

  /** Runs a check over the cached list when fresh, else over a fetched one; a list that verified is kept for its ttl. */
  private async check(uri: string, opts: StatusCheckOptions, check: (ctx: StatusContext) => Promise<StatusResult>): Promise<StatusResult> {
    const { ctx } = this;
    const base = { ...opts, validateChain: this.validateChain };
    const key = `status:${uri}`;
    const cached = uri ? await ctx.cache.get<{ body: string; contentType: string }>(key) : null;
    if (cached?.fresh) {
      const r = await check({ ...base, fetchList: async () => ({ body: base64Decode(cached.value.body), contentType: cached.value.contentType, source: 'cache' }) });
      if (r.value !== undefined) return r;
    }
    let fetched: FetchedStatusList | undefined;
    const r = await check({ ...base, fetchList: async (u, accept) => (fetched = await this.fetchList(u, accept)) });
    if (fetched && r.value !== undefined && (r.ttlMs ?? 0) > 0) {
      await ctx.cache.set(key, { body: base64Encode(fetched.body), contentType: fetched.contentType }, r.ttlMs!);
    }
    return r;
  }

  /** A credential status list per {@code lookups.statusLists}. Status lists are signed by their issuer; the caller verifies them. */
  private fetchList(uri: string, accept: string): Promise<FetchedStatusList> {
    const { ctx } = this;
    const contentType = (h: Headers) => (h.get('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
    return via<FetchedStatusList>(ctx, ctx.lookups.statusLists, async (t) => {
      const r = await t.request<Uint8Array>('GET', `/api/v1/proxy/status-list?uri=${encodeURIComponent(uri)}`, { accept, binary: true });
      return { body: r.body, contentType: contentType(r.headers), source: 'proxy' as const };
    }, async (source) => {
      requireSecureUrl(uri, 'A status list', ctx.insecureHosts);
      const res = await fetchWithTimeout(ctx.fetch, uri, { headers: { Accept: accept } }, ctx.timeoutMs);
      if (!res.ok) throw new Error(`Status list ${uri}: HTTP ${res.status}`);
      return { body: new Uint8Array(await res.arrayBuffer()), contentType: contentType(res.headers), source };
    });
  }
}
