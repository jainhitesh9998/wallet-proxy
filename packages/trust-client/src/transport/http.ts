/** HTTP transport to the trust service: timeouts, retries with backoff, circuit breaker, problem details. */
import { CircuitBreaker } from './circuit.js';
import { TrustServiceError, TrustServiceUnavailableError } from '../errors.js';
import { fetchWithTimeout } from '../did/resolver.js';

/** The service's own responses (a snapshot with large trust lists and their CRLs) may be bigger than a party's. */
const MAX_SERVICE_BODY_BYTES = 64 * 1024 * 1024;

/**
 * The codes of the service's {@code 502} problem documents: the party it asked on the caller's behalf (a CRL
 * distribution point, a status list or context host, an issuer) did not answer, or answered with something it does
 * not pass on. Such an answer comes from a service that works; the lookup goes to the standard mechanism, and the
 * service is not counted as down for it.
 */
const UPSTREAM_FAILURES = new Set(['upstream_unavailable', 'invalid_crl', 'invalid_status_list', 'invalid_context', 'fetch_failed']);

/** The problem document of a {@code 502} the service itself answered about its upstream; undefined for any other answer. */
async function upstreamFailure(res: Response): Promise<Record<string, unknown> | undefined> {
  if (res.status !== 502 || !(res.headers.get('Content-Type') ?? '').toLowerCase().startsWith('application/problem+json')) return undefined;
  try {
    const p = (await res.json()) as unknown;
    return p && typeof p === 'object' && typeof (p as Record<string, unknown>).code === 'string'
      && UPSTREAM_FAILURES.has((p as Record<string, unknown>).code as string) ? p as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

export interface TransportOptions {
  baseUrl: string;
  apiKey?: string;
  fetch: typeof fetch;
  timeoutMs: number;
  retries: number;
  backoffMs: number;
  breaker: CircuitBreaker;
  onAvailability?: (available: boolean, reason?: string) => void;
}

export interface TransportResponse<T> {
  status: number;
  body: T;
  headers: Headers;
}

export class HttpTransport {
  constructor(private readonly opts: TransportOptions) {}

  get breaker(): CircuitBreaker {
    return this.opts.breaker;
  }

  /** {@code binary}: a successful body is returned as bytes (e.g. a relayed CRL or status list). */
  async request<T>(method: 'GET' | 'POST', path: string, init: { body?: unknown; accept?: string; headers?: Record<string, string>; idempotent?: boolean;
    binary?: boolean } = {}): Promise<TransportResponse<T>> {
    const { breaker } = this.opts;
    if (!breaker.canRequest()) throw new TrustServiceUnavailableError('Trust service circuit is open');
    const headers: Record<string, string> = { Accept: init.accept ?? 'application/json', ...(init.headers ?? {}) };
    if (this.opts.apiKey) headers.Authorization = `Bearer ${this.opts.apiKey}`;
    if (init.body !== undefined) headers['Content-Type'] = 'application/json';
    const attempts = (init.idempotent ?? method === 'GET') ? this.opts.retries + 1 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt++) {
      if (attempt > 0) await sleep(this.opts.backoffMs * 2 ** (attempt - 1) * (0.5 + Math.random()));
      let res: Response;
      try {
        res = await fetchWithTimeout(this.opts.fetch, this.opts.baseUrl.replace(/\/$/, '') + path, {
          method, headers, body: init.body === undefined ? undefined : JSON.stringify(init.body),
        }, this.opts.timeoutMs, MAX_SERVICE_BODY_BYTES);
      } catch (e) {
        lastError = e;
        continue;
      }
      // A gateway's 502, the service's own 503 (not ready), any other 5xx and 429 are the service not answering:
      // retried, and counted against the circuit. A 502 problem document about the service's upstream is an answer.
      const upstream = await upstreamFailure(res);
      if (!upstream && (res.status >= 500 || res.status === 429)) {
        lastError = new Error(`HTTP ${res.status}`);
        continue;
      }
      breaker.success();
      this.opts.onAvailability?.(true);
      if (upstream) throw new TrustServiceError(String(upstream.detail ?? `HTTP ${res.status}`), res.status, upstream.code as string, upstream);
      if (res.status === 304) return { status: 304, body: undefined as T, headers: res.headers };
      const ct = res.headers.get('Content-Type') ?? '';
      if (init.binary && res.status < 400) return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) as T, headers: res.headers };
      const body = ct.includes('json') && !ct.includes('application/jwt') ? await res.json() : await res.text();
      if (res.status >= 400) {
        const p = (typeof body === 'object' && body) ? body as Record<string, unknown> : {};
        throw new TrustServiceError(String(p.detail ?? `HTTP ${res.status}`), res.status, String(p.code ?? p.title ?? 'error'), p);
      }
      return { status: res.status, body: body as T, headers: res.headers };
    }
    breaker.failure();
    const reason = lastError instanceof Error ? lastError.message : String(lastError);
    this.opts.onAvailability?.(false, reason);
    throw new TrustServiceUnavailableError(`Trust service unavailable: ${reason}`, lastError);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
