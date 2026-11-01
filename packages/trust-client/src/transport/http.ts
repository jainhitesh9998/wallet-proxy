/** HTTP transport to the trust service: timeouts, retries with backoff, circuit breaker, problem details. */
import { CircuitBreaker } from './circuit.js';
import { TrustServiceError, TrustServiceUnavailableError } from '../errors.js';
import { fetchWithTimeout } from '../did/resolver.js';

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

  async request<T>(method: 'GET' | 'POST', path: string, init: { body?: unknown; accept?: string; headers?: Record<string, string>; idempotent?: boolean } = {}): Promise<TransportResponse<T>> {
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
        }, this.opts.timeoutMs);
      } catch (e) {
        lastError = e;
        continue;
      }
      if (res.status >= 500 || res.status === 429) {
        lastError = new Error(`HTTP ${res.status}`);
        continue;
      }
      breaker.success();
      this.opts.onAvailability?.(true);
      if (res.status === 304) return { status: 304, body: undefined as T, headers: res.headers };
      const ct = res.headers.get('Content-Type') ?? '';
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
