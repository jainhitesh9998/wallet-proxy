/** Error types surfaced by the client. */

/**
 * The service answered with an error (an RFC 9457 problem): a 4xx, or a 502 saying that the party it asked on the
 * caller's behalf failed (`upstream_unavailable`, `invalid_crl`, ...). The service works; it is not counted as down.
 */
export class TrustServiceError extends Error {
  constructor(message: string, public readonly status: number, public readonly code: string, public readonly problem?: Record<string, unknown>) {
    super(message);
    this.name = 'TrustServiceError';
  }
}

/** The service could not be reached (network, timeout, 5xx, circuit open). Triggers fallback. */
export class TrustServiceUnavailableError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = 'TrustServiceUnavailableError';
  }
}

/** Integrity failure on data from the service (bad snapshot signature, wrong audience...). Never falls back silently. */
export class TrustIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrustIntegrityError';
  }
}
