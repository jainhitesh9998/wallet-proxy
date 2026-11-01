/** Circuit breaker: after N consecutive failures the circuit opens for a cool-down, then lets one probe through. */
export type CircuitState = 'closed' | 'open' | 'half-open';

export class CircuitBreaker {
  private failures = 0;
  private openedAt = 0;
  private _state: CircuitState = 'closed';

  constructor(private readonly failureThreshold = 3, private readonly resetAfterMs = 30_000, private readonly now: () => number = Date.now) {}

  get state(): CircuitState {
    if (this._state === 'open' && this.now() - this.openedAt >= this.resetAfterMs) this._state = 'half-open';
    return this._state;
  }

  canRequest(): boolean {
    return this.state !== 'open';
  }

  success(): void {
    this.failures = 0;
    this._state = 'closed';
  }

  failure(): void {
    this.failures++;
    if (this._state === 'half-open' || this.failures >= this.failureThreshold) {
      this._state = 'open';
      this.openedAt = this.now();
    }
  }

  reset(): void {
    this.success();
  }
}
