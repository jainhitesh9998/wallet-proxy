/**
 * When the trust snapshot is refreshed. Decisions do not wait for the service while a snapshot is usable: a refresh
 * that is due runs in the background, one at a time, and a failed one is retried after an interval, not on every
 * request.
 */
import type { Logger } from '../client.js';
import { snapshotInfo, type SnapshotData, type SnapshotInfo, type SnapshotManager } from './snapshot.js';

export interface RefreshOptions {
  /** Whether a trust service is configured; without one the held snapshot is all there is. */
  service: boolean;
  /** Refresh when older than this. */
  refreshMs: number;
  /** Wait this long after a failed refresh before trying again. */
  retryMs: number;
  now: () => number;
  logger?: Logger;
  /** Called when another snapshot comes into use, or a refresh starts or stops failing. */
  onChange: (reason: string) => void;
}

export class SnapshotRefresher {
  /** Why the last refresh failed; cleared by a successful one. */
  lastSyncError: string | undefined;
  /** id of the snapshot last taken into use, to tell a listener when it changes */
  private snapshotInUse: string | undefined;
  private refreshing: Promise<void> | null = null;
  private nextSyncAt = 0;

  constructor(private readonly snapshots: SnapshotManager, private readonly opts: RefreshOptions) {}

  /** Downloads and verifies the snapshot now; throws when that fails (the previous snapshot stays in use). */
  async sync(): Promise<SnapshotInfo> {
    try {
      const s = await this.snapshots.sync();
      const changed = this.lastSyncError !== undefined || s.id !== this.snapshotInUse;
      this.lastSyncError = undefined;
      this.snapshotInUse = s.id;
      this.nextSyncAt = this.opts.now() + this.opts.refreshMs;
      if (changed) this.opts.onChange('snapshot');
      return snapshotInfo(s);
    } catch (e) {
      const message = (e as Error).message;
      const changed = message !== this.lastSyncError;
      this.lastSyncError = message;
      this.nextSyncAt = this.opts.now() + this.opts.retryMs;
      if (changed) this.opts.onChange(message);
      throw e;
    }
  }

  /** One refresh at a time, never throwing; callers that need its outcome await the same promise. */
  refresh(): Promise<void> {
    this.refreshing ??= this.sync().then(() => undefined, (e: unknown) => {
      this.opts.logger?.warn?.(`snapshot refresh failed: ${(e as Error).message}`);
    }).finally(() => { this.refreshing = null; });
    return this.refreshing;
  }

  /**
   * The snapshot to decide from. A usable one is returned at once and refreshed in the background when due. With
   * none, the caller waits for the refresh in flight (every caller the same one), or for a new one when the retry
   * interval allows; after that it proceeds without.
   */
  async snapshot(): Promise<SnapshotData | null> {
    const current = await this.snapshots.current().catch(() => null);
    if (!this.opts.service) return current;
    const due = this.opts.now() >= this.nextSyncAt;
    if (current) {
      if (due || this.refreshing) void this.refresh();
      return current;
    }
    if (this.refreshing || due) await this.refresh();
    return this.snapshots.current().catch(() => null);
  }
}
