/** Pluggable persistence for cached responses and the offline snapshot. */
export interface CacheStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export class MemoryCacheStore implements CacheStore {
  private readonly map = new Map<string, string>();
  async get(key: string) { return this.map.get(key) ?? null; }
  async set(key: string, value: string) { this.map.set(key, value); }
  async delete(key: string) { this.map.delete(key); }
}

/** Adapts any localStorage / AsyncStorage-shaped store (sync or async). */
export interface KeyValueStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export class KeyValueCacheStore implements CacheStore {
  constructor(private readonly storage: KeyValueStorage, private readonly prefix = 'vctrust:') {}
  async get(key: string) { return (await this.storage.getItem(this.prefix + key)) ?? null; }
  async set(key: string, value: string) { await this.storage.setItem(this.prefix + key, value); }
  async delete(key: string) { await this.storage.removeItem(this.prefix + key); }
}

interface Entry<T> {
  value: T;
  storedAt: number;
  expiresAt: number;
}

/** JSON entries with freshness, served stale when the service is unavailable. */
export class ExpiringCache {
  constructor(private readonly store: CacheStore, private readonly now: () => number = Date.now) {}

  async get<T>(key: string): Promise<{ value: T; fresh: boolean; storedAt: number } | null> {
    const raw = await this.store.get(key).catch(() => null);
    if (!raw) return null;
    try {
      const e = JSON.parse(raw) as Entry<T>;
      return { value: e.value, fresh: e.expiresAt > this.now(), storedAt: e.storedAt };
    } catch {
      return null;
    }
  }

  async set<T>(key: string, value: T, ttlMs: number): Promise<void> {
    const e: Entry<T> = { value, storedAt: this.now(), expiresAt: this.now() + ttlMs };
    await this.store.set(key, JSON.stringify(e)).catch(() => undefined);
  }

  async delete(key: string): Promise<void> {
    await this.store.delete(key).catch(() => undefined);
  }
}
