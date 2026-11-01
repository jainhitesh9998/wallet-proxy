/** Credential storage. The demo app persists to AsyncStorage / localStorage through the KeyValue adapter. */
import type { IssuedCredential } from '../oid4vci/client.js';

export type StoredCredential = IssuedCredential & { label?: string };

export interface CredentialStore {
  list(): Promise<StoredCredential[]>;
  get(id: string): Promise<StoredCredential | undefined>;
  save(c: StoredCredential): Promise<void>;
  remove(id: string): Promise<void>;
}

export class MemoryCredentialStore implements CredentialStore {
  private readonly items = new Map<string, StoredCredential>();
  async list() { return [...this.items.values()].sort((a, b) => b.issuedAt.localeCompare(a.issuedAt)); }
  async get(id: string) { return this.items.get(id); }
  async save(c: StoredCredential) { this.items.set(c.id, c); }
  async remove(id: string) { this.items.delete(id); }
}

/**
 * One entry per credential ({@code <key>:<id>}) plus an index of ids under {@code <key>}, so no entry grows with the
 * wallet (Android's AsyncStorage reads a row through a 2 MB window). The older layout — every credential in the
 * index entry — is migrated on first access.
 */
export class KeyValueCredentialStore implements CredentialStore {
  constructor(private readonly kv: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void>; remove?(k: string): Promise<void> },
              private readonly key = 'credentials') {}

  private async ids(): Promise<string[]> {
    const raw = await this.kv.get(this.key);
    const index = raw ? (JSON.parse(raw) as Array<string | StoredCredential>) : [];
    if (index.every((x) => typeof x === 'string')) return index as string[];
    const legacy = index.filter((x): x is StoredCredential => typeof x !== 'string');
    for (const c of legacy) await this.kv.set(this.entry(c.id), JSON.stringify(c));
    const ids = index.map((x) => (typeof x === 'string' ? x : x.id));
    await this.kv.set(this.key, JSON.stringify(ids));
    return ids;
  }

  private entry(id: string) { return `${this.key}:${id}`; }

  async list() {
    const out: StoredCredential[] = [];
    for (const id of await this.ids()) {
      const raw = await this.kv.get(this.entry(id));
      if (raw) out.push(JSON.parse(raw) as StoredCredential);
    }
    return out.sort((a, b) => b.issuedAt.localeCompare(a.issuedAt));
  }

  async get(id: string) {
    if (!(await this.ids()).includes(id)) return undefined;
    const raw = await this.kv.get(this.entry(id));
    return raw ? (JSON.parse(raw) as StoredCredential) : undefined;
  }

  async save(c: StoredCredential) {
    await this.kv.set(this.entry(c.id), JSON.stringify(c));
    const ids = await this.ids();
    if (!ids.includes(c.id)) await this.kv.set(this.key, JSON.stringify([...ids, c.id]));
  }

  async remove(id: string) {
    await this.kv.set(this.key, JSON.stringify((await this.ids()).filter((x) => x !== id)));
    if (this.kv.remove) await this.kv.remove(this.entry(id));
    else await this.kv.set(this.entry(id), '');
  }
}
