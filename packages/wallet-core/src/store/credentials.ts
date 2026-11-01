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

export class KeyValueCredentialStore implements CredentialStore {
  constructor(private readonly kv: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void> }, private readonly key = 'credentials') {}
  private async all(): Promise<StoredCredential[]> {
    const raw = await this.kv.get(this.key);
    return raw ? (JSON.parse(raw) as StoredCredential[]) : [];
  }
  async list() { return (await this.all()).sort((a, b) => b.issuedAt.localeCompare(a.issuedAt)); }
  async get(id: string) { return (await this.all()).find((c) => c.id === id); }
  async save(c: StoredCredential) { const all = (await this.all()).filter((x) => x.id !== c.id); all.push(c); await this.kv.set(this.key, JSON.stringify(all)); }
  async remove(id: string) { await this.kv.set(this.key, JSON.stringify((await this.all()).filter((x) => x.id !== id))); }
}
