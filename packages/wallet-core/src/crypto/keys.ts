/** Holder / instance keys. Software P-256 keys by default; the interface allows hardware-backed stores. */
import { p256 } from '@noble/curves/nist.js';
import type { Jwk } from '@vctrust/trust-client';
import { bytes, publicKeyToJwk, jwkThumbprint } from '@vctrust/trust-client/primitives';

export interface SigningKey {
  readonly id: string;
  readonly alg: 'ES256';
  /** Public JWK (no private members). */
  readonly publicJwk: Jwk;
  /** Signs the message (SHA-256 applied internally); returns raw r||s. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface KeyStore {
  create(): Promise<SigningKey>;
  get(id: string): Promise<SigningKey | undefined>;
  /** Removes a key no credential uses any more (optional; hardware stores may manage this themselves). */
  delete?(id: string): Promise<void>;
}

export class SoftwareKey implements SigningKey {
  readonly alg = 'ES256' as const;
  readonly publicJwk: Jwk;
  readonly id: string;

  constructor(private readonly secret: Uint8Array) {
    this.publicJwk = publicKeyToJwk({ kty: 'EC', crv: 'P-256', point: p256.getPublicKey(secret, false) });
    this.id = jwkThumbprint(this.publicJwk);
  }

  static generate(): SoftwareKey {
    return new SoftwareKey(p256.utils.randomSecretKey());
  }

  static fromJwk(jwk: Jwk): SoftwareKey {
    if (!jwk.d) throw new Error('Private JWK required');
    return new SoftwareKey(bytes.base64UrlDecode(jwk.d));
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return p256.sign(data, this.secret, { prehash: true, format: 'compact' });
  }

  /** ECDH shared secret (x coordinate) with a peer public key. */
  ecdh(peerUncompressed: Uint8Array): Uint8Array {
    return p256.getSharedSecret(this.secret, peerUncompressed).subarray(1);
  }

  exportPrivateJwk(): Jwk {
    return { ...this.publicJwk, d: bytes.base64UrlEncode(this.secret) };
  }
}

/** Key store persisting private JWKs in a key-value store (demo wallet; not hardware protected). */
export class SoftwareKeyStore implements KeyStore {
  private readonly keys = new Map<string, SoftwareKey>();

  constructor(private readonly persist?: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void>; remove?(k: string): Promise<void> }) {}

  async create(): Promise<SigningKey> {
    const k = SoftwareKey.generate();
    this.keys.set(k.id, k);
    await this.persist?.set(`key:${k.id}`, JSON.stringify(k.exportPrivateJwk()));
    return k;
  }

  async delete(id: string): Promise<void> {
    this.keys.delete(id);
    await this.persist?.remove?.(`key:${id}`);
  }

  async get(id: string): Promise<SigningKey | undefined> {
    const k = this.keys.get(id);
    if (k) return k;
    const raw = await this.persist?.get(`key:${id}`);
    if (!raw) return undefined;
    const loaded = SoftwareKey.fromJwk(JSON.parse(raw) as Jwk);
    this.keys.set(id, loaded);
    return loaded;
  }
}
