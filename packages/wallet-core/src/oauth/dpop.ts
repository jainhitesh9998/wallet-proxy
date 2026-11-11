/**
 * DPoP (RFC 9449): proof JWTs bound to the HTTP method and URL, server nonces tracked per origin
 * (authorization server and credential issuer nonces are distinct), and the use_dpop_nonce retry dance
 * for both AS (400 JSON error) and resource servers (401 WWW-Authenticate).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytes } from '@vctrust/trust-client/primitives';
import { nowSeconds, randomId, signJwt } from '../crypto/jwt.js';
import type { SigningKey } from '../crypto/keys.js';

export class Dpop {
  private readonly nonces = new Map<string, string>();

  constructor(readonly key: SigningKey) {}

  static htu(url: string): string {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  }

  async proof(method: string, url: string, accessToken?: string): Promise<string> {
    const payload: Record<string, unknown> = { jti: randomId(), htm: method, htu: Dpop.htu(url), iat: nowSeconds() };
    if (accessToken) payload.ath = bytes.base64UrlEncode(sha256(bytes.utf8Encode(accessToken)));
    const nonce = this.nonces.get(new URL(url).origin + new URL(url).pathname) ?? this.nonces.get(new URL(url).origin);
    if (nonce) payload.nonce = nonce;
    return signJwt({ typ: 'dpop+jwt', jwk: this.key.publicJwk }, payload, this.key);
  }

  /** Records a DPoP-Nonce from a response (scoped to the origin of the server that issued it). */
  remember(url: string, res: Response): boolean {
    const n = res.headers.get('DPoP-Nonce');
    if (!n) return false;
    const changed = this.nonces.get(new URL(url).origin) !== n;
    this.nonces.set(new URL(url).origin, n);
    return changed;
  }

  /** Sets a nonce explicitly, e.g. the DPoP-Nonce returned by the Nonce Endpoint for the Credential Endpoint. */
  setNonce(url: string, nonce: string): void {
    this.nonces.set(new URL(url).origin, nonce);
  }

  /** Executes a request with a DPoP proof, retrying once when the server demands a (new) nonce. */
  async fetch(f: typeof fetch, url: string, init: RequestInit & { method: string }, accessToken?: string): Promise<Response> {
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers = new Headers(init.headers);
      headers.set('DPoP', await this.proof(init.method, url, accessToken));
      if (accessToken) headers.set('Authorization', `DPoP ${accessToken}`);
      const res = await f(url, { ...init, headers });
      const changed = this.remember(url, res);
      if (attempt === 0 && changed && (await Dpop.demandsNonce(res))) continue;
      return res;
    }
    throw new Error('unreachable');
  }

  static async demandsNonce(res: Response): Promise<boolean> {
    if (res.status === 401 && (res.headers.get('WWW-Authenticate') ?? '').includes('use_dpop_nonce')) return true;
    if (res.status === 400) {
      try {
        const body = (await res.clone().json()) as { error?: string };
        return body.error === 'use_dpop_nonce';
      } catch {
        return false;
      }
    }
    return false;
  }
}
