import { bytes } from '@vctrust/trust-client/primitives';
import type { SigningKey } from './keys.js';

const enc = (o: unknown) => bytes.base64UrlEncode(bytes.utf8Encode(JSON.stringify(o)));

/** Signs a compact JWS with an ES256 key. */
export async function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>, key: SigningKey): Promise<string> {
  const input = `${enc({ alg: key.alg, ...header })}.${enc(payload)}`;
  const sig = await key.sign(bytes.utf8Encode(input));
  return `${input}.${bytes.base64UrlEncode(sig)}`;
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);

export function randomId(n = 16): string {
  return bytes.base64UrlEncode(bytes.randomBytes(n));
}
