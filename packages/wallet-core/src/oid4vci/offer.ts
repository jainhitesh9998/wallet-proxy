/** OpenID4VCI 1.0 Credential Offer (§4.1): by value or by reference, from any URL scheme that carries the parameters. */
import { requireHttps } from '../net.js';

export interface TxCode {
  input_mode?: 'numeric' | 'text';
  length?: number;
  description?: string;
}

export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants?: {
    authorization_code?: { issuer_state?: string; authorization_server?: string };
    'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: { 'pre-authorized_code': string; tx_code?: TxCode; authorization_server?: string };
  };
}

export const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * Accepts an openid-credential-offer:// (or haip-vci://, https) link, or the offer JSON itself. An offer by reference
 * is fetched over https; the offer names an https issuer and at least one configuration.
 */
export async function resolveCredentialOffer(input: string, f: typeof fetch, insecureHosts: readonly string[] = []): Promise<CredentialOffer> {
  const s = input.trim();
  let offer: unknown;
  if (s.startsWith('{')) offer = JSON.parse(s);
  else {
    const params = new URLSearchParams(s.includes('?') ? s.slice(s.indexOf('?') + 1) : '');
    const byValue = params.get('credential_offer');
    const byRef = params.get('credential_offer_uri');
    // §4.1: exactly one of the two.
    if ((byValue === null) === (byRef === null)) throw new Error('A credential offer link carries either credential_offer or credential_offer_uri');
    if (byValue !== null) offer = JSON.parse(byValue);
    else {
      const r = await f(requireHttps(byRef, 'credential_offer_uri', insecureHosts), { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(`Fetching the credential offer failed: HTTP ${r.status}`);
      offer = await r.json();
    }
  }
  if (!isObject(offer) || typeof offer.credential_issuer !== 'string' || !Array.isArray(offer.credential_configuration_ids)
    || offer.credential_configuration_ids.length === 0 || !offer.credential_configuration_ids.every((id) => typeof id === 'string')) {
    throw new Error('Invalid credential offer: credential_issuer and credential_configuration_ids are required');
  }
  requireHttps(offer.credential_issuer, 'credential_issuer', insecureHosts);
  const pre = isObject(offer.grants) ? offer.grants[PRE_AUTH] : undefined;
  if (pre !== undefined && (!isObject(pre) || typeof pre['pre-authorized_code'] !== 'string')) throw new Error('Invalid credential offer: the pre-authorized code grant has no pre-authorized_code');
  return offer as unknown as CredentialOffer;
}
