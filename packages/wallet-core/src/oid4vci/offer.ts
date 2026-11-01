/** OpenID4VCI 1.0 Credential Offer (§4.1) parsing: by value or by reference, any scheme. */
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

/** Accepts openid-credential-offer:// / haip-vci:// / https deep links, or raw offer JSON. */
export async function resolveCredentialOffer(input: string, f: typeof fetch): Promise<CredentialOffer> {
  const s = input.trim();
  let offer: unknown;
  if (s.startsWith('{')) offer = JSON.parse(s);
  else {
    const q = s.includes('?') ? s.slice(s.indexOf('?') + 1) : '';
    const params = new URLSearchParams(q);
    const byValue = params.get('credential_offer');
    const byRef = params.get('credential_offer_uri');
    if (byValue) offer = JSON.parse(byValue);
    else if (byRef) {
      if (!byRef.startsWith('https://') && !byRef.startsWith('http://')) throw new Error(`credential_offer_uri is not a URL: ${byRef}`);
      const r = await f(byRef, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(`Fetching credential offer failed: HTTP ${r.status}`);
      offer = await r.json();
    } else throw new Error('No credential_offer or credential_offer_uri parameter');
  }
  const o = offer as CredentialOffer;
  if (typeof o.credential_issuer !== 'string' || !Array.isArray(o.credential_configuration_ids) || o.credential_configuration_ids.length === 0) {
    throw new Error('Invalid credential offer: credential_issuer and credential_configuration_ids are required');
  }
  return o;
}
