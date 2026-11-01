import Constants from 'expo-constants';
import { Platform } from 'react-native';
import type { IssuerClientRegistration } from '@vctrust/wallet-core';

/** Host of the machine running the Expo dev server (the phone reaches the trust server on the same LAN IP). */
function devHost(): string | undefined {
  const hostUri = Constants.expoConfig?.hostUri ?? (Constants as unknown as { manifest2?: { extra?: { expoGo?: { debuggerHost?: string } } } })
    .manifest2?.extra?.expoGo?.debuggerHost;
  const host = hostUri?.split(':')[0];
  return host && host !== 'localhost' && host !== '127.0.0.1' ? host : undefined;
}

export const DEFAULT_TRUST_URL = Platform.OS === 'web' ? 'http://localhost:8090' : `http://${devHost() ?? 'localhost'}:8090`;
export const DEFAULT_API_KEY = 'demo-wallet-key';
export const DEFAULT_CLIENT_ID = 'demo-wallet';
export const DEFAULT_CORS_RELAY = 'http://localhost:8787';
/** Used by "Simulate trust-service outage": nothing listens here, so every call fails fast and the client falls back. */
export const OUTAGE_URL = 'http://127.0.0.1:9';

/** Wallet provider identity (matches packages/wallet-core/test/wallet-provider.ts). */
export const WALLET_PROVIDER = {
  issuer: 'https://wallet.vctrust.dev',
  clientId: 'https://wallet.vctrust.dev',
  walletName: 'VC Trust Demo Wallet',
  walletLink: 'https://wallet.vctrust.dev',
};

/** Default redirect for authorization-code flows at issuers without a registration. */
export const DEFAULT_REDIRECT_URI = 'https://wallet.vctrust.dev/cb';

/** MOSIP's registered redirect (the Inji app's scheme). It cannot return to a web page, so web users paste it. */
export const MOSIP_REDIRECT = 'io.mosip.residentapp.inji://oauthredirect';
const mosip = (clientId: string, mimotoIssuer: string): IssuerClientRegistration => ({ clientId, redirectUri: MOSIP_REDIRECT,
  tokenEndpoint: `https://api.collab.mosip.net/v1/mimoto/get-token/${mimotoIssuer}`, extraAuthorizeParams: { ui_locales: 'en' } });

/** MOSIP collab issuers: pre-registered Mimoto clients with the Mimoto token proxy (as in mosip.live.test.ts). */
export const MOSIP_REGISTRATIONS: Record<string, IssuerClientRegistration> = {
  'https://injicertify-farmer.collab.mosip.net': mosip('mpartner-default-mimoto-land-oidc', 'Farmer'),
  'https://injicertify-landregistry.collab.mosip.net': mosip('mpartner-default-mimoto-land-oidc', 'Land'),
  'https://injicertify-mdl.collab.mosip.net': mosip('mpartner-default-mimoto-mdl-oidc', 'MockMdl'),
};
