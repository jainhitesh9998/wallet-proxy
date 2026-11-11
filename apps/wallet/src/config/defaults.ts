import Constants from 'expo-constants';
import { Platform } from 'react-native';

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
/** Used by "Simulate trust-service outage": nothing listens here, so every call to the service fails at once. */
export const OUTAGE_URL = 'http://127.0.0.1:9';

/**
 * Development only: hosts the wallet and the trust client may reach over plain http. They are this machine (the
 * reference issuer and verifier of test-ecosystem/ run on http://localhost) and the Android emulator's name for it.
 * Every other host must be https.
 */
export const DEV_HTTP_HOSTS: readonly string[] = ['localhost', '127.0.0.1', '10.0.2.2'];

/**
 * A trust service URL this app accepts: http(s)://host[:port][/path], with no userinfo, so that the host the URL
 * names is the host that is contacted (and, for http, the one host added to the plain-http hosts).
 */
const SERVICE_URL = /^(https?):\/\/([^/:?#@\\\s[\]]+)(?::\d{1,5})?(?:[/?#]|$)/;

export function usableServiceUrl(url: string): boolean {
  return SERVICE_URL.test(url);
}

/** The plain-http hosts for a trust service URL: the development hosts, and the service's own host when its URL is http. */
export function insecureHostsFor(trustUrl: string): string[] {
  const m = SERVICE_URL.exec(trustUrl);
  return [...new Set([...(m?.[1] === 'http' ? [m[2]!] : []), ...DEV_HTTP_HOSTS])];
}

/** Wallet provider identity (matches packages/wallet-core/test/wallet-provider.ts). */
export const WALLET_PROVIDER = {
  issuer: 'https://wallet.vctrust.dev',
  clientId: 'https://wallet.vctrust.dev',
  walletName: 'VC Trust Demo Wallet',
  walletLink: 'https://wallet.vctrust.dev',
};

/** Redirect for authorization-code flows when the app cannot name one of its own. */
export const DEFAULT_REDIRECT_URI = 'https://wallet.vctrust.dev/cb';

/** The reference issuer and verifier of test-ecosystem/ (scripts/dev-up.sh starts them and lists them in the trust service). */
export const REFERENCE_ISSUER = 'http://localhost:8791';
export const REFERENCE_VERIFIER = 'http://localhost:8792';
export const ANIMO_PLAYGROUND = 'https://playground.animo.id';

export interface DemoIssuer {
  id: string;
  name: string;
  url: string;
  description: string;
  /** Development: the issuer's admin API that creates a credential offer (POST {configurationIds, grant}). */
  offerApi?: string;
  /** Credential configurations the offer API can be asked for. */
  configurations?: { id: string; label: string }[];
  /** A page where the user creates an offer themself and copies its link. */
  offerPage?: string;
}

/** The issuers the Receive screen offers to start from. Any other issuer works through a pasted or scanned offer. */
export const DEMO_ISSUERS: DemoIssuer[] = [
  {
    id: 'reference', name: 'Reference issuer', url: REFERENCE_ISSUER,
    description: 'The local reference issuer (test-ecosystem/). It runs on this machine over plain http: development only.',
    offerApi: `${REFERENCE_ISSUER}/api/offers`,
    configurations: [
      { id: 'UniversityDegree_ldp_vc_ecdsa-rdfc-2019', label: 'University degree · ldp_vc · ecdsa-rdfc-2019' },
      { id: 'UniversityDegree_ldp_vc_eddsa-rdfc-2022', label: 'University degree · ldp_vc · eddsa-rdfc-2022' },
      { id: 'mDL_mso_mdoc', label: 'Driving licence · mso_mdoc' },
      { id: 'Identity_dc_sd_jwt', label: 'Identity · dc+sd-jwt' },
    ],
  },
  {
    id: 'animo', name: 'Animo playground', url: ANIMO_PLAYGROUND,
    description: 'Create an offer on the playground (Issue tab), copy its link and paste it on the Offer tab.',
    offerPage: ANIMO_PLAYGROUND,
  },
];
