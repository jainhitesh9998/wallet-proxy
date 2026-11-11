import { createNavigationContainerRef } from '@react-navigation/native';

export type RootStack = {
  Home: undefined;
  Receive: { uri?: string; nonce?: number } | undefined;
  Credential: { id: string };
  Present: { uri?: string; nonce?: number } | undefined;
  Settings: undefined;
};

export const navigationRef = createNavigationContainerRef<RootStack>();

/** Authorization-code callbacks delivered by deep link (device) or by the web /oauth-callback tab. */
type Listener = (url: string) => void;
const listeners = new Set<Listener>();
export const authCallbacks = {
  emit(url: string) { for (const l of listeners) l(url); },
  subscribe(l: Listener) { listeners.add(l); return () => { listeners.delete(l); }; },
};

export const OAUTH_CHANNEL = 'vctwallet-oauth';

/** Routes an incoming URL (QR content, deep link) to the right screen. Returns false when not recognised. */
export function routeIncoming(raw: string): boolean {
  let url = raw.trim();
  // vctwallet://receive?offer=… (development build) or exp://host:port/--/receive?offer=… (Expo Go)
  const wrapped = /^(?:vctwallet:\/\/|exps?:\/\/[^?#]*\/--\/)(receive|present)\?(?:uri|offer|request)=(.+)$/.exec(url);
  if (wrapped) url = decodeURIComponent(wrapped[2]!);
  const nonce = Date.now();
  if (/^vctwallet:\/\/oauth-callback/.test(url) || /[?&]code=.+[?&]state=|[?&]state=.+[?&]code=/.test(url) && !/credential_offer|request_uri/.test(url)) {
    authCallbacks.emit(url);
    return true;
  }
  if (!navigationRef.isReady()) return false;
  if (/^(openid-credential-offer|haip-vci):\/\//.test(url) || /[?&]credential_offer(_uri)?=/.test(url)) {
    navigationRef.navigate('Receive', { uri: url, nonce });
    return true;
  }
  if (/^(openid4vp|haip-vp|mdoc-openid4vp|eudi-openid4vp):\/\//.test(url) || /[?&](request_uri|dcql_query)=/.test(url)) {
    navigationRef.navigate('Present', { uri: url, nonce });
    return true;
  }
  return false;
}
