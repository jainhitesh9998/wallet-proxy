/**
 * Builds the TrustClient + Wallet from the persisted settings and exposes them to the screens.
 *
 * Trust decisions are made on this device from the trust service's signed snapshot. Lookups (issuer metadata, DID
 * documents, CRLs, status lists) go through the service's proxy first and to the party itself when the proxy cannot
 * serve. While no snapshot is usable, only the trust pinned in the app (src/config/pinned.ts) decides.
 *
 * Persistence (AsyncStorage; localStorage on web):
 *   app:settings              settings
 *   wallet:credentials        credential ids; wallet:credentials:<id> one credential (KeyValueCredentialStore)
 *   wallet:key:<id>           holder / instance keys (SoftwareKeyStore, demo: not hardware protected)
 *   vctrust:*                 trust client: the signed snapshot, the pinned service key, cached documents
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { createTrustClient, KeyValueCacheStore, type SnapshotInfo, type TrustClient, type TrustStatus } from '@vctrust/trust-client';
import { KeyValueCredentialStore, SoftwareKey, SoftwareKeyStore, Wallet, WalletAttester, type InstanceKeyProvider, type StoredCredential,
  type SigningKey } from '@vctrust/wallet-core';
import { Platform } from 'react-native';
import * as Linking from 'expo-linking';
import { DEFAULT_REDIRECT_URI, DEV_HTTP_HOSTS, insecureHostsFor, OUTAGE_URL, usableServiceUrl, WALLET_PROVIDER } from '../config/defaults';
import { PINNED_ANCHORS } from '../config/pinned';
import { WALLET_PROVIDER_SIGNER_JWK, WALLET_PROVIDER_X5C } from '../config/walletProvider.generated';
import { DEFAULT_SETTINGS, loadSettings, saveSettings, SETTINGS_KEY, type Settings } from './settings';

export type { SnapshotInfo, TrustStatus };

interface WalletState {
  ready: boolean;
  settings: Settings;
  trust: TrustClient;
  wallet: Wallet;
  /** What the trust client stands on: service availability, the snapshot in use, the last refresh error. */
  trustStatus: TrustStatus;
  /** Why the last change of the service's availability happened (the trust client's own words). */
  statusReason?: string;
  /** Set when the trust service settings cannot be used; the wallet then runs without a trust service. */
  configError?: string;
  credentials: StoredCredential[];
  updateSettings(patch: Partial<Settings>): Promise<void>;
  refresh(): Promise<void>;
  /** Reads the trust client's status again (after a flow that may have refreshed the snapshot). */
  refreshTrustStatus(): Promise<TrustStatus>;
  /** Downloads and verifies the snapshot now; throws with the reason when that fails. */
  syncSnapshot(): Promise<SnapshotInfo>;
  wipe(): Promise<void>;
}

const Ctx = createContext<WalletState | null>(null);

const kv = (prefix: string) => ({
  get: (k: string) => AsyncStorage.getItem(prefix + k),
  set: (k: string, v: string) => AsyncStorage.setItem(prefix + k, v),
  remove: (k: string) => AsyncStorage.removeItem(prefix + k),
});
const INSTANCE_KEY_PREFIX = 'wallet:instance-key:';

/** The trust client's storage (snapshot, pinned service key, cached documents) survives client rebuilds and restarts. */
const trustCache = new KeyValueCacheStore(AsyncStorage, 'vctrust:');

const NO_STATUS: TrustStatus = { service: 'unknown', snapshot: null, degraded: true };

/**
 * The platform's fetch as a plain function. A browser's fetch throws "Illegal invocation" when it is called as a
 * method of another object, which is how the wallet core calls the fetch it holds.
 */
const appFetch: typeof fetch = (input, init) => globalThis.fetch(input, init);

/**
 * The wallet instance key that attestations bind, one per authorization server and kept across restarts, so an
 * attestation's cnf key does not link the user across issuers.
 */
function instanceKeys(keyStore: SoftwareKeyStore): InstanceKeyProvider {
  const keys = new Map<string, Promise<SigningKey>>();
  return (as) => {
    if (!keys.has(as)) {
      keys.set(as, (async () => {
        const id = await AsyncStorage.getItem(INSTANCE_KEY_PREFIX + as);
        const existing = id ? await keyStore.get(id) : undefined;
        if (existing) return existing;
        const k = await keyStore.create();
        await AsyncStorage.setItem(INSTANCE_KEY_PREFIX + as, k.id);
        return k;
      })().catch((e: unknown) => { keys.delete(as); throw e; }));
    }
    return keys.get(as)!;
  };
}

/** redirect_uri of authorization-code flows: back into this app (web: the /oauth-callback page). */
function appRedirectUri(): string {
  try {
    if (Platform.OS === 'web') return typeof window !== 'undefined' ? `${window.location.origin}/oauth-callback` : DEFAULT_REDIRECT_URI;
    return Linking.createURL('oauth-callback');
  } catch {
    return DEFAULT_REDIRECT_URI;
  }
}

function buildTrust(s: Settings): { trust: TrustClient; insecureHosts: string[]; configError?: string } {
  const url = (s.simulateOutage ? OUTAGE_URL : s.trustUrl).trim().replace(/\/$/, '');
  const thumbprint = s.serviceKeyThumbprint.trim();
  const create = (service: boolean, insecureHosts: string[]) => createTrustClient({
    ...(service ? { service: {
      url, clientId: s.clientId.trim(), apiKey: s.apiKey.trim() || undefined,
      // Development only without a thumbprint: the first key the service presents is trusted and pinned on this
      // device. A released app ships the thumbprint published at /.well-known/trust-service.
      keys: thumbprint ? { thumbprints: [thumbprint] } : { trustOnFirstUse: true },
    } } : {}),
    // Used only while no snapshot is usable; with a snapshot the service is the authority.
    pinned: { anchors: PINNED_ANCHORS },
    // Proxy first by default; the client itself falls back to the standard mechanism when the proxy cannot serve.
    lookups: { metadata: s.metadata, did: s.did, crl: s.crl, statusLists: s.statusLists, unknownParties: s.unknownParties },
    http: { insecureHosts, fetch: appFetch },
    storage: trustCache,
  });
  // Settings the trust client cannot work with leave the wallet without a trust service (pinned trust and the
  // standard mechanisms only), and the reason is shown; they never stop the app.
  const withoutService = (configError: string) => ({ trust: create(false, [...DEV_HTTP_HOSTS]), insecureHosts: [...DEV_HTTP_HOSTS], configError });
  if (!usableServiceUrl(url)) return withoutService('The trust service URL is not of the form https://host[:port]: the wallet runs without a trust service.');
  if (!s.clientId.trim()) return withoutService('The client id is empty (it is the audience of what the trust service signs): the wallet runs without a trust service.');
  // Plain http: the development hosts, and the trust service's own host when its URL is http. Nothing else.
  const insecureHosts = insecureHostsFor(url);
  try {
    return { trust: create(true, insecureHosts), insecureHosts };
  } catch (e) {
    return withoutService(`${(e as Error).message}: the wallet runs without a trust service.`);
  }
}

function build(s: Settings, wiKeys: InstanceKeyProvider | undefined, keyStore: SoftwareKeyStore): { trust: TrustClient; wallet: Wallet; configError?: string } {
  const { trust, insecureHosts, configError } = buildTrust(s);
  const attester = wiKeys ? new WalletAttester({
    ...WALLET_PROVIDER,
    ...(s.highAssurance ? { keyStorage: ['iso_18045_high'], userAuthentication: ['iso_18045_high'] } : {}),
    // DEMO ONLY: the wallet provider key is bundled with the app (see scripts/gen-wallet-provider.mjs).
    signingKey: SoftwareKey.fromJwk({ ...WALLET_PROVIDER_SIGNER_JWK }),
    x5c: WALLET_PROVIDER_X5C,
  }, wiKeys) : undefined;
  const wallet = new Wallet({
    trust, keyStore, credentials: new KeyValueCredentialStore(kv('wallet:')), attester, insecureHosts, fetch: appFetch,
    redirectUri: appRedirectUri(),
    dpop: s.dpop, walletAttestation: s.walletAttestation, keyAttestation: s.keyAttestation, batchSize: Number(s.batchSize),
  });
  return { trust, wallet, configError };
}

export function WalletProvider({ children }: { children: React.ReactNode }) {
  const keyStore = useMemo(() => new SoftwareKeyStore(kv('wallet:')), []);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [wiKeys, setWiKeys] = useState<InstanceKeyProvider>();
  const [ready, setReady] = useState(false);
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [trustStatus, setTrustStatus] = useState<TrustStatus>(NO_STATUS);
  const [statusReason, setStatusReason] = useState<string>();

  const built = useMemo(() => build(settings, wiKeys, keyStore), [settings, wiKeys, keyStore]);
  const { trust, wallet, configError } = built;
  const walletRef = useRef(wallet);
  walletRef.current = wallet;
  const trustRef = useRef(trust);
  trustRef.current = trust;

  const refresh = useCallback(async () => {
    setCredentials(await walletRef.current.list());
  }, []);
  const refreshTrustStatus = useCallback(async () => {
    const status = await trust.status();
    // A status read from a client that was replaced meanwhile (settings changed) is not shown.
    if (trustRef.current === trust) setTrustStatus(status);
    return status;
  }, [trust]);
  const syncSnapshot = useCallback(async () => {
    try {
      return await trust.sync();
    } finally {
      await refreshTrustStatus();
    }
  }, [trust, refreshTrustStatus]);

  useEffect(() => {
    (async () => {
      const s = await loadSettings();
      setSettings(s);
      setWiKeys(() => instanceKeys(keyStore));
      setReady(true);
    })();
  }, [keyStore]);

  // The status of the current client: read now, again whenever the client sees the service come up or go down, and
  // after the first snapshot refresh.
  useEffect(() => {
    if (!ready) return;
    let cancelled = false;
    setStatusReason(undefined);
    const off = trust.onStatusChange((e) => {
      if (cancelled) return;
      setStatusReason(e.reason);
      void refreshTrustStatus();
    });
    (async () => {
      await refresh();
      await refreshTrustStatus();
      if ((await trust.status()).service === 'unconfigured') return;
      await trust.sync().catch(() => undefined);   // offline: the status says so, with the reason
      if (!cancelled) await refreshTrustStatus();
    })().catch(() => undefined);
    return () => {
      cancelled = true;
      off();
    };
  }, [ready, trust, refresh, refreshTrustStatus]);

  const updateSettings = useCallback(async (patch: Partial<Settings>) => {
    const next = { ...settings, ...patch };
    await saveSettings(next);
    setSettings(next);
  }, [settings]);

  const wipe = useCallback(async () => {
    const keys = await AsyncStorage.getAllKeys();
    await AsyncStorage.multiRemove(keys.filter((k) => k !== SETTINGS_KEY));
    // New instance keys also mean a new trust client: the old one holds the wiped snapshot in memory.
    setWiKeys(() => instanceKeys(keyStore));
    setCredentials([]);
    setTrustStatus(NO_STATUS);
  }, [keyStore]);

  const value: WalletState = { ready, settings, trust, wallet, trustStatus, statusReason, configError, credentials,
    updateSettings, refresh, refreshTrustStatus, syncSnapshot, wipe };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWallet(): WalletState {
  const v = useContext(Ctx);
  if (!v) throw new Error('useWallet outside WalletProvider');
  return v;
}
