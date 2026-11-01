/**
 * Builds the TrustClient + Wallet from the persisted settings and exposes them to the screens.
 * Persistence (AsyncStorage; localStorage on web):
 *   app:settings              settings
 *   wallet:credentials        credentials (KeyValueCredentialStore)
 *   wallet:key:<id>           holder / instance keys (SoftwareKeyStore, demo: not hardware protected)
 *   vctrust:*                 trust-client cache incl. the signed offline snapshot and pinned service key
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { createTrustClient, KeyValueCacheStore, type ServiceStatus, type TrustClient } from '@vctrust/trust-client';
import { KeyValueCredentialStore, SoftwareKey, SoftwareKeyStore, Wallet, WalletAttester, type StoredCredential, type SigningKey } from '@vctrust/wallet-core';
import { Platform } from 'react-native';
import * as Linking from 'expo-linking';
import { DEFAULT_REDIRECT_URI, MOSIP_REGISTRATIONS, OUTAGE_URL, WALLET_PROVIDER } from '../config/defaults';
import { WALLET_PROVIDER_SIGNER_JWK, WALLET_PROVIDER_X5C } from '../config/walletProvider.generated';
import { createAppFetch } from './net';
import { DEFAULT_SETTINGS, loadSettings, saveSettings, SETTINGS_KEY, type Settings } from './settings';

export interface SnapshotInfo {
  version: number;
  issuedAt: string;
  expiresAt: string;
  stale: boolean;
  entities: number;
  anchors: number;
}

interface WalletState {
  ready: boolean;
  settings: Settings;
  trust: TrustClient;
  wallet: Wallet;
  status: ServiceStatus;
  statusReason?: string;
  credentials: StoredCredential[];
  snapshot: SnapshotInfo | null;
  updateSettings(patch: Partial<Settings>): Promise<void>;
  refresh(): Promise<void>;
  syncSnapshot(): Promise<SnapshotInfo | null>;
  refreshSnapshotInfo(): Promise<SnapshotInfo | null>;
  wipe(): Promise<void>;
}

const Ctx = createContext<WalletState | null>(null);

const kv = (prefix: string) => ({
  get: (k: string) => AsyncStorage.getItem(prefix + k),
  set: (k: string, v: string) => AsyncStorage.setItem(prefix + k, v),
});
const INSTANCE_KEY = 'wallet:instance-key-id';

/** The trust-client cache (snapshot, pinned service key, cached metadata) survives client rebuilds and restarts. */
const trustCache = new KeyValueCacheStore(AsyncStorage, 'vctrust:');

async function instanceKey(keyStore: SoftwareKeyStore): Promise<SigningKey> {
  const id = await AsyncStorage.getItem(INSTANCE_KEY);
  const existing = id ? await keyStore.get(id) : undefined;
  if (existing) return existing;
  const k = await keyStore.create();
  await AsyncStorage.setItem(INSTANCE_KEY, k.id);
  return k;
}

/** redirect_uri for issuers without a registration: back into this app (web: the /oauth-callback page). */
function appRedirectUri(): string {
  try {
    if (Platform.OS === 'web') return typeof window !== 'undefined' ? `${window.location.origin}/oauth-callback` : DEFAULT_REDIRECT_URI;
    return Linking.createURL('oauth-callback');
  } catch {
    return DEFAULT_REDIRECT_URI;
  }
}

function build(s: Settings, wiKey: SigningKey | undefined, keyStore: SoftwareKeyStore): { trust: TrustClient; wallet: Wallet } {
  const appFetch = createAppFetch(s.corsRelayUrl);
  const trust = createTrustClient({
    baseUrl: s.simulateOutage ? OUTAGE_URL : s.trustUrl,
    apiKey: s.apiKey,
    clientId: s.clientId,
    cache: trustCache,
    fetch: appFetch,
    timeoutMs: s.simulateOutage ? 1500 : 6000,
    // Demo: pin the trust service's snapshot signing key on first use (production: ship its JWK thumbprint).
    serviceKeys: { trustOnFirstUse: true },
    fallback: { enabled: s.fallbackEnabled, useSnapshot: true },
  });
  const attester = wiKey ? new WalletAttester({
    ...WALLET_PROVIDER,
    ...(s.highAssurance ? { keyStorage: ['iso_18045_high'], userAuthentication: ['iso_18045_high'] } : {}),
    // DEMO ONLY: the wallet provider key is bundled with the app (see scripts/gen-wallet-provider.mjs).
    signingKey: SoftwareKey.fromJwk({ ...WALLET_PROVIDER_SIGNER_JWK }),
    x5c: WALLET_PROVIDER_X5C,
  }, wiKey) : undefined;
  const wallet = new Wallet({
    trust, keyStore, credentials: new KeyValueCredentialStore(kv('wallet:')), fetch: appFetch, attester,
    redirectUri: appRedirectUri(), registrations: MOSIP_REGISTRATIONS,
    dpop: s.dpop, walletAttestation: s.walletAttestation, keyAttestation: s.keyAttestation,
  });
  return { trust, wallet };
}

function snapshotInfo(d: Awaited<ReturnType<TrustClient['snapshots']['current']>>): SnapshotInfo | null {
  return d ? { version: d.version, issuedAt: d.issuedAt.toISOString(), expiresAt: d.expiresAt.toISOString(), stale: d.stale,
    entities: d.entities.length, anchors: d.anchors.length } : null;
}

export function WalletProvider({ children }: { children: React.ReactNode }) {
  const keyStore = useMemo(() => new SoftwareKeyStore(kv('wallet:')), []);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [wiKey, setWiKey] = useState<SigningKey>();
  const [ready, setReady] = useState(false);
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [snapshot, setSnapshot] = useState<SnapshotInfo | null>(null);
  const [status, setStatus] = useState<{ status: ServiceStatus; reason?: string }>({ status: 'unknown' });

  const built = useMemo(() => build(settings, wiKey, keyStore), [settings, wiKey, keyStore]);
  const { trust, wallet } = built;
  const walletRef = useRef(wallet);
  walletRef.current = wallet;

  const refresh = useCallback(async () => {
    setCredentials(await walletRef.current.list());
  }, []);
  const refreshSnapshotInfo = useCallback(async () => {
    const info = snapshotInfo(await trust.snapshots.current().catch(() => null));
    setSnapshot(info);
    return info;
  }, [trust]);
  const syncSnapshot = useCallback(async () => {
    await trust.syncSnapshot();
    return refreshSnapshotInfo();
  }, [trust, refreshSnapshotInfo]);

  useEffect(() => {
    (async () => {
      const s = await loadSettings();
      const k = await instanceKey(keyStore);
      setSettings(s);
      setWiKey(k);
      setReady(true);
    })();
  }, [keyStore]);

  // Track trust-service availability of the current client; probe it once, then keep the snapshot fresh.
  useEffect(() => {
    if (!ready) return;
    setStatus({ status: trust.status });
    const off = trust.onStatusChange((e) => setStatus({ status: e.status, reason: e.reason }));
    let cancelled = false;
    (async () => {
      await refresh();
      await refreshSnapshotInfo();
      try {
        await trust.discovery();
        if (!cancelled) await syncSnapshot();
      } catch {
        /* offline: status listener reports it */
      }
      if (!cancelled) setStatus({ status: trust.status });
    })();
    return () => {
      cancelled = true;
      off();
    };
  }, [ready, trust, refresh, refreshSnapshotInfo, syncSnapshot]);

  const updateSettings = useCallback(async (patch: Partial<Settings>) => {
    const next = { ...settings, ...patch };
    await saveSettings(next);
    setSettings(next);
  }, [settings]);

  const wipe = useCallback(async () => {
    const keys = await AsyncStorage.getAllKeys();
    await AsyncStorage.multiRemove(keys.filter((k) => k !== SETTINGS_KEY));
    const k = await instanceKey(keyStore);
    setWiKey(k);
    setCredentials([]);
    setSnapshot(null);
  }, [keyStore]);

  const value: WalletState = { ready, settings, trust, wallet, status: status.status, statusReason: status.reason, credentials, snapshot,
    updateSettings, refresh, syncSnapshot, refreshSnapshotInfo, wipe };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWallet(): WalletState {
  const v = useContext(Ctx);
  if (!v) throw new Error('useWallet outside WalletProvider');
  return v;
}
