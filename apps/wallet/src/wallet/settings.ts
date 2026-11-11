import AsyncStorage from '@react-native-async-storage/async-storage';
import { DEFAULT_API_KEY, DEFAULT_CLIENT_ID, DEFAULT_TRUST_URL } from '../config/defaults';

export type Tri = 'auto' | 'always' | 'never';
/** Through the trust service's proxy (with the standard mechanism when the proxy cannot serve), or always the standard mechanism. */
export type Via = 'proxy' | 'direct';

/**
 * Trust decisions are always made on this device, and the fallback from the proxy to the standard mechanisms is part
 * of the trust client: neither is a setting.
 */
export interface Settings {
  trustUrl: string;
  apiKey: string;
  clientId: string;
  /**
   * JWK thumbprint (RFC 7638) of the trust service's signing key, as published at /.well-known/trust-service. Empty:
   * the first key the service presents is trusted and pinned on this device (development only).
   */
  serviceKeyThumbprint: string;
  /** Issuer and authorization server metadata. */
  metadata: Via;
  /** DID documents the snapshot does not carry. */
  did: Via;
  /** CRLs the snapshot does not carry; 'none' leaves the status of their certificates unknown. */
  crl: Via | 'none';
  /** Credential status lists. */
  statusLists: Via;
  /** Ask the trust service about parties missing from the snapshot (tells it which party). */
  unknownParties: boolean;
  simulateOutage: boolean;
  dpop: 'auto' | 'never';
  walletAttestation: Tri;
  keyAttestation: Tri;
  /** Attest iso_18045_high key storage / user authentication (simulated WSCD; needed for Animo key-attestation offers). */
  highAssurance: boolean;
  /** Instances to request of each credential from issuers with batch issuance: a fresh one for each verifier. */
  batchSize: '1' | '3' | '5';
}

export const DEFAULT_SETTINGS: Settings = {
  trustUrl: DEFAULT_TRUST_URL,
  apiKey: DEFAULT_API_KEY,
  clientId: DEFAULT_CLIENT_ID,
  serviceKeyThumbprint: '',
  metadata: 'proxy',
  did: 'proxy',
  crl: 'proxy',
  statusLists: 'proxy',
  unknownParties: false,
  simulateOutage: false,
  dpop: 'auto',
  walletAttestation: 'auto',
  keyAttestation: 'auto',
  highAssurance: false,
  batchSize: '3',
};

export const SETTINGS_KEY = 'app:settings';

const oneOf = <T extends string>(allowed: readonly T[], ...candidates: unknown[]): T | undefined =>
  candidates.find((c): c is T => typeof c === 'string' && (allowed as readonly string[]).includes(c));
/** Earlier versions called the proxy 'service'. */
const renamed = (v: unknown) => (v === 'service' ? 'proxy' : v);

/**
 * Settings as stored by this or an earlier version of the app, read into the current shape. Earlier versions had one
 * `lookups` value for metadata and DIDs, `crls`, 'service' where the proxy is meant, and three settings that no longer
 * exist (`decisions`, `fallbackEnabled`, `corsRelayUrl`): a stored choice is kept under its new name, the removed
 * ones are dropped, and anything unreadable falls back to the default.
 */
export function readSettings(stored: unknown): Settings {
  const o = (stored && typeof stored === 'object' ? stored : {}) as Record<string, unknown>;
  const d = DEFAULT_SETTINGS;
  const text = (v: unknown, fallback: string) => (typeof v === 'string' ? v : fallback);
  const flag = (v: unknown, fallback: boolean) => (typeof v === 'boolean' ? v : fallback);
  const VIA = ['proxy', 'direct'] as const;
  const TRI = ['auto', 'always', 'never'] as const;
  return {
    trustUrl: text(o.trustUrl, d.trustUrl),
    apiKey: text(o.apiKey, d.apiKey),
    clientId: text(o.clientId, d.clientId),
    serviceKeyThumbprint: text(o.serviceKeyThumbprint, d.serviceKeyThumbprint),
    metadata: oneOf(VIA, o.metadata, renamed(o.lookups)) ?? d.metadata,
    did: oneOf(VIA, o.did, renamed(o.lookups)) ?? d.did,
    crl: oneOf([...VIA, 'none'] as const, o.crl, renamed(o.crls)) ?? d.crl,
    statusLists: oneOf(VIA, renamed(o.statusLists)) ?? d.statusLists,
    unknownParties: flag(o.unknownParties, d.unknownParties),
    simulateOutage: flag(o.simulateOutage, d.simulateOutage),
    dpop: oneOf(['auto', 'never'] as const, o.dpop) ?? d.dpop,
    walletAttestation: oneOf(TRI, o.walletAttestation) ?? d.walletAttestation,
    keyAttestation: oneOf(TRI, o.keyAttestation) ?? d.keyAttestation,
    highAssurance: flag(o.highAssurance, d.highAssurance),
    batchSize: oneOf(['1', '3', '5'] as const, o.batchSize) ?? d.batchSize,
  };
}

export async function loadSettings(): Promise<Settings> {
  try {
    const raw = await AsyncStorage.getItem(SETTINGS_KEY);
    return raw ? readSettings(JSON.parse(raw)) : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(s: Settings): Promise<void> {
  await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}
