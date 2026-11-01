import AsyncStorage from '@react-native-async-storage/async-storage';
import { DEFAULT_API_KEY, DEFAULT_CLIENT_ID, DEFAULT_CORS_RELAY, DEFAULT_TRUST_URL } from '../config/defaults';

export type Tri = 'auto' | 'always' | 'never';

export interface Settings {
  trustUrl: string;
  apiKey: string;
  clientId: string;
  /** web only: dev CORS relay for MOSIP hosts */
  corsRelayUrl: string;
  /** Where trust decisions are made: on this device from the signed trust list ('local'), or by the trust service. */
  decisions: 'local' | 'service';
  /** Issuer metadata and DIDs: fetched from the party itself ('direct') or through the trust service ('service'). */
  lookups: 'direct' | 'service';
  /** Ask the trust service about parties missing from the trust list (tells it which party). */
  unknownParties: boolean;
  /** CRLs the trust list does not carry: from the CA ('direct'), through the trust service relay, or not at all. */
  crls: 'direct' | 'service' | 'none';
  /** Credential status lists: from the issuer ('direct') or through the trust service relay (hides this device from the issuer). */
  statusLists: 'direct' | 'service';
  /** 'service' decisions: standards-based fallback when the trust service is unreachable. */
  fallbackEnabled: boolean;
  simulateOutage: boolean;
  dpop: 'auto' | 'never';
  walletAttestation: Tri;
  keyAttestation: Tri;
  /** Attest iso_18045_high key storage / user authentication (simulated WSCD; needed for Animo key-attestation offers). */
  highAssurance: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  trustUrl: DEFAULT_TRUST_URL,
  apiKey: DEFAULT_API_KEY,
  clientId: DEFAULT_CLIENT_ID,
  corsRelayUrl: DEFAULT_CORS_RELAY,
  decisions: 'local',
  lookups: 'direct',
  unknownParties: false,
  crls: 'direct',
  statusLists: 'direct',
  fallbackEnabled: true,
  simulateOutage: false,
  dpop: 'auto',
  walletAttestation: 'auto',
  keyAttestation: 'auto',
  highAssurance: false,
};

export const SETTINGS_KEY = 'app:settings';

export async function loadSettings(): Promise<Settings> {
  try {
    const raw = await AsyncStorage.getItem(SETTINGS_KEY);
    return raw ? { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<Settings>) } : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(s: Settings): Promise<void> {
  await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}
