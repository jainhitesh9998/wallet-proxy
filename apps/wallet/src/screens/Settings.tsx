import React, { useEffect, useState } from 'react';
import { Platform, ScrollView, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { DEFAULT_SETTINGS, type Tri } from '../wallet/settings';
import { shortDate } from '../wallet/display';
import { TrustStatusPill } from '../components/StatusPill';
import { Button, colors, ErrorBox, Field, Info, KV, s, Section, Segmented, Toggle } from '../components/ui';

const TRI: readonly Tri[] = ['auto', 'always', 'never'];

export default function SettingsScreen({ navigation }: NativeStackScreenProps<RootStack, 'Settings'>) {
  const { settings, updateSettings, snapshot, syncSnapshot, refreshSnapshotInfo, wipe, status } = useWallet();
  const [form, setForm] = useState({ trustUrl: settings.trustUrl, apiKey: settings.apiKey, clientId: settings.clientId, corsRelayUrl: settings.corsRelayUrl });
  const [msg, setMsg] = useState<string>();
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const [confirmWipe, setConfirmWipe] = useState(false);

  useEffect(() => { refreshSnapshotInfo(); }, [refreshSnapshotInfo]);
  useEffect(() => {
    setForm({ trustUrl: settings.trustUrl, apiKey: settings.apiKey, clientId: settings.clientId, corsRelayUrl: settings.corsRelayUrl });
  }, [settings.trustUrl, settings.apiKey, settings.clientId, settings.corsRelayUrl]);

  const run = async (name: string, f: () => Promise<string | undefined>) => {
    setBusy(name); setErr(undefined); setMsg(undefined);
    try { setMsg(await f()); } catch (e) { setErr((e as Error).message); } finally { setBusy(undefined); }
  };

  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled" testID="settings-screen">
      <Section title="Trust service" right={<TrustStatusPill testID="settings-trust-status" />}>
        <Field testID="settings-trust-url" label="Trust service URL" value={form.trustUrl} onChangeText={(t) => setForm({ ...form, trustUrl: t })} keyboardType="url"
          placeholder="http://192.168.1.10:8090" />
        {Platform.OS !== 'web' ? <Info message="On a phone use your computer's LAN IP (not localhost)." /> : null}
        <Field testID="settings-api-key" label="API key" value={form.apiKey} onChangeText={(t) => setForm({ ...form, apiKey: t })} />
        <Field testID="settings-client-id" label="Client id (snapshot audience)" value={form.clientId} onChangeText={(t) => setForm({ ...form, clientId: t })} />
        {Platform.OS === 'web' ? (
          <Field testID="settings-cors-relay" label="Dev CORS relay for MOSIP hosts (web only; node dev-cors-proxy.mjs)" value={form.corsRelayUrl}
            onChangeText={(t) => setForm({ ...form, corsRelayUrl: t })} />
        ) : null}
        <View style={{ flexDirection: 'row', gap: 8 }}>
          <Button testID="settings-save" title="Save" style={{ flex: 2 }} busy={busy === 'save'}
            onPress={() => run('save', async () => { await updateSettings({ ...form, trustUrl: form.trustUrl.trim().replace(/\/$/, '') }); return 'Saved. Trust client rebuilt.'; })} />
          <Button title="Defaults" kind="secondary" style={{ flex: 1 }} onPress={() => setForm({ trustUrl: DEFAULT_SETTINGS.trustUrl, apiKey: DEFAULT_SETTINGS.apiKey,
            clientId: DEFAULT_SETTINGS.clientId, corsRelayUrl: DEFAULT_SETTINGS.corsRelayUrl })} />
        </View>
        <Info message={msg} testID="settings-message" />
        <ErrorBox message={err} testID="settings-error" />
      </Section>

      <Section title="Fallback and offline snapshot">
        <Toggle testID="settings-fallback" label="Standards-based fallback" hint="When the trust service is unreachable, use the signed snapshot, cached answers and direct discovery / DID / X.509 validation."
          value={settings.fallbackEnabled} onChange={(v) => updateSettings({ fallbackEnabled: v })} />
        <Toggle testID="settings-outage" label="Simulate trust-service outage" hint="Rebuilds the trust client against an unreachable URL. The snapshot store is kept."
          value={settings.simulateOutage} onChange={(v) => updateSettings({ simulateOutage: v })} />
        <View style={{ marginTop: 8 }} testID="snapshot-info">
          {snapshot ? (
            <>
              <KV k="Snapshot" v={`version ${snapshot.version}${snapshot.stale ? ' (STALE, in grace period)' : ''}`} testID="snapshot-version" />
              <KV k="Issued" v={shortDate(snapshot.issuedAt)} />
              <KV k="Expires" v={shortDate(snapshot.expiresAt)} testID="snapshot-expiry" />
              <KV k="Contents" v={`${snapshot.entities} entities, ${snapshot.anchors} trust anchors`} />
            </>
          ) : <Text testID="snapshot-none" style={s.hint}>No offline snapshot stored yet.</Text>}
        </View>
        <Button testID="settings-sync-snapshot" title="Sync offline snapshot" kind="secondary" busy={busy === 'sync'} style={{ marginTop: 8 }}
          onPress={() => run('sync', async () => { const i = await syncSnapshot(); return i ? `Snapshot version ${i.version} verified and stored.` : 'No snapshot.'; })} />
        {status === 'offline' ? <Info message="The trust service is offline, so syncing will fail; decisions use the stored snapshot." /> : null}
      </Section>

      <Section title="HAIP">
        <Segmented testID="settings-dpop" label="DPoP" options={['auto', 'never'] as const} value={settings.dpop} onChange={(v) => updateSettings({ dpop: v })} />
        <Segmented testID="settings-wallet-attestation" label="Wallet attestation" options={TRI} value={settings.walletAttestation} onChange={(v) => updateSettings({ walletAttestation: v })} />
        <Segmented testID="settings-key-attestation" label="Key attestation" options={TRI} value={settings.keyAttestation} onChange={(v) => updateSettings({ keyAttestation: v })} />
        <Toggle testID="settings-high-assurance" label="Simulated high-assurance key storage" value={settings.highAssurance} onChange={(v) => updateSettings({ highAssurance: v })}
          hint="Attests iso_18045_high key storage and user authentication (a simulated WSCD; keys are still software keys). Needed for issuers that require it, e.g. Animo key-attestation offers." />
      </Section>

      <Section title="Danger zone">
        <Text style={[s.hint, { marginBottom: 8 }]}>Deletes all credentials, keys, cached trust data and the snapshot. Settings are kept.</Text>
        <Button testID="settings-wipe" title={confirmWipe ? 'Tap again to wipe everything' : 'Wipe wallet'} kind="danger" busy={busy === 'wipe'}
          onPress={() => {
            if (!confirmWipe) { setConfirmWipe(true); return; }
            setConfirmWipe(false);
            run('wipe', async () => { await wipe(); navigation.popToTop(); return undefined; });
          }} />
      </Section>
      <Text style={[s.hint, { textAlign: 'center', color: colors.muted }]}>Demo wallet. Keys are software keys stored in {Platform.OS === 'web' ? 'localStorage' : 'AsyncStorage'}.</Text>
    </ScrollView>
  );
}
