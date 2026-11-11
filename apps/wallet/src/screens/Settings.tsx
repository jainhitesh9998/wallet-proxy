import React, { useEffect, useState } from 'react';
import { Platform, ScrollView, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { DEFAULT_SETTINGS, type Settings, type Tri } from '../wallet/settings';
import { PINNED_TRUST_NOTE } from '../config/pinned';
import { shortDate } from '../wallet/display';
import { TrustStatusPill } from '../components/StatusPill';
import { Button, colors, ErrorBox, Field, Info, KV, s, Section, Segmented, Toggle } from '../components/ui';

const TRI: readonly Tri[] = ['auto', 'always', 'never'];
const VIA = ['proxy', 'direct'] as const;

type ServiceForm = Pick<Settings, 'trustUrl' | 'apiKey' | 'clientId' | 'serviceKeyThumbprint'>;
const serviceForm = (x: Settings): ServiceForm => ({ trustUrl: x.trustUrl, apiKey: x.apiKey, clientId: x.clientId, serviceKeyThumbprint: x.serviceKeyThumbprint });

/** TrustClient.status(), as it is: the service, the snapshot decisions are made from, and why it is not fresh when it is not. */
function TrustStatusSection() {
  const { trustStatus: t, statusReason, syncSnapshot, refreshTrustStatus } = useWallet();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  const [err, setErr] = useState<string>();
  const snap = t.snapshot;

  useEffect(() => { void refreshTrustStatus(); }, [refreshTrustStatus]);

  const sync = async () => {
    setBusy(true); setErr(undefined); setMsg(undefined);
    try {
      const i = await syncSnapshot();
      setMsg(`Snapshot of ${shortDate(i.issuedAt)} verified and stored.`);
    } catch (e) {
      setErr(`The snapshot could not be refreshed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title="Trust status" testID="trust-status-section">
      <KV k="Trust service" testID="status-service" v={t.service === 'online' ? 'online' : t.service === 'offline' ? `offline${statusReason ? ` (${statusReason})` : ''}`
        : t.service === 'unconfigured' ? 'not configured' : 'not contacted yet'} />
      <KV k="Decisions" testID="status-degraded" v={!snap ? 'degraded: no usable snapshot, only pinned trust decides'
        : snap.stale ? 'degraded: the snapshot has expired and is used within its grace period; decisions carry a warning' : 'from a current snapshot'} />
      <View testID="snapshot-info">
        {snap ? (
          <>
            <KV k="Snapshot" v={`${snap.id}${snap.stale ? ' (expired)' : ''}`} testID="snapshot-id" mono />
            <KV k="Issued" v={shortDate(snap.issuedAt)} testID="snapshot-issued" />
            <KV k="Expires" v={shortDate(snap.expiresAt)} testID="snapshot-expiry" />
            <KV k="Contents" testID="snapshot-contents"
              v={`${snap.entities} entities, ${snap.anchors} trust anchors, ${snap.didDocuments} DID documents, ${snap.contexts} JSON-LD contexts, ${snap.crls} CRLs`} />
            <KV k="Policy" testID="snapshot-policy" v={`${snap.strictAuthorization ? 'strict' : 'lenient'} authorization, revocation status ${snap.requireRevocationStatus ? 'required' : 'checked when available'}`
              + `${snap.requireSignedIssuerMetadata ? ', signed issuer metadata required' : ''}`} />
          </>
        ) : <Text testID="snapshot-none" style={[s.hint, { color: colors.amber }]}>No usable snapshot on this device.</Text>}
      </View>
      {t.lastSyncError ? <KV k="Last refresh" v={`failed: ${t.lastSyncError}`} testID="status-sync-error" /> : null}
      <Text testID="pinned-note" style={[s.hint, { marginTop: 6 }]}>{PINNED_TRUST_NOTE}</Text>
      <Button testID="settings-sync-snapshot" title="Refresh snapshot now" kind="secondary" busy={busy} style={{ marginTop: 8 }} onPress={sync} />
      <Info message={msg} testID="sync-message" />
      <ErrorBox message={err} testID="sync-error" />
    </Section>
  );
}

export default function SettingsScreen({ navigation }: NativeStackScreenProps<RootStack, 'Settings'>) {
  const { settings, updateSettings, wipe, configError } = useWallet();
  const [form, setForm] = useState<ServiceForm>(serviceForm(settings));
  const [msg, setMsg] = useState<string>();
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const [confirmWipe, setConfirmWipe] = useState(false);

  useEffect(() => {
    setForm(serviceForm(settings));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.trustUrl, settings.apiKey, settings.clientId, settings.serviceKeyThumbprint]);

  const run = async (name: string, f: () => Promise<string | undefined>) => {
    setBusy(name); setErr(undefined); setMsg(undefined);
    try { setMsg(await f()); } catch (e) { setErr((e as Error).message); } finally { setBusy(undefined); }
  };
  const tofu = !form.serviceKeyThumbprint.trim();

  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled" testID="settings-screen">
      <Section title="Trust service" right={<TrustStatusPill testID="settings-trust-status" />}>
        <Field testID="settings-trust-url" label="Trust service URL" value={form.trustUrl} onChangeText={(t) => setForm({ ...form, trustUrl: t })} keyboardType="url"
          placeholder="https://trust.example" />
        <Text style={[s.hint, { marginBottom: 8 }]}>
          https, or http for development: an http URL adds its host to the hosts this wallet reaches without TLS (otherwise only localhost, 127.0.0.1 and 10.0.2.2).
          {Platform.OS !== 'web' ? ' On a phone use the LAN address of the machine running the service, not localhost.' : ''}
        </Text>
        <Field testID="settings-api-key" label="API key" value={form.apiKey} onChangeText={(t) => setForm({ ...form, apiKey: t })} />
        <Field testID="settings-client-id" label="Client id (the audience of what the service signs)" value={form.clientId} onChangeText={(t) => setForm({ ...form, clientId: t })} />
        <Field testID="settings-service-key" label="Service key thumbprint" value={form.serviceKeyThumbprint} onChangeText={(t) => setForm({ ...form, serviceKeyThumbprint: t })}
          placeholder="signing_key_thumbprint from /.well-known/trust-service" />
        <Text testID="settings-service-key-mode" style={[s.hint, { marginBottom: 8 }, tofu && { color: colors.amber }]}>
          {tofu ? 'Development only: no thumbprint is set, so the first key the service presents is trusted and pinned on this device (wiping the wallet forgets it).'
            : 'Only snapshots and proxied documents signed with this key are accepted.'}
        </Text>
        <View style={{ flexDirection: 'row', gap: 8 }}>
          <Button testID="settings-save" title="Save" style={{ flex: 2 }} busy={busy === 'save'}
            onPress={() => run('save', async () => {
              await updateSettings({ trustUrl: form.trustUrl.trim().replace(/\/$/, ''), apiKey: form.apiKey.trim(), clientId: form.clientId.trim(),
                serviceKeyThumbprint: form.serviceKeyThumbprint.trim() });
              return 'Saved. The trust client was rebuilt.';
            })} />
          <Button title="Defaults" kind="secondary" style={{ flex: 1 }} onPress={() => setForm(serviceForm(DEFAULT_SETTINGS))} />
        </View>
        <Info message={msg} testID="settings-message" />
        <ErrorBox message={err ?? configError} testID="settings-error" />
      </Section>

      <TrustStatusSection />

      <Section title="Lookups" testID="settings-lookups">
        <Text style={[s.hint, { marginBottom: 6 }]}>
          Trust decisions are always made on this device. Documents about an issuer or verifier come through the trust service's proxy first, and from the party
          itself when the proxy cannot serve them. A proxied lookup shows the service which party you deal with and hides this device from that party; a direct
          one does the opposite. Either way the wallet verifies what it receives.
        </Text>
        <Segmented testID="settings-metadata" label="Issuer metadata" options={VIA} value={settings.metadata} onChange={(v) => updateSettings({ metadata: v })} />
        <Segmented testID="settings-did" label="DID documents" options={VIA} value={settings.did} onChange={(v) => updateSettings({ did: v })} />
        <Segmented testID="settings-crl" label="CRLs not in the snapshot" options={['proxy', 'direct', 'none'] as const} value={settings.crl}
          onChange={(v) => updateSettings({ crl: v })} />
        <Segmented testID="settings-status-lists" label="Status lists" options={VIA} value={settings.statusLists} onChange={(v) => updateSettings({ statusLists: v })} />
        <Text style={[s.hint, { marginBottom: 6 }]}>
          With CRLs set to none, a certificate whose CRL is not in the snapshot has an unknown revocation status. OCSP is never used: it would reveal the exact certificate.
        </Text>
        <Toggle testID="settings-unknown-parties" label="Ask the service about unlisted parties" value={settings.unknownParties}
          onChange={(v) => updateSettings({ unknownParties: v })}
          hint="For registries too large for the snapshot (OpenID Federation, EBSI). Sends that party's identifier to the service. Off by default." />
        <Toggle testID="settings-outage" label="Simulate trust-service outage" value={settings.simulateOutage} onChange={(v) => updateSettings({ simulateOutage: v })}
          hint="Points the trust client at an address where nothing listens. The stored snapshot stays in use and lookups fall back to the party itself." />
      </Section>

      <Section title="HAIP">
        <Segmented testID="settings-dpop" label="DPoP" options={['auto', 'never'] as const} value={settings.dpop} onChange={(v) => updateSettings({ dpop: v })} />
        <Segmented testID="settings-wallet-attestation" label="Wallet attestation" options={TRI} value={settings.walletAttestation} onChange={(v) => updateSettings({ walletAttestation: v })} />
        <Segmented testID="settings-key-attestation" label="Key attestation" options={TRI} value={settings.keyAttestation} onChange={(v) => updateSettings({ keyAttestation: v })} />
        <Toggle testID="settings-high-assurance" label="Simulated high-assurance key storage" value={settings.highAssurance} onChange={(v) => updateSettings({ highAssurance: v })}
          hint="Attests iso_18045_high key storage and user authentication (a simulated WSCD; keys are still software keys). Needed for issuers that require it, e.g. Animo key-attestation offers." />
        <Segmented testID="settings-batch" label="Instances per credential" options={['1', '3', '5'] as const} value={settings.batchSize}
          onChange={(v) => updateSettings({ batchSize: v })} />
        <Text style={s.hint}>From issuers that support batch issuance: each instance has its own key, and every verifier gets one not shown before, so verifiers cannot link your presentations.</Text>
      </Section>

      <Section title="Danger zone">
        <Text style={[s.hint, { marginBottom: 8 }]}>Deletes all credentials, keys, the snapshot, the pinned service key and cached documents. Settings are kept.</Text>
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
