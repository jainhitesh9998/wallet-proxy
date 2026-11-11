import React, { useEffect, useMemo, useState } from 'react';
import { Image, ScrollView, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { RootStack } from '../navigation';
import { instancesOf } from '@vctrust/wallet-core';
import { useWallet } from '../wallet/WalletContext';
import { claimGroups, claimNames, credentialView, humanize, imageUri, isBytes, nameFor, shortDate } from '../wallet/display';
import { TrustEvidence } from '../components/TrustEvidence';
import { Button, Checks, checkSummary, colors, ErrorBox, Info, KV, Logo, s, Section, TrustLine } from '../components/ui';

function ClaimValue({ value, path, names, depth }: { value: unknown; path: (string | number)[]; names: Map<string, string>; depth: number }) {
  const img = imageUri(value);
  if (img) return <Image source={{ uri: img }} style={{ width: 120, height: 150, borderRadius: 6, backgroundColor: '#eee' }} resizeMode="contain" testID="claim-image" />;
  if (isBytes(value)) return <Text style={s.kvVal}>{`<${value.length ?? '?'} bytes>`}</Text>;
  if (value === null || value === undefined) return <Text style={s.kvVal}>—</Text>;
  if (Array.isArray(value) && value.every((x) => x === null || typeof x !== 'object')) return <Text selectable style={s.kvVal}>{value.join(', ')}</Text>;
  if (typeof value === 'object' && depth < 4) {
    const entries = Array.isArray(value) ? value.map((v, i) => [i, v] as const) : Object.entries(value as Record<string, unknown>);
    return (
      <View style={{ flex: 1, borderLeftWidth: 2, borderLeftColor: colors.border, paddingLeft: 8 }}>
        {entries.map(([k, v]) => <ClaimRow key={String(k)} name={k} value={v} path={[...path, k]} names={names} depth={depth + 1} />)}
      </View>
    );
  }
  return <Text selectable style={s.kvVal}>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</Text>;
}

function ClaimRow({ name, value, path, names, depth, alt }: { name: string | number; value: unknown; path: (string | number)[]; names: Map<string, string>; depth: number; alt?: (string | number)[] }) {
  const label = typeof name === 'number' ? `#${name + 1}` : nameFor(names, path, alt) ?? humanize(name);
  return <KV k={label} v={<ClaimValue value={value} path={path} names={names} depth={depth} />} />;
}

export default function CredentialScreen({ route, navigation }: NativeStackScreenProps<RootStack, 'Credential'>) {
  const { credentials, wallet, refresh } = useWallet();
  const c = credentials.find((x) => x.id === route.params.id);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [note, setNote] = useState<string>();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const names = useMemo(() => claimNames(c?.claimMetadata), [c?.claimMetadata]);
  const v = c ? credentialView(c) : undefined;

  useEffect(() => { if (v) navigation.setOptions({ title: v.title }); }, [v?.title]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!c || !v) return <View style={s.screen}><Info message="Credential not found (deleted?)" /></View>;
  const report = c.report;

  return (
    <ScrollView contentContainerStyle={s.screen} testID="credential-screen">
      <View style={{ backgroundColor: v.background ?? '#fff', borderRadius: 14, padding: 14, borderWidth: 1, borderColor: colors.border, gap: 8 }}>
        <View style={{ flexDirection: 'row', gap: 10, alignItems: 'center' }}>
          <Logo uri={v.logo} size={48} />
          <View style={{ flex: 1 }}>
            <Text testID="detail-title" style={{ fontSize: 18, fontWeight: '700', color: v.textColor ?? colors.text }}>{v.title}</Text>
            <Text style={{ color: v.textColor ?? colors.muted }}>{v.issuer}</Text>
          </View>
        </View>
        <View style={{ backgroundColor: 'rgba(255,255,255,0.92)', borderRadius: 8, padding: 8 }}>
          <TrustLine trust={report?.trust} valid={report?.valid} testIDPrefix="detail-trust" />
        </View>
      </View>

      <Section title="Details">
        <KV k="Format" v={c.format} />
        <KV k="Type" v={report?.credentialType ?? c.configurationId} />
        <KV k="Issuer" v={c.credentialIssuer} mono />
        <KV k="Issued to wallet" v={shortDate(c.issuedAt)} />
        {report?.validFrom || report?.validUntil ? <KV k="Valid" v={`${shortDate(report?.validFrom)} – ${shortDate(report?.validUntil)}`} /> : null}
        {c.unbound
          ? <KV k="Holder key" v="none: the issuer does not bind this credential to a key of the wallet" testID="detail-unbound" />
          : <KV k="Holder key" v={c.holderDid ?? c.holderKeyId} mono />}
        {c.instances?.length ? (() => {
          const all = instancesOf(c);
          const usable = all.filter((x) => x.report?.valid !== false);
          const unused = usable.filter((x) => !x.presentations).length;
          return <KV k="Instances" v={`${usable.length}, ${unused} not yet presented${usable.length < all.length ? ` (${all.length - usable.length} failed re-verification)` : ''}`} testID="detail-instances" />;
        })() : null}
      </Section>

      <Section title="Claims" testID="claims">
        {!report ? <Info message="No claims (not verified)." /> : claimGroups(c).map((g, gi) => (
          <View key={gi} style={{ marginBottom: 8 }}>
            {g.title ? <Text style={[s.label, { color: colors.primary, marginBottom: 4 }]}>{g.title}</Text> : null}
            {Object.entries(g.values).map(([k, val]) => (
              <ClaimRow key={k} name={k} value={val} path={[...g.prefix, k]} alt={g.altPrefix ? [...g.altPrefix, k] : undefined} names={names} depth={0} />
            ))}
          </View>
        ))}
      </Section>

      <Section title="Verification checks" testID="checks">
        {report ? (
          <>
            <Text testID="checks-summary" style={[s.hint, { marginBottom: 4 }]}>{checkSummary(report)}</Text>
            <Checks report={report} />
          </>
        ) : <Info message="Not verified." />}
      </Section>

      <TrustEvidence trust={report?.trust} />
      {report?.issuer ? (
        <Section title="Issuer material in the credential">
          {report.issuer.issuer ? <KV k="iss / issuer" v={String(report.issuer.issuer)} mono /> : null}
          {report.issuer.kid ? <KV k="kid" v={String(report.issuer.kid)} mono /> : null}
          {report.issuer.x5c?.length ? <KV k="x5c" v={`${report.issuer.x5c.length} certificate(s)`} /> : null}
        </Section>
      ) : null}

      <Info message={note} testID="detail-note" />
      <ErrorBox message={error} />
      <View style={{ flexDirection: 'row', gap: 8 }}>
        {c.pending ? (
          <Button testID="cred-retrieve" title="Check for the credential" busy={busy === 'retrieve'} style={{ flex: 1 }} onPress={async () => {
            setBusy('retrieve'); setError(undefined); setNote(undefined);
            try {
              const r = await wallet.retrieveDeferred(c.id);
              await refresh();
              setNote(r.pending ? `The issuer is not done yet; try again in ${r.pending.interval} s.` : 'Issued, verified and stored.');
            } catch (e) { setError((e as Error).message); } finally { setBusy(undefined); }
          }} />
        ) : (
          <Button testID="cred-reverify" title="Re-verify" busy={busy === 'reverify'} style={{ flex: 1 }} onPress={async () => {
            setBusy('reverify'); setError(undefined); setNote(undefined);
            try {
              const r = await wallet.reverify(c.id);
              await refresh();
              setNote(`Re-verified: ${r.valid ? 'valid' : 'INVALID'}, issuer ${r.trust?.decision ?? 'not evaluated'} (${r.trust?.source ?? '-'}), ${checkSummary(r)}, at ${shortDate(new Date().toISOString())}`);
            } catch (e) { setError((e as Error).message); } finally { setBusy(undefined); }
          }} />
        )}
        <Button testID="cred-delete" title={confirmDelete ? 'Tap again to delete' : 'Delete'} kind="danger" style={{ flex: 1 }} busy={busy === 'delete'} onPress={async () => {
          if (!confirmDelete) { setConfirmDelete(true); return; }
          setBusy('delete');
          await wallet.remove(c.id);
          await refresh();
          navigation.popToTop();
        }} />
      </View>
    </ScrollView>
  );
}
