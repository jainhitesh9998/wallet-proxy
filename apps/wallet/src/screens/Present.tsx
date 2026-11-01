/** Present: OpenID4VP 1.0 request (paste / scan), verifier trust, DCQL matching with a candidate picker, share / decline. */
import React, { useCallback, useEffect, useState } from 'react';
import { Linking, Platform, Pressable, ScrollView, Text, View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { pickInstance, PresentationRequestError, reportPresentationError, type PresentationSession } from '@vctrust/wallet-core';
import type { RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { claimNames, credentialView, humanize, nameFor, shortDate } from '../wallet/display';
import { ScanButton } from '../components/QrScanner';
import { TrustEvidence } from '../components/TrustEvidence';
import { Button, colors, ErrorBox, Field, Info, KV, Logo, s, Section, TrustLine } from '../components/ui';

type Result = { kind: 'shared' | 'declined'; status: number; redirectUri?: string; body?: unknown };

export default function PresentScreen({ route, navigation }: NativeStackScreenProps<RootStack, 'Present'>) {
  const { wallet, refresh } = useWallet();
  const [input, setInput] = useState(route.params?.uri ?? '');
  const [session, setSession] = useState<PresentationSession>();
  const [choice, setChoice] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  /** a failed request the verifier may be told about, once the user chooses to (OpenID4VP §15.9.2) */
  const [reportable, setReportable] = useState<PresentationRequestError>();
  const [result, setResult] = useState<Result>();

  const load = useCallback(async (uri: string) => {
    setSession(undefined); setResult(undefined); setError(undefined); setReportable(undefined); setChoice({});
    if (!uri.trim()) return;
    setBusy('load');
    try {
      const p = await wallet.startPresentation(uri.trim());
      setSession(p);
      setChoice(Object.fromEntries(p.dcql.matches.filter((m) => m.candidates[0]).map((m) => [m.query.id, m.candidates[0]!.id])));
    } catch (e) {
      setError((e as Error).message);
      if (e instanceof PresentationRequestError && e.reportTo) setReportable(e);
    } finally {
      setBusy(undefined);
    }
  }, [wallet]);

  useEffect(() => {
    if (route.params?.uri) { setInput(route.params.uri); load(route.params.uri); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.params?.nonce]);

  const finish = (kind: Result['kind'], r: { status: number; redirectUri?: string; body?: unknown }) => {
    setResult({ kind, ...r });
    if (r.redirectUri) {
      // OpenID4VP §8.2: continue the user's session at the verifier.
      if (Platform.OS === 'web') window.open(r.redirectUri, '_blank');
      else Linking.openURL(r.redirectUri).catch(() => undefined);
    }
  };

  const share = async () => {
    if (!session) return;
    setBusy('share'); setError(undefined);
    try { finish('shared', await session.respond(choice)); } catch (e) { setError((e as Error).message); } finally { setBusy(undefined); void refresh(); }
  };
  const decline = async () => {
    if (!session) return;
    setBusy('decline'); setError(undefined);
    try { finish('declined', await session.decline()); } catch (e) { setError((e as Error).message); } finally { setBusy(undefined); }
  };

  const v = session?.verifier;
  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled" testID="present-screen">
      {!session ? (
        <Section title="Presentation request">
          <Field testID="present-input" label="openid4vp:// request" value={input} onChangeText={setInput} multiline placeholder="openid4vp://?client_id=...&request_uri=..." />
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <Button title="Paste" kind="secondary" style={{ flex: 1 }} onPress={async () => { try { setInput(await Clipboard.getStringAsync()); } catch { /* denied */ } }} />
            <ScanButton testID="present-scan" onScanned={(d) => { setInput(d); load(d); }} />
            <Button testID="present-load" title="Load request" busy={busy === 'load'} disabled={!input.trim()} onPress={() => load(input)} style={{ flex: 1 }} />
          </View>
          <ErrorBox message={error} testID="present-error" />
          {reportable ? (
            <Button testID="present-report-error" title="Tell the verifier" kind="secondary" busy={busy === 'report'} onPress={async () => {
              setBusy('report');
              try {
                const status = await reportPresentationError(reportable, wallet.fetchFn);
                setReportable(undefined);
                setError(`${reportable.message}. The verifier was told (${reportable.code}, HTTP ${status}).`);
              } catch (e) { setError((e as Error).message); } finally { setBusy(undefined); }
            }} />
          ) : null}
        </Section>
      ) : null}

      {session && v ? (
        <>
          <Section title="Verifier" testID="verifier-section">
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <Logo uri={v.logoUri} size={44} />
              <View style={{ flex: 1 }}>
                <Text testID="verifier-name" style={{ fontSize: 17, fontWeight: '700', color: colors.text }}>{v.name ?? 'Unnamed verifier'}</Text>
                <Text selectable style={s.hint} numberOfLines={2}>{v.clientId}</Text>
              </View>
            </View>
            <TrustLine trust={v.trust} testIDPrefix="verifier-trust" />
            {v.refusal ? <ErrorBox testID="verifier-refusal" message={`Sharing is blocked: ${v.refusal}`} /> : null}
            <View style={{ marginTop: 8 }}>
              <KV k="Client id prefix" v={v.prefix} />
              <KV k="Response mode" v={session.request.responseMode} />
              {session.request.responseUri ? <KV k="Response URI" v={session.request.responseUri} mono /> : null}
            </View>
            <Text style={[s.label, { marginTop: 8 }]}>Request checks</Text>
            {v.checks.map((c, i) => (
              <Text key={i} testID={`verifier-check-${i}`} style={[s.hint, { color: c.ok ? colors.green : colors.amber }]}>{c.ok ? '✓' : '!'} {c.label}{c.detail ? `: ${c.detail}` : ''}</Text>
            ))}
          </Section>

          <Section title="Requested credentials" testID="dcql-section">
            {!session.dcql.satisfied ? <ErrorBox testID="dcql-unsatisfied" message={session.dcql.reason ?? 'This wallet cannot satisfy the request'} /> : null}
            {session.dcql.matches.map((m) => {
              const selected = session.dcql.selected.includes(m.query.id);
              const meta = m.query.meta ?? {};
              const type = (meta.doctype_value ?? (meta.vct_values as string[] | undefined)?.join(', ')) as string | undefined;
              return (
                <View key={m.query.id} testID={`dcql-query-${m.query.id}`} style={{ paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.border, gap: 4, opacity: selected ? 1 : 0.6 }}>
                  <Text style={s.label}>{m.query.id} · {m.query.format}{type ? ` · ${type}` : ''}{selected ? '' : ' (not needed)'}</Text>
                  <Text style={s.hint}>Claims to share:</Text>
                  {!(m.claimsFor[choice[m.query.id] ?? ''] ?? m.claims).length
                    ? <Text style={[s.hint, { color: colors.text }]}>• None: only that you hold this credential (no selectively disclosable claims)</Text> : null}
                  {(m.claimsFor[choice[m.query.id] ?? ''] ?? m.claims).map((cl, i) => {
                    const cand = m.candidates.find((c) => c.id === choice[m.query.id]);
                    const names = claimNames(cand?.claimMetadata);
                    const path = cl.path.filter((p): p is string | number => p !== null);
                    const label = nameFor(names, path) ?? humanize(String(path[path.length - 1] ?? ''));
                    return <Text key={i} style={[s.hint, { color: colors.text }]}>• {label} <Text style={s.hint}>({cl.path.map(String).join(' / ')})</Text></Text>;
                  })}
                  <Text style={[s.hint, { marginTop: 4 }]}>From:</Text>
                  {m.candidates.length === 0 ? <Text style={[s.hint, { color: colors.red }]}>No matching credential in this wallet</Text> : null}
                  {m.candidates.map((c, i) => {
                    const cv = credentialView(c);
                    const on = choice[m.query.id] === c.id;
                    const next = pickInstance(c);
                    return (
                      <Pressable key={c.id} testID={`candidate-${m.query.id}-${i}`} accessibilityRole="radio" accessibilityState={{ checked: on }}
                        onPress={() => setChoice({ ...choice, [m.query.id]: c.id })} style={[s.row, { paddingVertical: 4 }]}>
                        <Text style={{ fontSize: 16 }}>{on ? '◉' : '○'}</Text>
                        <View style={{ flex: 1 }}>
                          <Text style={s.label}>{cv.title} <Text style={s.hint}>· {cv.issuer}</Text></Text>
                          <Text style={s.hint}>issued {shortDate(c.issuedAt)} · {c.report?.trust?.decision ?? '?'} ({c.report?.trust?.source ?? '-'})</Text>
                          {next.total > 1 ? (
                            <Text testID={`instance-${m.query.id}-${i}`} style={[s.hint, !next.fresh && { color: colors.amber }]}>
                              {next.fresh ? `Instance ${next.ordinal} of ${next.total}, not shown to any verifier before`
                                : `All ${next.total} instances were presented before: this verifier could link this presentation to an earlier one`}
                            </Text>
                          ) : null}
                        </View>
                      </Pressable>
                    );
                  })}
                </View>
              );
            })}
          </Section>

          {!result ? (
            <View style={{ flexDirection: 'row', gap: 8 }}>
              <Button testID="present-decline" title="Decline" kind="secondary" busy={busy === 'decline'} disabled={!!busy} onPress={decline} style={{ flex: 1 }} />
              <Button testID="present-share" title="Share" busy={busy === 'share'} disabled={!session.dcql.satisfied || !!v.refusal || !!busy} onPress={share} style={{ flex: 2 }} />
            </View>
          ) : (
            <Section title={result.kind === 'shared' ? 'Shared' : 'Declined'} testID="present-result">
              <Text testID="present-result-status" style={s.label}>
                {result.kind === 'shared' ? 'Presentation sent' : 'Decline sent'}: verifier responded HTTP {result.status}{result.status >= 200 && result.status < 300 ? ' (accepted)' : ''}
              </Text>
              {result.redirectUri ? (
                <View style={{ marginTop: 8, gap: 6 }}>
                  <Text style={s.hint}>The verifier asked to continue at:</Text>
                  <Text selectable style={[s.hint, { color: colors.primary }]}>{result.redirectUri}</Text>
                  <Button title="Open verifier" kind="secondary" onPress={() => (Platform.OS === 'web' ? window.open(result.redirectUri, '_blank') : Linking.openURL(result.redirectUri!))} />
                </View>
              ) : null}
              {result.body && typeof result.body === 'object' && Object.keys(result.body).length ? (
                <Text selectable style={[s.hint, s.mono, { marginTop: 6 }]}>{JSON.stringify(result.body).slice(0, 400)}</Text>
              ) : null}
              <Button testID="present-done" title="Done" style={{ marginTop: 10 }} onPress={() => navigation.popToTop()} />
            </Section>
          )}
          <ErrorBox message={error} testID="present-error" />
          <TrustEvidence trust={v.trust} title="Verifier trust evidence" testIDPrefix="verifier-evidence" />
          {!result ? <Button title="Start over" kind="secondary" onPress={() => { setSession(undefined); setError(undefined); }} /> : null}
        </>
      ) : null}
    </ScrollView>
  );
}
