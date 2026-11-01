/**
 * Receive: OpenID4VCI issuance from a pasted / scanned offer, or wallet-initiated from an issuer listed by the trust
 * service. Pre-authorized code (+ tx_code) and authorization code flows (device: auth session; web: new tab + paste).
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Platform, Pressable, ScrollView, Text, View } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import * as Clipboard from 'expo-clipboard';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { EntityView, TrustDecision } from '@vctrust/trust-client';
import { IssuanceError, type IssuanceSession, type IssuedCredential } from '@vctrust/wallet-core';
import { authCallbacks, OAUTH_CHANNEL, type RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { credentialView, issuerView, pickLocale } from '../wallet/display';
import { MOSIP_REGISTRATIONS } from '../config/defaults';
import { ScanButton } from '../components/QrScanner';
import { Button, colors, ErrorBox, Field, Info, KV, Logo, s, Section, SourcePill, TrustLine } from '../components/ui';

const errMsg = (e: unknown) => {
  const err = e as Error & { code?: string };
  return `${err.message ?? String(e)}${err.code && !String(err.message).includes(err.code) ? ` (${err.code})` : ''}`;
};

function configLabel(config: Record<string, unknown>, id: string) {
  const md = (config.credential_metadata ?? {}) as Record<string, unknown>;
  const d = pickLocale((md.display ?? config.display) as { name?: string; locale?: string }[] | undefined);
  const type = (config.doctype ?? config.vct ?? ((config.credential_definition as { type?: string[] } | undefined)?.type ?? []).slice(-1)[0]) as string | undefined;
  return { name: d?.name ?? id, format: String(config.format ?? '?'), type };
}

function TrustedIssuers({ onStart }: { onStart: (issuer: string, configs: string[]) => Promise<void> }) {
  const { trust } = useWallet();
  const [list, setList] = useState<{ items: EntityView[]; source: string }>();
  const [error, setError] = useState<string>();
  const [picked, setPicked] = useState<{ entity: EntityView; url: string; configs: { id: string; name: string; format: string; type?: string }[];
    chosen: string[]; trust: TrustDecision; mdSource: string }>();
  const [busy, setBusy] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    trust.issuers({ size: 100 }).then((r) => { if (!cancelled) setList(r); }).catch((e) => !cancelled && setError(errMsg(e)));
    return () => { cancelled = true; };
  }, [trust]);

  const pick = async (entity: EntityView, url: string) => {
    setBusy(url); setError(undefined);
    try {
      const md = await trust.getIssuerMetadata(url);
      const supported = (md.credentialIssuerMetadata.credential_configurations_supported ?? {}) as Record<string, Record<string, unknown>>;
      const configs = Object.entries(supported).map(([id, c]) => ({ id, ...configLabel(c, id) }));
      setPicked({ entity, url: md.credentialIssuer, configs, chosen: configs.slice(0, 1).map((c) => c.id), trust: md.trust, mdSource: md.source });
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(undefined);
    }
  };

  if (picked) {
    return (
      <Section title={pickLocale(picked.entity.display)?.name ?? picked.entity.id} testID="issuer-picked">
        <Text selectable style={s.hint}>{picked.url}</Text>
        <View style={{ marginVertical: 8 }}><TrustLine trust={picked.trust} testIDPrefix="picked-trust" /></View>
        <KV k="Metadata via" v={picked.mdSource} />
        {MOSIP_REGISTRATIONS[picked.url] ? <Info message="MOSIP issuer: uses the registered Mimoto client and token proxy." /> : null}
        {picked.url.startsWith('https://playground.animo.id/') ? (
          <Info message="The Animo playground only issues from its own offers: create one at playground.animo.id (Issue tab) and paste the link on the Offer tab." />
        ) : null}
        <Text style={[s.label, { marginTop: 8 }]}>Credential configurations</Text>
        {picked.configs.map((c, i) => {
          const on = picked.chosen.includes(c.id);
          return (
            <Pressable key={c.id} testID={`issuer-config-${i}`} accessibilityRole="checkbox" accessibilityState={{ checked: on }}
              onPress={() => setPicked({ ...picked, chosen: on ? picked.chosen.filter((x) => x !== c.id) : [...picked.chosen, c.id] })}
              style={[s.row, { borderBottomWidth: 1, borderBottomColor: colors.border }]}>
              <Text style={{ fontSize: 18 }}>{on ? '☑' : '☐'}</Text>
              <View style={{ flex: 1 }}>
                <Text style={s.label}>{c.name}</Text>
                <Text style={s.hint}>{c.format}{c.type ? ` · ${c.type}` : ''} · {c.id}</Text>
              </View>
            </Pressable>
          );
        })}
        <ErrorBox message={error} />
        <View style={{ flexDirection: 'row', gap: 8, marginTop: 10 }}>
          <Button title="Back" kind="secondary" onPress={() => setPicked(undefined)} style={{ flex: 1 }} />
          <Button testID="issuer-start" title="Start issuance" busy={busy === 'start'} disabled={picked.chosen.length === 0} style={{ flex: 2 }}
            onPress={async () => { setBusy('start'); setError(undefined); try { await onStart(picked.url, picked.chosen); } catch (e) { setError(errMsg(e)); } finally { setBusy(undefined); } }} />
        </View>
      </Section>
    );
  }
  return (
    <Section title="Trusted issuers (trust list)" right={<SourcePill source={list?.source} testID="issuers-source" />}>
      {!list && !error ? <Info message="Loading…" /> : null}
      <ErrorBox message={error} />
      {list?.items.length === 0 ? <Info message="No issuers registered." /> : null}
      {list?.items.map((e) => {
        const urls = e.identifiers.filter((i) => i.type.toUpperCase() === 'URL').map((i) => i.value);
        const d = pickLocale(e.display);
        return (
          <View key={e.id} style={{ paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.border, gap: 4 }}>
            <View style={{ flexDirection: 'row', gap: 8, alignItems: 'center' }}>
              <Logo uri={d?.logoUri} size={28} />
              <Text style={[s.label, { flex: 1 }]}>{d?.name ?? e.id}</Text>
              <Text style={s.hint}>{e.frameworkId}</Text>
            </View>
            <Text style={s.hint}>{[...new Set(e.authorizations.map((a) => [a.format, a.type].filter(Boolean).join(' ')))].join(' · ')}</Text>
            {urls.map((u) => (
              <Button key={u} testID={`issuer-pick-${e.id}`} title={`Get credential from ${u.replace(/^https:\/\//, '')}`} kind="secondary" busy={busy === u} onPress={() => pick(e, u)} />
            ))}
          </View>
        );
      })}
    </Section>
  );
}

export default function ReceiveScreen({ navigation, route }: NativeStackScreenProps<RootStack, 'Receive'>) {
  const { wallet, refresh } = useWallet();
  const [tab, setTab] = useState<'offer' | 'issuers'>('offer');
  const [input, setInput] = useState(route.params?.uri ?? '');
  const [session, setSession] = useState<IssuanceSession>();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [progress, setProgress] = useState<string>();
  const [txCode, setTxCode] = useState('');
  const [auth, setAuth] = useState<{ authorizationUrl: string; redirectUri: string }>();
  const [callback, setCallback] = useState('');
  const [issued, setIssued] = useState<IssuedCredential[]>();
  const completing = useRef(false);

  const reset = () => {
    setSession(undefined); setError(undefined); setIssued(undefined); setAuth(undefined); setCallback(''); setTxCode(''); setProgress(undefined);
    completing.current = false;
  };

  const load = useCallback(async (uri: string) => {
    reset();
    if (!uri.trim()) return;
    setBusy('load');
    try {
      setSession(await wallet.receive(uri.trim()));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(undefined);
    }
  }, [wallet]);

  useEffect(() => {
    if (route.params?.uri) {
      setTab('offer');
      setInput(route.params.uri);
      load(route.params.uri);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.params?.nonce]);

  /** A later credential of the offer failed: the ones issued before it are still kept. */
  const keepIssued = async (e: unknown) => {
    if (e instanceof IssuanceError && e.issued.length) await finish(e.issued).catch(() => undefined);
  };

  const finish = async (creds: IssuedCredential[]) => {
    await wallet.store(creds);
    await refresh();
    setIssued(creds);
  };

  const accept = async () => {
    if (!session) return;
    setBusy('accept'); setError(undefined); setProgress('Requesting token and credential…');
    try {
      await finish(await session.acceptPreAuthorized(session.txCode ? txCode.trim() : undefined));
    } catch (e) {
      setError(errMsg(e));
      await keepIssued(e);
    } finally {
      setBusy(undefined); setProgress(undefined);
    }
  };

  const complete = useCallback(async (url: string) => {
    if (!session || completing.current) return;
    completing.current = true;
    setBusy('complete'); setError(undefined); setProgress('Exchanging the authorization code…');
    try {
      await finish(await session.completeAuthorization(url.trim()));
    } catch (e) {
      setError(errMsg(e));
      await keepIssued(e);
      completing.current = false;
    } finally {
      setBusy(undefined); setProgress(undefined);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // Callbacks arriving by deep link (device) or from the web /oauth-callback tab.
  useEffect(() => {
    if (!auth || issued) return;
    const off = authCallbacks.subscribe((u) => complete(u));
    let bc: BroadcastChannel | undefined;
    if (Platform.OS === 'web' && typeof BroadcastChannel !== 'undefined') {
      bc = new BroadcastChannel(OAUTH_CHANNEL);
      bc.onmessage = (ev) => { if (typeof ev.data === 'string') { setCallback(ev.data); complete(ev.data); } };
    }
    return () => { off(); bc?.close(); };
  }, [auth, issued, complete]);

  const authorize = async () => {
    if (!session) return;
    setBusy('auth'); setError(undefined);
    try {
      const a = await session.beginAuthorization();
      setAuth(a);
      if (Platform.OS === 'web') {
        window.open(a.authorizationUrl, '_blank');
      } else {
        const r = await WebBrowser.openAuthSessionAsync(a.authorizationUrl, a.redirectUri);
        if (r.type === 'success' && r.url) await complete(r.url);
      }
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(undefined);
    }
  };

  const startWalletInitiated = async (issuer: string, configs: string[]) => {
    reset();
    const sess = await wallet.oid4vci.startWalletInitiated(issuer, configs);
    setSession(sess);
  };

  const issuer = session ? issuerView(session.issuerDisplay, session.credentialIssuer) : undefined;
  const registered = session ? MOSIP_REGISTRATIONS[session.credentialIssuer] : undefined;

  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled" testID="receive-screen">
      {!session ? (
        <View style={{ flexDirection: 'row', gap: 8 }}>
          <Button testID="tab-offer" title="Offer" kind={tab === 'offer' ? 'primary' : 'secondary'} onPress={() => setTab('offer')} style={{ flex: 1 }} />
          <Button testID="tab-issuers" title="From trusted issuers" kind={tab === 'issuers' ? 'primary' : 'secondary'} onPress={() => setTab('issuers')} style={{ flex: 1 }} />
        </View>
      ) : null}

      {!session && tab === 'offer' ? (
        <Section title="Credential offer">
          <Field testID="offer-input" label="openid-credential-offer:// or https offer link" value={input} onChangeText={setInput} multiline
            placeholder="openid-credential-offer://?credential_offer_uri=..." />
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <Button title="Paste" kind="secondary" style={{ flex: 1 }} onPress={async () => { try { setInput(await Clipboard.getStringAsync()); } catch { /* denied */ } }} />
            <ScanButton testID="offer-scan" onScanned={(d) => { setInput(d); load(d); }} />
            <Button testID="offer-load" title="Load offer" busy={busy === 'load'} disabled={!input.trim()} onPress={() => load(input)} style={{ flex: 1 }} />
          </View>
          <ErrorBox message={error} testID="receive-error" />
        </Section>
      ) : null}

      {!session && tab === 'issuers' ? <TrustedIssuers onStart={startWalletInitiated} /> : null}

      {session ? (
        <>
          <Section title="Issuer" testID="issuer-section">
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <Logo uri={issuer?.logo} size={44} />
              <View style={{ flex: 1 }}>
                <Text testID="issuer-name" style={{ fontSize: 17, fontWeight: '700', color: colors.text }}>{issuer?.name}</Text>
                <Text selectable style={s.hint}>{session.credentialIssuer}</Text>
              </View>
            </View>
            <TrustLine trust={session.issuerTrust} testIDPrefix="issuer-trust" />
            <View style={{ marginTop: 8 }}>
              <KV k="Framework" v={session.issuerTrust.framework?.name ?? '—'} />
              <KV k="Registered as" v={session.issuerTrust.entity ? (pickLocale(session.issuerTrust.entity.display)?.name ?? session.issuerTrust.entity.id) : '—'} />
              <KV k="Metadata via" v={session.metadata.source} testID="issuer-metadata-source" />
              {session.metadata.signedMetadata ? <KV k="Signed metadata" v={session.metadata.signedMetadataVerified ? 'verified' : 'NOT verified'} /> : null}
              {session.metadata.warnings?.length ? <KV k="Warnings" v={session.metadata.warnings.join('\n')} /> : null}
            </View>
          </Section>

          <Section title="Offered credentials">
            {session.configurations.map((c, i) => {
              const l = configLabel(c.config, c.id);
              return (
                <View key={c.id} testID={`offered-config-${i}`} style={{ paddingVertical: 6 }}>
                  <Text style={s.label}>{l.name}</Text>
                  <Text style={s.hint}>{l.format}{l.type ? ` · ${l.type}` : ''} · {c.id}</Text>
                </View>
              );
            })}
            <KV k="Grant" v={session.grant} testID="offer-grant" />
          </Section>

          {!issued ? (
            <Section title={session.grant === 'pre-authorized_code' ? 'Accept' : 'Authorize'}>
              {session.grant === 'pre-authorized_code' ? (
                <>
                  {session.txCode ? (
                    <Field testID="txcode-input" label={`Transaction code${session.txCode.length ? ` (${session.txCode.length} ${session.txCode.input_mode === 'text' ? 'characters' : 'digits'})` : ''}`}
                      value={txCode} onChangeText={setTxCode} keyboardType={session.txCode.input_mode === 'text' ? 'default' : 'number-pad'}
                      placeholder={session.txCode.description ?? 'Code sent to you by the issuer'} />
                  ) : null}
                  <Button testID="offer-accept" title="Accept" busy={busy === 'accept'} disabled={!!session.txCode && !txCode.trim()} onPress={accept} />
                </>
              ) : (
                <>
                  {registered ? <Info message={`MOSIP issuer: registered client ${registered.clientId}, Mimoto token proxy, redirect ${registered.redirectUri}.`} /> : null}
                  <Button testID="auth-begin" title={auth ? 'Open authorization page again' : 'Authorize with issuer'} busy={busy === 'auth'}
                    onPress={auth ? () => (Platform.OS === 'web' ? window.open(auth.authorizationUrl, '_blank') : WebBrowser.openBrowserAsync(auth.authorizationUrl)) : authorize} />
                  {auth ? (
                    <View style={{ marginTop: 10 }}>
                      <Text style={s.hint}>Authorization URL:</Text>
                      <Text testID="auth-url" selectable numberOfLines={3} style={[s.hint, s.mono, { color: colors.primary, marginBottom: 6 }]}>{auth.authorizationUrl}</Text>
                      <Info message={Platform.OS === 'web' || registered
                        ? `After signing in you are redirected to ${auth.redirectUri}. ${auth.redirectUri.startsWith('http') && Platform.OS === 'web' ? 'This tab continues automatically; otherwise paste' : 'A browser cannot open that; copy'} the full redirect URL (e.g. from the address bar or devtools) and paste it here.`
                        : 'Complete sign-in in the browser; the wallet continues when it is redirected back.'} />
                      <Field testID="auth-callback-input" label="Redirect URL" value={callback} onChangeText={setCallback} multiline placeholder={`${auth.redirectUri}?code=...&state=...`} />
                      <Button testID="auth-complete" title="Complete" busy={busy === 'complete'} disabled={!callback.trim()} onPress={() => complete(callback)} />
                    </View>
                  ) : null}
                </>
              )}
              <Info message={progress} testID="receive-progress" />
              <ErrorBox message={error} testID="receive-error" />
            </Section>
          ) : (
            <Section title="Received" testID="issued-section">
              {issued.map((c, i) => {
                const v = credentialView(c);
                const fails = c.report?.checks.filter((x) => x.status === 'fail').length ?? 0;
                return (
                  <View key={c.id} testID={`issued-${i}`} style={{ paddingVertical: 8, gap: 6 }}>
                    <Text style={s.label}>{v.title} <Text style={s.hint}>({c.format})</Text></Text>
                    {c.pending ? <Info message={`Deferred: transaction ${c.pending.transactionId}`} /> : <TrustLine trust={c.report?.trust} valid={c.report?.valid} testIDPrefix={`issued-trust-${i}`} />}
                    <Text style={s.hint}>{c.report ? `${c.report.checks.length} checks, ${fails} failed` : 'not verified'}</Text>
                    <Button title="View details" kind="secondary" onPress={() => navigation.navigate('Credential', { id: c.id })} />
                  </View>
                );
              })}
              <Button testID="receive-done" title="Done" onPress={() => navigation.popToTop()} />
            </Section>
          )}
          {!issued ? <Button title="Start over" kind="secondary" onPress={reset} /> : null}
        </>
      ) : null}
    </ScrollView>
  );
}
