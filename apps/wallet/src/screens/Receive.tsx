/**
 * Receive: OpenID4VCI issuance from a pasted / scanned offer, or from an offer of one of the demo issuers.
 * Pre-authorized code (+ tx_code) and authorization code flows (device: auth session; web: new tab + paste).
 *
 * The issuer's trust decision is shown before a token or credential is requested from it (the wallet has then read
 * the offer and the issuer's public metadata, nothing else):
 *  - TRUSTED: the user accepts or authorizes.
 *  - UNKNOWN: a warning, and nothing can be requested until the user chose to continue with the unknown issuer.
 *  - NOT_TRUSTED: the wallet refuses (wallet.receive throws issuer_not_trusted); the reason is shown and that is all.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Linking, Platform, ScrollView, Text, View } from 'react-native';
import * as WebBrowser from 'expo-web-browser';
import * as Clipboard from 'expo-clipboard';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { IssuanceError, type IssuanceSession, type IssuedCredential, type VerificationReport } from '@vctrust/wallet-core';
import { authCallbacks, OAUTH_CHANNEL, type RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { credentialView, issuerView, pickLocale } from '../wallet/display';
import { DEMO_ISSUERS, type DemoIssuer } from '../config/defaults';
import { ScanButton } from '../components/QrScanner';
import { Button, Checks, checkSummary, colors, ErrorBox, Field, Info, KV, Logo, s, Section, Segmented, SourcePill, TrustLine, WarningBox } from '../components/ui';

const errMsg = (e: unknown) => {
  const err = e as Error & { code?: string };
  return `${err.message ?? String(e)}${err.code && !String(err.message).includes(err.code) ? ` (${err.code})` : ''}`;
};

function configLabel(config: Record<string, unknown>, id: string) {
  const md = (config.credential_metadata ?? {}) as Record<string, unknown>;
  const d = pickLocale(md.display as { name?: string; locale?: string }[] | undefined);
  const type = (config.doctype ?? config.vct ?? ((config.credential_definition as { type?: string[] } | undefined)?.type ?? []).slice(-1)[0]) as string | undefined;
  return { name: d?.name ?? id, format: String(config.format ?? '?'), type };
}

const GRANTS = ['pre-authorized_code', 'authorization_code'] as const;

/** The demo issuers: an offer from the reference issuer's admin API (development), or the page where the user creates one. */
function DemoIssuers({ onOffer }: { onOffer: (offer: string) => void }) {
  const [grant, setGrant] = useState<(typeof GRANTS)[number]>('pre-authorized_code');
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();

  const createOffer = async (issuer: DemoIssuer, configurationId: string) => {
    setBusy(configurationId); setError(undefined);
    try {
      const r = await fetch(issuer.offerApi!, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ configurationIds: [configurationId], grant }) });
      if (!r.ok) throw new Error(`${issuer.name} answered HTTP ${r.status}`);
      const { credentialOfferUri } = (await r.json()) as { credentialOfferUri?: string };
      if (!credentialOfferUri) throw new Error(`${issuer.name} returned no offer`);
      onOffer(credentialOfferUri);
    } catch (e) {
      setError(`No offer from ${issuer.url}: ${errMsg(e)}. Is it running (scripts/dev-up.sh)?`);
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <>
      {DEMO_ISSUERS.map((issuer) => (
        <Section key={issuer.id} title={issuer.name} testID={`demo-issuer-${issuer.id}`}>
          <Text selectable style={s.hint}>{issuer.url}</Text>
          <Text style={[s.hint, { marginVertical: 6 }]}>{issuer.description}</Text>
          {issuer.offerApi ? (
            <>
              <Segmented testID={`demo-grant-${issuer.id}`} label="Grant" options={GRANTS} value={grant} onChange={setGrant} />
              {issuer.configurations?.map((c) => (
                <Button key={c.id} testID={`demo-offer-${c.id}`} title={c.label} kind="secondary" busy={busy === c.id} disabled={!!busy} style={{ marginTop: 6 }}
                  onPress={() => createOffer(issuer, c.id)} />
              ))}
              <Text style={[s.hint, { marginTop: 6 }]}>Each button asks the issuer for an offer and loads it; the issuer's trust is shown before anything else is requested.</Text>
            </>
          ) : null}
          {issuer.offerPage ? (
            <Button testID={`demo-open-${issuer.id}`} title={`Open ${issuer.offerPage.replace(/^https:\/\//, '')}`} kind="secondary"
              onPress={() => (Platform.OS === 'web' ? window.open(issuer.offerPage, '_blank') : Linking.openURL(issuer.offerPage!).catch(() => undefined))} />
          ) : null}
        </Section>
      ))}
      <ErrorBox message={error} testID="demo-issuer-error" />
    </>
  );
}

/** Who the issuer is and how far it is trusted. A logo is shown (and fetched) only for a TRUSTED issuer. */
function IssuerSection({ session }: { session: IssuanceSession }) {
  const trust = session.issuerTrust;
  const registered = pickLocale(trust.entity?.display);
  const declared = issuerView(session.issuerDisplay, session.credentialIssuer);
  const trusted = trust.decision === 'TRUSTED';
  return (
    <Section title="Issuer" testID="issuer-section" right={<SourcePill source={session.metadata.source} testID="issuer-metadata-source-pill" />}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        {trusted ? <Logo uri={registered?.logoUri ?? declared.logo} size={44} /> : null}
        <View style={{ flex: 1 }}>
          <Text testID="issuer-name" style={{ fontSize: 17, fontWeight: '700', color: colors.text }}>{registered?.name ?? declared.name}</Text>
          {!registered?.name ? <Text testID="issuer-name-claimed" style={[s.hint, { color: colors.amber }]}>Name given by the issuer itself, not by a trust list</Text> : null}
          <Text selectable style={s.hint}>{session.credentialIssuer}</Text>
        </View>
      </View>
      <TrustLine trust={trust} testIDPrefix="issuer-trust" />
      <View style={{ marginTop: 8 }}>
        <KV k="Framework" v={trust.framework?.name ?? '—'} />
        <KV k="Registered as" v={trust.entity ? (registered?.name ?? trust.entity.id) : '—'} testID="issuer-registered-as" />
        <KV k="Metadata via" v={session.metadata.source} testID="issuer-metadata-source" />
        {session.metadata.signedMetadata ? <KV k="Signed metadata" v={session.metadata.signedMetadataVerified ? 'verified' : 'NOT verified'} /> : null}
        {session.metadata.warnings?.length ? <KV k="Metadata notes" v={session.metadata.warnings.join('\n')} /> : null}
      </View>
      {trust.reasons?.filter((r) => r.severity !== 'INFO').map((r, i) => (
        <Text key={i} testID={`issuer-trust-reason-${i}`} style={[s.hint, { color: r.severity === 'ERROR' ? colors.red : colors.amber }]}>[{r.severity}] {r.message}</Text>
      ))}
    </Section>
  );
}

/** A credential the wallet refused, with the verification report the refusal rests on. */
interface Refused { message: string; report?: VerificationReport }

export default function ReceiveScreen({ navigation, route }: NativeStackScreenProps<RootStack, 'Receive'>) {
  const { wallet, refresh, refreshTrustStatus } = useWallet();
  const [tab, setTab] = useState<'offer' | 'issuers'>('offer');
  const [input, setInput] = useState(route.params?.uri ?? '');
  const [session, setSession] = useState<IssuanceSession>();
  /** the user's explicit choice to go on with an issuer the trust layer does not know */
  const [confirmedUnknown, setConfirmedUnknown] = useState(false);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  /** the trust layer refuses the issuer: nothing can be done with this offer */
  const [issuerRefused, setIssuerRefused] = useState<string>();
  const [refused, setRefused] = useState<Refused>();
  const [progress, setProgress] = useState<string>();
  const [txCode, setTxCode] = useState('');
  const [auth, setAuth] = useState<{ authorizationUrl: string; redirectUri: string }>();
  const [callback, setCallback] = useState('');
  const [issued, setIssued] = useState<IssuedCredential[]>();
  const completing = useRef(false);

  const reset = () => {
    setSession(undefined); setError(undefined); setIssuerRefused(undefined); setRefused(undefined); setIssued(undefined); setAuth(undefined);
    setCallback(''); setTxCode(''); setProgress(undefined); setConfirmedUnknown(false);
    completing.current = false;
  };

  const load = useCallback(async (uri: string) => {
    reset();
    if (!uri.trim()) return;
    setBusy('load');
    try {
      setSession(await wallet.receive(uri.trim()));
    } catch (e) {
      if (e instanceof IssuanceError && e.code === 'issuer_not_trusted') setIssuerRefused(e.message);
      else setError(errMsg(e));
    } finally {
      setBusy(undefined);
      void refreshTrustStatus();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet, refreshTrustStatus]);

  useEffect(() => {
    if (route.params?.uri) {
      setTab('offer');
      setInput(route.params.uri);
      load(route.params.uri);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.params?.nonce]);

  const finish = async (creds: IssuedCredential[]) => {
    await wallet.store(creds);
    await refresh();
    setIssued(creds);
  };

  /** Shows why issuance stopped; credentials of the same offer issued before the failure are still kept. */
  const failed = async (e: unknown) => {
    if (e instanceof IssuanceError && e.report) setRefused({ message: e.message, report: e.report });
    else setError(errMsg(e));
    if (e instanceof IssuanceError && e.issued.length) await finish(e.issued).catch(() => undefined);
  };

  const confirmUnknown = () => {
    if (!session) return;
    session.confirmUnknownIssuer();
    setConfirmedUnknown(true);
  };

  const accept = async () => {
    if (!session) return;
    setBusy('accept'); setError(undefined); setRefused(undefined); setProgress('Requesting token and credential…');
    try {
      await finish(await session.acceptPreAuthorized(session.txCode ? txCode.trim() : undefined));
    } catch (e) {
      await failed(e);
    } finally {
      setBusy(undefined); setProgress(undefined);
    }
  };

  const complete = useCallback(async (url: string) => {
    if (!session || completing.current) return;
    completing.current = true;
    setBusy('complete'); setError(undefined); setRefused(undefined); setProgress('Exchanging the authorization code…');
    try {
      await finish(await session.completeAuthorization(url.trim()));
    } catch (e) {
      await failed(e);
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

  const unknown = !!session && session.issuerTrust.decision !== 'TRUSTED';
  const idle = !session && !issuerRefused;

  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled" testID="receive-screen">
      {idle ? (
        <View style={{ flexDirection: 'row', gap: 8 }}>
          <Button testID="tab-offer" title="Offer" kind={tab === 'offer' ? 'primary' : 'secondary'} onPress={() => setTab('offer')} style={{ flex: 1 }} />
          <Button testID="tab-issuers" title="Demo issuers" kind={tab === 'issuers' ? 'primary' : 'secondary'} onPress={() => setTab('issuers')} style={{ flex: 1 }} />
        </View>
      ) : null}

      {idle && tab === 'offer' ? (
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

      {idle && tab === 'issuers' ? (
        <>
          <DemoIssuers onOffer={(offer) => { setInput(offer); load(offer); }} />
          <Info message={busy === 'load' ? 'Loading the offer…' : undefined} />
          <ErrorBox message={error} testID="receive-error" />
        </>
      ) : null}

      {issuerRefused ? (
        <Section title="Issuer refused" testID="issuer-refused-section">
          <ErrorBox message={issuerRefused} testID="issuer-refused" />
          <Text style={s.hint}>The trust decision about this issuer is NOT_TRUSTED. The wallet requests no credential from it, and this cannot be overridden.</Text>
          <Button testID="receive-start-over" title="Start over" kind="secondary" style={{ marginTop: 10 }} onPress={reset} />
        </Section>
      ) : null}

      {session ? (
        <>
          <IssuerSection session={session} />

          {unknown ? (
            <WarningBox testID="issuer-unknown-warning"
              message={confirmedUnknown
                ? 'You chose to continue with an issuer no trust list vouches for. A credential is kept only if it verifies, and one signed with a certificate that chains to no trusted anchor is refused.'
                : `Unknown issuer: no trust list vouches for ${session.credentialIssuer}. Only its public metadata has been read; no credential has been requested. `
                  + 'If you continue, a credential is kept only if it verifies, and one signed with a certificate that chains to no trusted anchor is still refused.'}>
              {session.needsConfirmation
                ? <Button testID="issuer-confirm-unknown" title="Continue with this unknown issuer" kind="danger" onPress={confirmUnknown} /> : null}
            </WarningBox>
          ) : null}

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

          {issued ? (
            <Section title="Received" testID="issued-section">
              {issued.map((c, i) => {
                const v = credentialView(c);
                return (
                  <View key={c.id} testID={`issued-${i}`} style={{ paddingVertical: 8, gap: 6 }}>
                    <Text style={s.label}>{v.title} <Text style={s.hint}>({c.format})</Text></Text>
                    {c.pending ? <Info message={`Deferred: transaction ${c.pending.transactionId}`} /> : <TrustLine trust={c.report?.trust} valid={c.report?.valid} testIDPrefix={`issued-trust-${i}`} />}
                    <Text testID={`issued-checks-${i}`} style={s.hint}>{c.report ? checkSummary(c.report) : 'not verified yet'}</Text>
                    {c.report ? <Checks report={c.report} only={['warn', 'fail']} testID={`issued-findings-${i}`} /> : null}
                    <Button title="View details" kind="secondary" onPress={() => navigation.navigate('Credential', { id: c.id })} />
                  </View>
                );
              })}
              <Button testID="receive-done" title="Done" onPress={() => navigation.popToTop()} />
            </Section>
          ) : session.needsConfirmation || refused ? null : (
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
                  <Button testID="auth-begin" title={auth ? 'Open authorization page again' : 'Authorize with issuer'} busy={busy === 'auth'}
                    onPress={auth ? () => (Platform.OS === 'web' ? window.open(auth.authorizationUrl, '_blank') : WebBrowser.openBrowserAsync(auth.authorizationUrl)) : authorize} />
                  {auth ? (
                    <View style={{ marginTop: 10 }}>
                      <Text style={s.hint}>Authorization URL:</Text>
                      <Text testID="auth-url" selectable numberOfLines={3} style={[s.hint, s.mono, { color: colors.primary, marginBottom: 6 }]}>{auth.authorizationUrl}</Text>
                      <Info message={Platform.OS === 'web'
                        ? `After signing in you are redirected to ${auth.redirectUri} and this tab continues. If it does not, paste the full redirect URL here.`
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
          )}

          {refused ? (
            <Section title="Credential refused" testID="refused-section">
              <ErrorBox message={refused.message} testID="refused-reason" />
              <Text style={s.hint}>The credential was not kept. An offer is used up by one attempt: start over with a new one.
                {refused.report ? ` The verification report (${checkSummary(refused.report)}):` : ''}</Text>
              {refused.report ? (
                <>
                  <View style={{ marginVertical: 6 }}><TrustLine trust={refused.report.trust} valid={refused.report.valid} testIDPrefix="refused-trust" /></View>
                  <Checks report={refused.report} testID="refused-report" />
                </>
              ) : null}
            </Section>
          ) : null}

          {!issued ? <Button testID="receive-start-over" title="Start over" kind="secondary" onPress={reset} /> : null}
        </>
      ) : null}
    </ScrollView>
  );
}
