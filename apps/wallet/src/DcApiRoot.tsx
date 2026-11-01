/**
 * The screen Android shows when the user picks this wallet for a Digital Credentials API request (OpenID4VP Appendix A):
 * the verifier (origin, signature, trust), what it asks for, and Share / Decline. The response goes back through the
 * platform to the page or app that asked; declining or closing on an error cancels, so the verifier learns nothing
 * (OpenID4VP §15.9.2) unless the user chooses to tell it.
 */
import React, { useEffect, useRef, useState } from 'react';
import { ScrollView, Text, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { dcApiError, pickDcApiRequest, PresentationRequestError, type PresentationSession } from '@vctrust/wallet-core';
import { cancel, finish, type DcApiLaunch } from '../modules/dc-api';
import { WalletProvider, useWallet } from './wallet/WalletContext';
import { RequestedCredentials, VerifierSection } from './components/Presentation';
import { TrustEvidence } from './components/TrustEvidence';
import { Button, colors, ErrorBox, Info, s, Section } from './components/ui';

/** The platform's selection: which request its matcher answered and, per DCQL query, the credential the user tapped. */
function readSelection(json?: string): { requestIndex?: number; credentials: Record<string, string> } {
  try {
    const o = JSON.parse(json ?? '{}') as { requestIndex?: number; credentials?: Record<string, string> };
    return { requestIndex: typeof o.requestIndex === 'number' ? o.requestIndex : undefined, credentials: o.credentials ?? {} };
  } catch {
    return { credentials: {} };
  }
}

function DcApiConsent({ requestJson, origin, selectionJson, token = '', error: launchError }: DcApiLaunch) {
  const { ready, wallet, refresh } = useWallet();
  const [session, setSession] = useState<PresentationSession>();
  const [protocol, setProtocol] = useState<string>();
  const [choice, setChoice] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [reportable, setReportable] = useState<PresentationRequestError>();
  /** set on the first tap: a second tap must not present (and use up) another instance */
  const sharing = useRef(false);

  useEffect(() => {
    if (!ready) return;
    (async () => {
      try {
        if (launchError) throw new Error(launchError);
        if (!requestJson || !origin) throw new Error('The platform passed no request or no verifier origin');
        const selection = readSelection(selectionJson);
        const picked = pickDcApiRequest(requestJson, origin, selection.requestIndex);
        if (!picked) throw new Error('The request has no OpenID4VP 1.0 protocol this wallet supports');
        setProtocol(picked.protocol);
        const p = await wallet.startDcApiPresentation(picked);
        setSession(p);
        // Preselect what the user tapped in the system picker; the wallet still checks it against the request.
        setChoice(Object.fromEntries(p.dcql.matches.filter((m) => m.candidates[0]).map((m) => {
          const tapped = m.candidates.find((c) => c.id === selection.credentials[m.query.id]);
          return [m.query.id, (tapped ?? m.candidates[0]!).id];
        })));
      } catch (e) {
        setError((e as Error).message);
        if (e instanceof PresentationRequestError && e.reportTo?.dcApi) setReportable(e);
      }
    })();
  }, [ready]); // eslint-disable-line react-hooks/exhaustive-deps

  const share = async () => {
    if (!session || !protocol || sharing.current) return;
    sharing.current = true;
    setBusy('share'); setError(undefined);
    try {
      const r = await session.respond(choice);
      if (!finish(token, protocol, r.dcApi!)) setError('This request is no longer open.');
      refresh().catch(() => undefined);              // the instance count; never in the way of the answer
    } catch (e) {
      setError((e as Error).message);
      sharing.current = false;
      setBusy(undefined);
    }
  };

  return (
    <ScrollView contentContainerStyle={s.screen} testID="dcapi-screen">
      <Text style={{ fontSize: 20, fontWeight: '700', color: colors.text }}>Share with {origin ?? 'a verifier'}?</Text>
      <Text style={s.hint} testID="dcapi-protocol">Digital Credentials API request{protocol ? ` (${protocol})` : ''}</Text>
      {!session && !error ? <Info message="Reading the request…" testID="dcapi-loading" /> : null}
      {session ? (
        <>
          <VerifierSection session={session} />
          <RequestedCredentials session={session} choice={choice} setChoice={setChoice} />
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <Button testID="dcapi-decline" title="Decline" kind="secondary" disabled={!!busy} onPress={() => cancel(token)} style={{ flex: 1 }} />
            <Button testID="dcapi-share" title="Share" busy={busy === 'share'} disabled={!session.dcql.satisfied || !!session.verifier.refusal || !!busy}
              onPress={share} style={{ flex: 2 }} />
          </View>
          <TrustEvidence trust={session.verifier.trust} title="Verifier trust evidence" testIDPrefix="verifier-evidence" />
        </>
      ) : null}
      <ErrorBox message={error} testID="dcapi-error" />
      {error && !session ? (
        <Section title="This request cannot be answered">
          <Text style={s.hint}>
            Closing tells the site nothing.{reportable ? ` You can instead tell ${origin ?? 'the site'} that the request was invalid (${reportable.code}); nothing else is sent.` : ''}
          </Text>
          <View style={{ flexDirection: 'row', gap: 8, marginTop: 8 }}>
            <Button testID="dcapi-close" title="Close" kind="secondary" onPress={() => cancel(token)} style={{ flex: 1 }} />
            {reportable && protocol ? (
              <Button testID="dcapi-report-error" title="Tell the site" onPress={() => finish(token, protocol, dcApiError(reportable))} style={{ flex: 1 }} />
            ) : null}
          </View>
        </Section>
      ) : null}
    </ScrollView>
  );
}

export default function DcApiRoot(props: DcApiLaunch) {
  return (
    <SafeAreaProvider>
      <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
        <WalletProvider>
          <DcApiConsent {...props} />
        </WalletProvider>
      </SafeAreaView>
      <StatusBar style="dark" />
    </SafeAreaProvider>
  );
}
