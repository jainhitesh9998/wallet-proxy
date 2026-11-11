/** The parts of a presentation request the user decides on: who asks (and how far they are trusted) and what for. */
import React from 'react';
import { Pressable, Text, View } from 'react-native';
import { pickInstance, type PresentationSession } from '@vctrust/wallet-core';
import { claimNames, credentialView, humanize, nameFor, shortDate } from '../wallet/display';
import { ErrorBox, KV, Logo, colors, s, Section, Toggle, TrustLine, WarningBox } from './ui';

export function VerifierSection({ session }: { session: PresentationSession }) {
  const v = session.verifier;
  return (
    <Section title="Verifier" testID="verifier-section">
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        {/* logoUri is set only for a verifier the trust layer knows: images of unknown parties are not fetched */}
        <Logo uri={v.logoUri} size={44} />
        <View style={{ flex: 1 }}>
          <Text testID="verifier-name" style={{ fontSize: 17, fontWeight: '700', color: colors.text }}>{v.name ?? 'Unnamed verifier'}</Text>
          {v.nameSelfDeclared ? <Text testID="verifier-name-claimed" style={[s.hint, { color: colors.amber }]}>Name given by the verifier itself, not by a trust list</Text> : null}
          <Text selectable style={s.hint} numberOfLines={2}>{v.clientId}</Text>
        </View>
      </View>
      <TrustLine trust={v.trust} testIDPrefix="verifier-trust" />
      {v.refusal ? <ErrorBox testID="verifier-refusal" message={`Sharing is blocked: ${v.refusal}`} /> : null}
      {!v.refusal && v.trust.decision !== 'TRUSTED' ? (
        <WarningBox testID="verifier-unknown-warning"
          message={`Unknown verifier: no trust list vouches for it. What you share goes to ${v.origin ?? session.request.responseUri ?? v.clientId}.`} />
      ) : null}
      <View style={{ marginTop: 8 }}>
        <KV k="Client id prefix" v={v.prefix} />
        <KV k="Response mode" v={session.request.responseMode} />
        {session.request.responseUri ? <KV k="Response URI" v={session.request.responseUri} mono /> : null}
        {v.origin ? <KV k="Origin" v={v.origin} mono testID="verifier-origin" /> : null}
      </View>
      <Text style={[s.label, { marginTop: 8 }]}>Request checks</Text>
      {v.checks.map((c, i) => (
        <Text key={i} testID={`verifier-check-${i}`} style={[s.hint, { color: c.ok ? colors.green : colors.amber }]}>{c.ok ? '✓' : '!'} {c.label}{c.detail ? `: ${c.detail}` : ''}</Text>
      ))}
    </Section>
  );
}

/**
 * What the verifier asks for. Credentials of required queries are shared; credentials the verifier marked optional
 * (DcqlResult.optional) are off until the user turns them on ({@code include}); nothing else is ever shared.
 */
export function RequestedCredentials({ session, choice, setChoice, include, setInclude }: {
  session: PresentationSession; choice: Record<string, string>; setChoice(c: Record<string, string>): void; include: string[]; setInclude(ids: string[]): void;
}) {
  return (
    <Section title="Requested credentials" testID="dcql-section">
      {!session.dcql.satisfied ? <ErrorBox testID="dcql-unsatisfied" message={session.dcql.reason ?? 'This wallet cannot satisfy the request'} /> : null}
      {session.dcql.matches.map((m) => {
        const required = session.dcql.selected.includes(m.query.id);
        const optional = !required && session.dcql.optional.includes(m.query.id);
        const added = optional && include.includes(m.query.id);
        const shared = required || added;
        const meta = m.query.meta ?? {};
        const type = (meta.doctype_value ?? (meta.vct_values as string[] | undefined)?.join(', ')) as string | undefined;
        return (
          <View key={m.query.id} testID={`dcql-query-${m.query.id}`} style={{ paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: colors.border, gap: 4, opacity: shared ? 1 : 0.6 }}>
            <Text testID={`dcql-status-${m.query.id}`} style={s.label}>
              {m.query.id} · {m.query.format}{type ? ` · ${type}` : ''} · {required ? 'required' : optional ? (added ? 'optional, will be shared' : 'optional, not shared') : 'not needed, not shared'}
            </Text>
            {optional ? (
              <Toggle testID={`dcql-include-${m.query.id}`} label="Share this optional credential too" value={added}
                hint="The verifier does not require it. It is shared only if you turn this on."
                onChange={(on) => setInclude(on ? [...include, m.query.id] : include.filter((id) => id !== m.query.id))} />
            ) : null}
            <Text style={s.hint}>{shared ? 'Claims to share:' : 'Claims asked for:'}</Text>
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
                    <Text style={s.hint}>issued {shortDate(c.issuedAt)} · issuer {c.report?.trust?.decision ?? 'not evaluated'}</Text>
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
  );
}
