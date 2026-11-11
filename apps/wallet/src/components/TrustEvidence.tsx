/** Full trust evidence of a TrustDecision: decision, summary, what it rests on, framework, entity, reasons, X.509 path or DID. */
import React from 'react';
import { Text, View } from 'react-native';
import type { CertificateRevocation, TrustDecision } from '@vctrust/trust-client';
import { pickLocale, shortDate } from '../wallet/display';
import { colors, decisionSourceLabel, KV, s, Section, TrustLine } from './ui';

export function TrustEvidence({ trust, title = 'Trust evidence', testIDPrefix = 'evidence' }: { trust?: TrustDecision | null; title?: string; testIDPrefix?: string }) {
  if (!trust) return <Section title={title}><Text style={s.hint}>Issuer trust was not evaluated.</Text></Section>;
  const ev = trust.evidence ?? {};
  const entity = trust.entity;
  return (
    <Section title={title} testID={testIDPrefix}>
      <TrustLine trust={trust} testIDPrefix={testIDPrefix} />
      <View style={{ marginTop: 8 }}>
        <KV k="Decided on" v={`${decisionSourceLabel(trust)}${trust.snapshot ? `, valid until ${shortDate(trust.snapshot.expiresAt)}` : ''}`} testID={`${testIDPrefix}-source-text`} />
        <KV k="Framework" v={trust.framework ? `${trust.framework.name} (${trust.framework.id})` : '—'} />
        <KV k="Entity" v={entity ? `${pickLocale(entity.display)?.name ?? entity.id} [${entity.id}, ${entity.status}]` : '—'} />
        {entity?.provenance?.sourceId ? <KV k="Registry source" v={`${entity.provenance.sourceId}${entity.provenance.sourceType ? ` (${entity.provenance.sourceType})` : ''}`} /> : null}
        {ev.matchedIdentifiers?.length ? <KV k="Matched" v={ev.matchedIdentifiers.join('\n')} mono /> : null}
        {ev.authorization ? <KV k="Authorized for" v={`${ev.authorization.format ?? '*'} ${ev.authorization.type ?? '*'}: ${ev.authorization.authorized ? 'yes' : 'NO'}${ev.authorization.rule ? ` (${ev.authorization.rule})` : ''}`} /> : null}
        <KV k="Evaluated" v={`${shortDate(trust.evaluatedAt)} (valid until ${shortDate(trust.validUntil)})`} />
      </View>
      {trust.reasons?.length ? (
        <View style={{ marginTop: 8 }}>
          <Text style={s.label}>Reasons</Text>
          {trust.reasons.map((r, i) => (
            <Text key={i} selectable style={[s.hint, { color: r.severity === 'ERROR' ? colors.red : r.severity === 'WARNING' ? colors.amber : colors.muted }]}>
              [{r.severity}] {r.code}: {r.message}
            </Text>
          ))}
        </View>
      ) : null}
      {ev.x509 ? (
        <View style={{ marginTop: 8 }} testID={`${testIDPrefix}-x509`}>
          <Text style={s.label}>X.509 path ({ev.x509.valid ? 'valid' : 'invalid'}, anchor {ev.x509.anchorFound ? 'found' : 'not found'}, profile {ev.x509.profile})</Text>
          {ev.x509.path.map((c, i) => (
            <View key={i} style={{ paddingLeft: 8 * i, paddingVertical: 3 }}>
              <Text selectable style={[s.hint, { color: colors.text }]}>{i === 0 ? '└' : '↳'} {c.subject}{c.ca ? ' (CA)' : ''}</Text>
              <Text selectable style={s.hint}>   issuer {c.issuer} · until {shortDate(c.notAfter)} · sha256 {c.sha256.slice(0, 16)}…</Text>
            </View>
          ))}
          {ev.x509.revocation?.length ? (
            <View testID={`${testIDPrefix}-revocation`}>
              {ev.x509.revocation.map((r, i) => <KV key={i} k={`Certificate ${r.index} status`} v={revocationText(r)} testID={`${testIDPrefix}-revocation-${r.index}`} />)}
            </View>
          ) : null}
          {ev.x509.issues.filter((x) => x.severity !== 'INFO').map((x, i) => <Text key={i} style={[s.hint, { color: x.severity === 'ERROR' ? colors.red : colors.amber }]}>[{x.severity}] {x.code}: {x.message}</Text>)}
        </View>
      ) : null}
      {ev.did ? (
        <View style={{ marginTop: 8 }} testID={`${testIDPrefix}-did`}>
          <Text style={s.label}>DID evidence</Text>
          <KV k="DID" v={ev.did.did} mono />
          <KV k="Resolved" v={ev.did.resolved ? 'yes' : `no${ev.did.error ? ` (${ev.did.error})` : ''}`} />
          {ev.did.verificationMethod ? <KV k="Key" v={`${ev.did.verificationMethod} (${ev.did.verificationMethodFound ? 'found' : 'missing'})`} mono /> : null}
          {ev.did.relationship ? <KV k="Relationship" v={`${ev.did.relationship}: ${ev.did.relationshipValid ? 'ok' : 'NOT authorized'}`} /> : null}
        </View>
      ) : null}
      {ev.trustedAuthorities?.length ? (
        <View style={{ marginTop: 8 }}>
          <Text style={s.label}>Trusted authorities</Text>
          {ev.trustedAuthorities.map((t, i) => <Text key={i} style={s.hint}>{t.type}: {t.matched ? `matched ${t.matchedValue ?? ''}` : 'no match'}</Text>)}
        </View>
      ) : null}
    </Section>
  );
}

/** e.g. "not revoked · CRL https://ca.example/crl (snapshot), next update 2027-10-26 00:00:00Z" */
function revocationText(r: CertificateRevocation): string {
  const where = r.method === 'ocsp' ? 'OCSP' : r.crlUrl ? `CRL ${r.crlUrl}` : 'CRL';
  const via = r.source ? ` (${r.source})` : '';
  switch (r.status) {
    case 'GOOD': return `not revoked · ${where}${via}${r.nextUpdate ? `, next update ${shortDate(r.nextUpdate)}` : ''}`;
    case 'REVOKED': return `REVOKED ${r.revokedAt ? shortDate(r.revokedAt) : ''} (${r.reason ?? 'unspecified'}) · ${where}${via}`;
    case 'ON_HOLD': return `ON HOLD since ${r.revokedAt ? shortDate(r.revokedAt) : '?'} · ${where}${via}`;
    default: return `unknown: ${r.reason ?? 'no revocation information'}`;
  }
}
