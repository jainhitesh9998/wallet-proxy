/** Small shared UI kit: buttons, toggles, sections, trust badges and check rows. testIDs map to data-testid on web. */
import React from 'react';
import { ActivityIndicator, Image, Platform, Pressable, StyleSheet, Text, TextInput, View, type TextInputProps, type ViewStyle } from 'react-native';
import { SvgUri, SvgXml } from 'react-native-svg';
import type { Decision, TrustDecision } from '@vctrust/trust-client';
import type { Check, VerificationReport } from '@vctrust/wallet-core';
import { shortDate } from '../wallet/display';

export const colors = {
  bg: '#f4f5f7', card: '#ffffff', text: '#1d2330', muted: '#5f6b7a', border: '#dde1e7', primary: '#2f54eb',
  green: '#1f8a4c', greenBg: '#e3f5ea', amber: '#9a6700', amberBg: '#fff4d6', red: '#c62828', redBg: '#fde7e7', grey: '#6b7280', greyBg: '#eceff3',
};

export function Button({ title, onPress, testID, disabled, busy, kind = 'primary', style }: {
  title: string; onPress: () => void; testID?: string; disabled?: boolean; busy?: boolean; kind?: 'primary' | 'secondary' | 'danger'; style?: ViewStyle;
}) {
  const off = disabled || busy;
  return (
    <Pressable testID={testID} accessibilityRole="button" disabled={off} onPress={onPress}
      style={({ pressed }) => [s.btn, kind === 'secondary' && s.btnSecondary, kind === 'danger' && s.btnDanger, off && s.btnDisabled, pressed && { opacity: 0.8 }, style]}>
      {busy ? <ActivityIndicator color={kind === 'secondary' ? colors.primary : '#fff'} /> : null}
      <Text style={[s.btnText, kind === 'secondary' && { color: colors.primary }]}>{title}</Text>
    </Pressable>
  );
}

export function Toggle({ label, value, onChange, testID, hint }: { label: string; value: boolean; onChange: (v: boolean) => void; testID?: string; hint?: string }) {
  return (
    <Pressable testID={testID} accessibilityRole="switch" accessibilityState={{ checked: value }} onPress={() => onChange(!value)} style={s.row}>
      <View style={{ flex: 1 }}>
        <Text style={s.label}>{label}</Text>
        {hint ? <Text style={s.hint}>{hint}</Text> : null}
      </View>
      <View style={[s.switch, value && s.switchOn]}>
        <Text testID={testID ? `${testID}-state` : undefined} style={[s.switchText, value && { color: '#fff' }]}>{value ? 'ON' : 'OFF'}</Text>
      </View>
    </Pressable>
  );
}

export function Segmented<T extends string>({ label, options, value, onChange, testID }: { label: string; options: readonly T[]; value: T; onChange: (v: T) => void; testID: string }) {
  return (
    <View style={s.row}>
      <Text style={[s.label, { flex: 1 }]}>{label}</Text>
      <View style={s.segment}>
        {options.map((o) => (
          <Pressable key={o} testID={`${testID}-${o}`} accessibilityRole="radio" accessibilityState={{ checked: o === value }} aria-checked={o === value} onPress={() => onChange(o)}
            style={[s.segmentItem, o === value && s.segmentItemOn]}>
            <Text style={[s.segmentText, o === value && { color: '#fff' }]}>{o}</Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

export function Section({ title, children, testID, right }: { title?: string; children: React.ReactNode; testID?: string; right?: React.ReactNode }) {
  return (
    <View testID={testID} style={s.section}>
      {title ? (
        <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
          <Text style={[s.sectionTitle, { flex: 1 }]}>{title}</Text>
          {right}
        </View>
      ) : null}
      {children}
    </View>
  );
}

export function Field({ label, testID, ...props }: TextInputProps & { label: string; testID?: string }) {
  return (
    <View style={{ marginBottom: 10 }}>
      <Text style={s.label}>{label}</Text>
      <TextInput testID={testID} autoCapitalize="none" autoCorrect={false} placeholderTextColor="#9aa3ae" {...props}
        style={[s.input, props.multiline && { minHeight: 80, textAlignVertical: 'top' }, props.style]} />
    </View>
  );
}

export function KV({ k, v, testID, mono }: { k: string; v: React.ReactNode; testID?: string; mono?: boolean }) {
  return (
    <View style={s.kv}>
      <Text style={s.kvKey}>{k}</Text>
      {typeof v === 'string' || typeof v === 'number'
        ? <Text testID={testID} selectable style={[s.kvVal, mono && s.mono]}>{String(v)}</Text>
        : <View style={{ flex: 1 }} testID={testID}>{v}</View>}
    </View>
  );
}

export function ErrorBox({ message, testID }: { message?: string; testID?: string }) {
  if (!message) return null;
  return <View style={[s.pill, { backgroundColor: colors.redBg, borderRadius: 8, padding: 10, marginVertical: 8 }]}><Text testID={testID} selectable style={{ color: colors.red }}>{message}</Text></View>;
}

/** Something the user has to know before going on; not an error. */
export function WarningBox({ message, testID, children }: { message: string; testID?: string; children?: React.ReactNode }) {
  return (
    <View style={{ backgroundColor: colors.amberBg, borderRadius: 8, padding: 10, marginVertical: 8, gap: 8 }}>
      <Text testID={testID} selectable style={{ color: colors.amber }}>{message}</Text>
      {children}
    </View>
  );
}

export function Info({ message, testID }: { message?: string; testID?: string }) {
  if (!message) return null;
  return <Text testID={testID} style={[s.hint, { marginVertical: 6 }]}>{message}</Text>;
}

const decisionColors: Record<Decision, [string, string]> = {
  TRUSTED: [colors.green, colors.greenBg], UNKNOWN: [colors.amber, colors.amberBg], NOT_TRUSTED: [colors.red, colors.redBg],
};

export function Pill({ text, color, bg, testID }: { text: string; color: string; bg: string; testID?: string }) {
  return <View style={[s.pill, { backgroundColor: bg }]}><Text testID={testID} style={[s.pillText, { color }]}>{text}</Text></View>;
}

export function DecisionBadge({ decision, testID }: { decision?: Decision | null; testID?: string }) {
  const [c, bg] = decision ? decisionColors[decision] : [colors.grey, colors.greyBg];
  return <Pill testID={testID} text={decision ?? 'NOT EVALUATED'} color={c} bg={bg} />;
}

/** Where a document (issuer metadata, a DID document, a status list) came from. */
export function SourcePill({ source, testID }: { source?: string; testID?: string }) {
  if (!source) return null;
  // The snapshot, the proxy and the party itself are the configured paths; 'fallback' (the proxy could not serve)
  // and 'cache' are worth noticing.
  const normal = source === 'proxy' || source === 'snapshot' || source === 'direct';
  return <Pill testID={testID} text={`source: ${source}`} color={normal ? colors.primary : colors.amber} bg={normal ? '#e8edff' : colors.amberBg} />;
}

/**
 * What a trust decision rests on. Decisions are always made on this device: from the trust snapshot, or, while no
 * snapshot is usable, from the trust pinned in the app.
 */
export function decisionSourceLabel(trust: TrustDecision): string {
  if (trust.source === 'snapshot') return `device · snapshot of ${shortDate(trust.snapshot?.issuedAt)}${trust.snapshot?.stale ? ' (expired)' : ''}`;
  if (trust.source === 'pinned') return 'device · pinned trust, no snapshot';
  // A report stored by an earlier version of the app; re-verifying replaces it.
  return `earlier app version (${String(trust.source)})`;
}

export function DecisionSourcePill({ trust, testID }: { trust?: TrustDecision | null; testID?: string }) {
  if (!trust) return null;
  const normal = trust.source === 'snapshot' && !trust.snapshot?.stale;
  return <Pill testID={testID} text={`decided on: ${decisionSourceLabel(trust)}`} color={normal ? colors.primary : colors.amber} bg={normal ? '#e8edff' : colors.amberBg} />;
}

/** Decision + who decided + summary (and optionally a "valid signature" indicator). */
export function TrustLine({ trust, valid, testIDPrefix }: { trust?: TrustDecision | null; valid?: boolean; testIDPrefix: string }) {
  return (
    <View>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
        <DecisionBadge decision={trust?.decision} testID={`${testIDPrefix}-decision`} />
        <DecisionSourcePill trust={trust} testID={`${testIDPrefix}-source`} />
        {valid !== undefined ? (
          <Pill testID={`${testIDPrefix}-valid`} text={valid ? '✓ valid signature' : '✗ invalid'} color={valid ? colors.green : colors.red} bg={valid ? colors.greenBg : colors.redBg} />
        ) : null}
      </View>
      {trust?.summary ? <Text style={[s.hint, { marginTop: 4 }]}>{trust.summary}</Text> : null}
    </View>
  );
}

const checkStyle = { pass: [colors.green, '✓'], warn: [colors.amber, '!'], fail: [colors.red, '✗'], skip: [colors.grey, '–'] } as const;

export function CheckRow({ check }: { check: Check }) {
  const [c, icon] = checkStyle[check.status] ?? checkStyle.skip;
  return (
    <View testID={`check-${check.id}`} style={s.check}>
      <Text style={[s.checkIcon, { color: c }]}>{icon}</Text>
      <View style={{ flex: 1 }}>
        <Text style={s.label}>{check.label} <Text testID={`check-status-${check.id}`} style={{ color: c, fontWeight: '700' }}>{String(check.status).toUpperCase()}</Text></Text>
        {check.detail ? <Text selectable style={s.hint}>{check.detail}</Text> : null}
      </View>
    </View>
  );
}

/** How many checks of a report passed, warned, failed or were skipped. */
export function checkCounts(report: Pick<VerificationReport, 'checks'>): Record<Check['status'], number> {
  const n = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of report.checks) n[c.status] = (n[c.status] ?? 0) + 1;
  return n;
}

export function checkSummary(report: Pick<VerificationReport, 'checks'>): string {
  const n = checkCounts(report);
  return `${report.checks.length} checks: ${n.pass} passed, ${n.warn} warning(s), ${n.fail} failed${n.skip ? `, ${n.skip} skipped` : ''}`;
}

/**
 * Every check of a verification report as the verifier reported it: nothing is filtered or renamed here, so a new
 * check shows up without a change to the app. {@code only} narrows the list (the warnings and failures of a summary).
 */
export function Checks({ report, only, testID }: { report: Pick<VerificationReport, 'checks'>; only?: readonly Check['status'][]; testID?: string }) {
  const list = only ? report.checks.filter((c) => only.includes(c.status)) : report.checks;
  if (list.length === 0) return null;
  return <View testID={testID}>{list.map((c, i) => <CheckRow key={`${c.id}-${i}`} check={c} />)}</View>;
}

const SVG_DATA = /^data:image\/svg\+xml(;base64)?,/i;

function svgXml(uri: string): string | undefined {
  const m = SVG_DATA.exec(uri);
  if (!m) return undefined;
  const data = uri.slice(m[0].length);
  try {
    return m[1] ? atob(data) : decodeURIComponent(data);
  } catch {
    return undefined;
  }
}

/**
 * Issuer / verifier / credential logo. HAIP 1.0 §4.1: PNG and SVG, by https or data: URI. Native Image has no SVG
 * support, so SVG goes through react-native-svg; browsers render both in an img.
 */
export function Logo({ uri, size = 40 }: { uri?: string; size?: number }) {
  if (!uri) return null;
  const style = { width: size, height: size, borderRadius: 6, backgroundColor: '#fff' };
  if (Platform.OS !== 'web') {
    const xml = svgXml(uri);
    if (xml) return <View style={style}><SvgXml xml={xml} width={size} height={size} /></View>;
    if (/^https:\/\/[^?#]+\.svg([?#].*)?$/i.test(uri)) return <View style={style}><SvgUri uri={uri} width={size} height={size} /></View>;
  }
  return <Image source={{ uri }} style={style} resizeMode="contain" accessibilityIgnoresInvertColors />;
}

export const s = StyleSheet.create({
  screen: { padding: 16, paddingBottom: 48, gap: 12, maxWidth: 760, width: '100%', alignSelf: 'center' },
  btn: { backgroundColor: colors.primary, paddingVertical: 11, paddingHorizontal: 16, borderRadius: 8, alignItems: 'center', justifyContent: 'center', flexDirection: 'row', gap: 8 },
  btnSecondary: { backgroundColor: '#fff', borderWidth: 1, borderColor: colors.primary },
  btnDanger: { backgroundColor: colors.red },
  btnDisabled: { opacity: 0.45 },
  btnText: { color: '#fff', fontWeight: '600', fontSize: 15 },
  row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, gap: 10 },
  label: { color: colors.text, fontSize: 14, fontWeight: '500' },
  hint: { color: colors.muted, fontSize: 12 },
  switch: { width: 52, paddingVertical: 4, borderRadius: 14, backgroundColor: colors.greyBg, alignItems: 'center' },
  switchOn: { backgroundColor: colors.green },
  switchText: { fontSize: 12, fontWeight: '700', color: colors.muted },
  segment: { flexDirection: 'row', borderWidth: 1, borderColor: colors.primary, borderRadius: 8, overflow: 'hidden' },
  segmentItem: { paddingHorizontal: 10, paddingVertical: 6 },
  segmentItemOn: { backgroundColor: colors.primary },
  segmentText: { color: colors.primary, fontSize: 13 },
  section: { backgroundColor: colors.card, borderRadius: 12, padding: 14, borderWidth: 1, borderColor: colors.border },
  sectionTitle: { fontSize: 16, fontWeight: '700', color: colors.text },
  input: { borderWidth: 1, borderColor: colors.border, borderRadius: 8, padding: 10, marginTop: 4, backgroundColor: '#fff', color: colors.text, fontSize: 14 },
  kv: { flexDirection: 'row', paddingVertical: 4, gap: 10 },
  kvKey: { width: 120, color: colors.muted, fontSize: 13 },
  kvVal: { flex: 1, color: colors.text, fontSize: 13 },
  // Long identifiers (did:jwk, URLs) must wrap on web instead of overflowing the card.
  mono: { fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' }), fontSize: 12,
    ...(Platform.OS === 'web' ? ({ wordBreak: 'break-all' } as object) : {}) },
  pill: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: 10, alignSelf: 'flex-start' },
  pillText: { fontSize: 12, fontWeight: '700' },
  check: { flexDirection: 'row', gap: 8, paddingVertical: 5, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: colors.border },
  checkIcon: { width: 16, fontWeight: '900', fontSize: 15 },
});
