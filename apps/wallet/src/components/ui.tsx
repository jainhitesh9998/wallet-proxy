/** Small shared UI kit: buttons, toggles, sections, trust badges and check rows. testIDs map to data-testid on web. */
import React from 'react';
import { ActivityIndicator, Image, Platform, Pressable, StyleSheet, Text, TextInput, View, type TextInputProps, type ViewStyle } from 'react-native';
import type { Decision, TrustDecision } from '@vctrust/trust-client';
import type { Check } from '@vctrust/wallet-core';

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
          <Pressable key={o} testID={`${testID}-${o}`} accessibilityRole="button" accessibilityState={{ selected: o === value }} onPress={() => onChange(o)}
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

export function SourcePill({ source, testID }: { source?: string; testID?: string }) {
  if (!source) return null;
  // trust-service, the signed trust list and the party itself are normal paths; cache / fallback are degraded ones.
  const normal = source === 'trust-service' || source === 'snapshot' || source === 'direct';
  return <Pill testID={testID} text={`source: ${source}`} color={normal ? colors.primary : colors.amber} bg={normal ? '#e8edff' : colors.amberBg} />;
}

/** Who made a trust decision: this device (from which trust list) or the trust service. */
export function decisionSourceLabel(trust: TrustDecision): string {
  if (trust.source === 'trust-service') return 'trust service';
  if (trust.source === 'snapshot') return `device · list v${trust.snapshot?.version ?? '?'}${trust.snapshot?.stale ? ' (expired)' : ''}`;
  return 'device · no trust list';
}

export function DecisionSourcePill({ trust, testID }: { trust?: TrustDecision | null; testID?: string }) {
  if (!trust) return null;
  const normal = trust.source === 'trust-service' || (trust.source === 'snapshot' && !trust.snapshot?.stale);
  return <Pill testID={testID} text={`decided by: ${decisionSourceLabel(trust)}`} color={normal ? colors.primary : colors.amber} bg={normal ? '#e8edff' : colors.amberBg} />;
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
  const [c, icon] = checkStyle[check.status];
  return (
    <View testID={`check-${check.id}`} style={s.check}>
      <Text style={[s.checkIcon, { color: c }]}>{icon}</Text>
      <View style={{ flex: 1 }}>
        <Text style={s.label}>{check.label} <Text testID={`check-status-${check.id}`} style={{ color: c, fontWeight: '700' }}>{check.status.toUpperCase()}</Text></Text>
        {check.detail ? <Text selectable style={s.hint}>{check.detail}</Text> : null}
      </View>
    </View>
  );
}

export function Logo({ uri, size = 40 }: { uri?: string; size?: number }) {
  if (!uri) return null;
  return <Image source={{ uri }} style={{ width: size, height: size, borderRadius: 6, backgroundColor: '#fff' }} resizeMode="contain" accessibilityIgnoresInvertColors />;
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
