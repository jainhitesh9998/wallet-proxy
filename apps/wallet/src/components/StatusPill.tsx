import React from 'react';
import { Text, View } from 'react-native';
import { useWallet } from '../wallet/WalletContext';
import { shortDate } from '../wallet/display';
import { colors, s } from './ui';

/**
 * What the trust client stands on (TrustClient.status()): whether the trust service was reachable when last tried,
 * and the snapshot decisions are made from. Decisions are made on this device either way: an outage only delays
 * snapshot refreshes and sends lookups to the standard mechanisms.
 */
export function TrustStatusPill({ testID = 'trust-status' }: { testID?: string }) {
  const { trustStatus: t, statusReason, settings, configError } = useWallet();
  const [label, c, bg] = t.service === 'online' ? ['online', colors.green, colors.greenBg]
    : t.service === 'offline' ? ['offline', colors.amber, colors.amberBg]
      : t.service === 'unconfigured' ? ['not configured', colors.red, colors.redBg]
        : ['not contacted yet', colors.grey, colors.greyBg];
  const basis = t.snapshot ? `snapshot of ${shortDate(t.snapshot.issuedAt)}${t.snapshot.stale ? ' (expired)' : ''}` : 'no snapshot, pinned trust only';
  return (
    <View style={{ gap: 2 }}>
      <View style={[s.pill, { backgroundColor: bg, flexDirection: 'row', alignItems: 'center', gap: 6 }]}>
        <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: c }} />
        <Text testID={testID} style={[s.pillText, { color: c }]}>Trust service: {label}</Text>
      </View>
      <Text testID={`${testID}-basis`} style={[s.hint, t.degraded && { color: colors.amber }]}>Decisions on this device · {basis}</Text>
      {configError ? <Text testID={`${testID}-config-error`} style={[s.hint, { color: colors.red }]}>{configError}</Text> : null}
      {settings.simulateOutage ? <Text testID={`${testID}-outage`} style={[s.hint, { color: colors.red }]}>Simulated outage active</Text> : null}
      {t.service === 'offline' && statusReason && !settings.simulateOutage ? <Text style={s.hint} numberOfLines={1}>{statusReason}</Text> : null}
    </View>
  );
}
