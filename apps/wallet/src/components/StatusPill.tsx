import React from 'react';
import { Text, View } from 'react-native';
import { useWallet } from '../wallet/WalletContext';
import { colors, s } from './ui';

/**
 * Trust-service availability as last observed by the trust client, and where decisions are made. With decisions on
 * this device an outage only delays trust-list refreshes; with decisions by the service it means fallback.
 */
export function TrustStatusPill({ testID = 'trust-status' }: { testID?: string }) {
  const { status, statusReason, settings, snapshot } = useWallet();
  const local = settings.decisions === 'local';
  const [label, c, bg] = status === 'online' ? ['online', colors.green, colors.greenBg]
    : status === 'offline' ? [local ? 'offline' : 'offline (fallback)', local ? colors.amber : colors.red, local ? colors.amberBg : colors.redBg]
      : ['unknown', colors.grey, colors.greyBg];
  const mode = local ? `Decisions on this device${snapshot ? ` · trust list v${snapshot.version}${snapshot.stale ? ' (expired)' : ''}` : ' · no trust list yet'}`
    : 'Decisions by the trust service';
  return (
    <View style={{ gap: 2 }}>
      <View style={[s.pill, { backgroundColor: bg, flexDirection: 'row', alignItems: 'center', gap: 6 }]}>
        <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: c }} />
        <Text testID={testID} style={[s.pillText, { color: c }]}>Trust service: {label}</Text>
      </View>
      <Text testID={`${testID}-mode`} style={s.hint}>{mode}</Text>
      {settings.simulateOutage ? <Text testID={`${testID}-outage`} style={[s.hint, { color: colors.red }]}>Simulated outage active</Text> : null}
      {status === 'offline' && statusReason && !settings.simulateOutage ? <Text style={s.hint} numberOfLines={1}>{statusReason}</Text> : null}
    </View>
  );
}
