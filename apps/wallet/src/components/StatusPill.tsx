import React from 'react';
import { Text, View } from 'react-native';
import { useWallet } from '../wallet/WalletContext';
import { colors, s } from './ui';

/** Trust-service availability as last observed by the trust client. */
export function TrustStatusPill({ testID = 'trust-status' }: { testID?: string }) {
  const { status, statusReason, settings } = useWallet();
  const [label, c, bg] = status === 'online' ? ['online', colors.green, colors.greenBg]
    : status === 'offline' ? ['offline (fallback)', colors.red, colors.redBg] : ['unknown', colors.grey, colors.greyBg];
  return (
    <View style={{ gap: 2 }}>
      <View style={[s.pill, { backgroundColor: bg, flexDirection: 'row', alignItems: 'center', gap: 6 }]}>
        <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: c }} />
        <Text testID={testID} style={[s.pillText, { color: c }]}>Trust service: {label}</Text>
      </View>
      {settings.simulateOutage ? <Text testID={`${testID}-outage`} style={[s.hint, { color: colors.red }]}>Simulated outage active</Text> : null}
      {status === 'offline' && statusReason && !settings.simulateOutage ? <Text style={s.hint} numberOfLines={1}>{statusReason}</Text> : null}
    </View>
  );
}
