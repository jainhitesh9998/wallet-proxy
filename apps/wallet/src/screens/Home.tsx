import React from 'react';
import { Pressable, ScrollView, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import type { StoredCredential } from '@vctrust/wallet-core';
import type { RootStack } from '../navigation';
import { useWallet } from '../wallet/WalletContext';
import { credentialView, shortDate } from '../wallet/display';
import { TrustStatusPill } from '../components/StatusPill';
import { Button, colors, Logo, s, Section, TrustLine } from '../components/ui';

function CredentialCard({ c, index, onPress }: { c: StoredCredential; index: number; onPress: () => void }) {
  const v = credentialView(c);
  const bg = v.background ?? '#ffffff';
  const fg = v.textColor ?? colors.text;
  return (
    <Pressable testID={`credential-card-${index}`} accessibilityRole="button" onPress={onPress}
      style={({ pressed }) => [{ backgroundColor: bg, borderRadius: 14, padding: 14, borderWidth: 1, borderColor: colors.border, gap: 8 }, pressed && { opacity: 0.85 }]}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
        <Logo uri={v.logo} />
        <View style={{ flex: 1 }}>
          <Text testID={`credential-title-${index}`} style={{ color: fg, fontSize: 17, fontWeight: '700' }}>{v.title}</Text>
          <Text style={{ color: fg, opacity: 0.85, fontSize: 13 }}>{v.issuer}</Text>
        </View>
        <Text style={{ color: fg, fontSize: 11, opacity: 0.8 }}>{c.format}</Text>
      </View>
      <View style={{ backgroundColor: 'rgba(255,255,255,0.92)', borderRadius: 8, padding: 8 }}>
        {c.pending ? <Text style={s.hint}>Deferred issuance pending ({c.pending.transactionId})</Text>
          : <TrustLine trust={c.report?.trust} valid={c.report?.valid} testIDPrefix={`credential-trust-${index}`} />}
        <Text style={[s.hint, { marginTop: 4 }]}>Issued {shortDate(c.issuedAt)}{v.type ? ` · ${v.type}` : ''}</Text>
      </View>
    </Pressable>
  );
}

export default function HomeScreen({ navigation }: NativeStackScreenProps<RootStack, 'Home'>) {
  const { credentials, ready } = useWallet();
  return (
    <ScrollView contentContainerStyle={s.screen} testID="home-screen">
      <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
        <TrustStatusPill />
        <Text testID="credential-count" style={s.hint}>{ready ? `${credentials.length} credential(s)` : 'Loading…'}</Text>
      </View>
      <View style={{ flexDirection: 'row', gap: 8 }}>
        <Button testID="nav-receive" title="Receive" onPress={() => navigation.navigate('Receive')} style={{ flex: 1 }} />
        <Button testID="nav-present" title="Present" onPress={() => navigation.navigate('Present')} style={{ flex: 1 }} />
        <Button testID="nav-settings" title="Settings" kind="secondary" onPress={() => navigation.navigate('Settings')} style={{ flex: 1 }} />
      </View>
      {credentials.length === 0 && ready ? (
        <Section><Text style={s.hint}>No credentials yet. Use Receive to paste or scan a credential offer, or start from a demo issuer.</Text></Section>
      ) : null}
      {credentials.map((c, i) => (
        <CredentialCard key={c.id} c={c} index={i} onPress={() => navigation.navigate('Credential', { id: c.id })} />
      ))}
    </ScrollView>
  );
}
