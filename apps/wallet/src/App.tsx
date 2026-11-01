import React, { useEffect } from 'react';
import { Linking, Platform, Text, View } from 'react-native';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { WalletProvider } from './wallet/WalletContext';
import { navigationRef, OAUTH_CHANNEL, routeIncoming, type RootStack } from './navigation';
import HomeScreen from './screens/Home';
import ReceiveScreen from './screens/Receive';
import CredentialScreen from './screens/CredentialDetail';
import PresentScreen from './screens/Present';
import SettingsScreen from './screens/Settings';
import { colors } from './components/ui';

const Stack = createNativeStackNavigator<RootStack>();

/** Web: the AS redirect landed on /oauth-callback in a new tab; hand the URL to the wallet tab and stop. */
function WebOAuthCallback() {
  useEffect(() => {
    try {
      new BroadcastChannel(OAUTH_CHANNEL).postMessage(window.location.href);
    } catch { /* old browser: user pastes the URL */ }
  }, []);
  return (
    <View style={{ padding: 24 }}>
      <Text testID="oauth-callback-done" style={{ fontSize: 18, fontWeight: '700' }}>Authorization complete</Text>
      <Text selectable style={{ marginTop: 8 }}>Return to the wallet tab. If it does not continue automatically, paste this URL there:</Text>
      <Text selectable style={{ marginTop: 8, fontFamily: 'monospace' }}>{window.location.href}</Text>
    </View>
  );
}

export default function App() {
  useEffect(() => {
    if (Platform.OS === 'web') return;
    Linking.getInitialURL().then((u) => { if (u) setTimeout(() => routeIncoming(u), 300); }).catch(() => undefined);
    const sub = Linking.addEventListener('url', ({ url }) => routeIncoming(url));
    return () => sub.remove();
  }, []);

  if (Platform.OS === 'web' && typeof window !== 'undefined' && window.location.pathname.startsWith('/oauth-callback')) {
    return <WebOAuthCallback />;
  }
  return (
    <SafeAreaProvider>
      <WalletProvider>
        <NavigationContainer ref={navigationRef} theme={{ ...DefaultTheme, colors: { ...DefaultTheme.colors, background: colors.bg, primary: colors.primary } }}
          documentTitle={{ formatter: () => 'VC Trust Wallet' }}>
          <Stack.Navigator>
            <Stack.Screen name="Home" component={HomeScreen} options={{ title: 'VC Trust Wallet' }} />
            <Stack.Screen name="Receive" component={ReceiveScreen} options={{ title: 'Receive credential' }} />
            <Stack.Screen name="Credential" component={CredentialScreen} options={{ title: 'Credential' }} />
            <Stack.Screen name="Present" component={PresentScreen} options={{ title: 'Present' }} />
            <Stack.Screen name="Settings" component={SettingsScreen} options={{ title: 'Settings' }} />
          </Stack.Navigator>
        </NavigationContainer>
        <StatusBar style="dark" />
      </WalletProvider>
    </SafeAreaProvider>
  );
}
