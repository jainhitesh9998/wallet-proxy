/** QR scanning with expo-camera (device only; on web the user pastes). */
import React, { useState } from 'react';
import { Modal, Platform, Text, View } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { Button, s } from './ui';

export function ScanButton({ onScanned, testID }: { onScanned: (data: string) => void; testID?: string }) {
  const [open, setOpen] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();
  if (Platform.OS === 'web') return null;
  const start = async () => {
    if (!permission?.granted) {
      const r = await requestPermission();
      if (!r.granted) return;
    }
    setOpen(true);
  };
  return (
    <>
      <Button testID={testID} title="Scan QR" kind="secondary" onPress={start} style={{ flex: 1 }} />
      <Modal visible={open} animationType="slide" onRequestClose={() => setOpen(false)}>
        <View style={{ flex: 1, backgroundColor: '#000' }}>
          <CameraView style={{ flex: 1 }} facing="back" barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={open ? ({ data }) => { setOpen(false); onScanned(data); } : undefined} />
          <View style={{ padding: 16, gap: 8, backgroundColor: '#fff' }}>
            <Text style={s.hint}>Point the camera at an OpenID4VCI offer or OpenID4VP request QR code.</Text>
            <Button title="Cancel" kind="secondary" onPress={() => setOpen(false)} />
          </View>
        </View>
      </Modal>
    </>
  );
}
