#!/bin/bash
# Runs the demo wallet in Expo Go on a local Android emulator (Apple Silicon or x86_64 macOS / Linux).
#
#   scripts/android.sh setup            # once: Android command-line tools, emulator, API 35 image, AVD, Expo Go
#   scripts/android.sh start            # boot the emulator (headless unless WINDOW=1) and open the wallet in Expo Go
#   scripts/android.sh open <uri>       # hand an openid-credential-offer:// or openid4vp:// URI to the wallet
#
# The wallet's Metro server must be running (cd apps/wallet && npx expo start). The emulator reaches Metro (8081),
# the trust service (8090) and the reference issuer and verifier (8791, 8792; scripts/dev-up.sh) on localhost through
# adb reverse.
set -euo pipefail
cd "$(dirname "$0")/.." && . scripts/env.sh

SDK=${ANDROID_HOME:-$HOME/.local/tools/android-sdk}
export ANDROID_HOME=$SDK
ADB=$SDK/platform-tools/adb
AVD=${AVD:-wallet-demo}
ABI=$([ "$(uname -m)" = arm64 ] && echo arm64-v8a || echo x86_64)
IMAGE="system-images;android-35;google_apis;$ABI"
EXPO_GO_SDK=58.0.0
APKS=$HOME/.local/tools/android-apks

setup() {
  if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
    os=$([ "$(uname)" = Darwin ] && echo mac || echo linux)
    zip=$(curl -sL https://dl.google.com/android/repository/repository2-3.xml | grep -o "commandlinetools-$os-[0-9]*_latest.zip" | sort -t- -k3 -n -u | tail -1)
    mkdir -p "$SDK/cmdline-tools" && curl -sSLo /tmp/clt.zip "https://dl.google.com/android/repository/$zip"
    rm -rf "$SDK/cmdline-tools/latest" && unzip -q /tmp/clt.zip -d "$SDK/cmdline-tools" && mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest" && rm /tmp/clt.zip
  fi
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null || true
  "$SDK/cmdline-tools/latest/bin/sdkmanager" --install platform-tools emulator "$IMAGE" > /dev/null
  echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" -k "$IMAGE" -d pixel_7 --force > /dev/null
  url=$(curl -s https://api.expo.dev/v2/versions/latest | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['sdkVersions']['$EXPO_GO_SDK']['androidClientUrl'])")
  mkdir -p "$APKS" && curl -sSLo "$APKS/expo-go-$EXPO_GO_SDK.apk" "$url"
  echo "Android SDK, AVD '$AVD' and Expo Go $EXPO_GO_SDK ready"
}

start() {
  if ! "$ADB" devices | grep -q emulator; then
    window=$([ "${WINDOW:-0}" = 1 ] && echo "" || echo "-no-window")
    nohup "$SDK/emulator/emulator" -avd "$AVD" $window -no-audio -no-boot-anim -no-snapshot-save > /tmp/wallet-emulator.log 2>&1 &
  fi
  "$ADB" wait-for-device
  until [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 3; done
  "$ADB" shell pm list packages | grep -q host.exp.exponent || "$ADB" install -r "$APKS/expo-go-$EXPO_GO_SDK.apk" > /dev/null
  for port in 8081 8090 8791 8792; do "$ADB" reverse tcp:$port tcp:$port > /dev/null; done
  "$ADB" shell am start -a android.intent.action.VIEW -d "exp://127.0.0.1:8081" host.exp.exponent > /dev/null
  echo "wallet opening in Expo Go (screenshot: $ADB exec-out screencap -p > shot.png)"
}

open_uri() {
  # Expo Go delivers exp://host/--/<path>?… to the app; the wallet routes receive?offer= and present?request=.
  case "$1" in
    openid4vp://*|haip-vp://*) path=present; param=request ;;
    *) path=receive; param=offer ;;
  esac
  enc=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1")
  "$ADB" shell am start -a android.intent.action.VIEW -d "'exp://127.0.0.1:8081/--/$path?$param=$enc'" host.exp.exponent > /dev/null
}

case "${1:-}" in
  setup) setup ;;
  start) start ;;
  open) open_uri "${2:?usage: scripts/android.sh open <openid-credential-offer:// | openid4vp:// URI>}" ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
