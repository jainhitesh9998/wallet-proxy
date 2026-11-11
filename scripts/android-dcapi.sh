#!/bin/bash
# The wallet as a native Android app answering Digital Credentials API requests (Credential Manager), on an emulator
# whose Chrome and Play services support the DC API (Chrome >= 141, Play services >= 24.31: Android 37.2 google_apis).
# Expo Go cannot do this: the wallet registers with Credential Manager from its own native module (modules/dc-api).
#
#   scripts/android-dcapi.sh setup     # once: system image, AVD 'dcapi-37', build tools (scripts/android.sh setup first)
#   scripts/android-dcapi.sh start     # boot the emulator (headless unless WINDOW=1); Chrome first-run off; adb reverse
#   scripts/android-dcapi.sh build     # expo prebuild + release APK (JS bundled; no Metro needed) + install
#   node e2e/dcapi-android.mjs issue   # load an mDL and a PID from the Animo playground into the wallet
#   node e2e/dcapi-android.mjs         # run the DC API scenarios against Animo's verifier in Chrome
#
# The trust service (:8090) and the reference issuer and verifier (:8791, :8792) run on the host (scripts/dev-up.sh);
# the release build reaches them on localhost through adb reverse (plain http is allowed only to localhost, 127.0.0.1
# and 10.0.2.2, see apps/wallet/plugins/with-local-cleartext.js).
set -euo pipefail
cd "$(dirname "$0")/.." && . scripts/env.sh

SDK=${ANDROID_HOME:-$HOME/.local/tools/android-sdk}
export ANDROID_HOME=$SDK GRADLE_USER_HOME=${GRADLE_USER_HOME:-$HOME/.local/tools/gradle-home}
ADB=$SDK/platform-tools/adb
AVD=${AVD:-dcapi-37}
PORT=${PORT:-5556}
SERIAL=emulator-$PORT
# Host ports the wallet reaches as localhost: the trust service, the reference issuer, the reference verifier.
HOST_PORTS="8090 8791 8792"
ABI=$([ "$(uname -m)" = arm64 ] && echo arm64-v8a || echo x86_64)
IMAGE="system-images;android-37.2;google_apis_ps16k;$ABI"

reverse_ports() {
  for port in $HOST_PORTS; do "$ADB" -s "$SERIAL" reverse tcp:$port tcp:$port > /dev/null; done
}

setup() {
  [ -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ] || { echo "run scripts/android.sh setup first (Android command-line tools)"; exit 1; }
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null || true
  "$SDK/cmdline-tools/latest/bin/sdkmanager" --install platform-tools emulator "$IMAGE" > /dev/null
  echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" -k "$IMAGE" -d pixel_8 --force > /dev/null
  sed -i.bak 's/^hw.ramSize=.*/hw.ramSize=4G/' "$HOME/.android/avd/$AVD.avd/config.ini" && rm -f "$HOME/.android/avd/$AVD.avd/config.ini.bak"
  echo "AVD '$AVD' ready ($IMAGE)"
}

start() {
  if ! "$ADB" devices | grep -q "$SERIAL"; then
    window=$([ "${WINDOW:-0}" = 1 ] && echo "" || echo "-no-window")
    nohup "$SDK/emulator/emulator" -avd "$AVD" -port "$PORT" $window -no-audio -no-boot-anim -no-snapshot-save > /tmp/dcapi-emulator.log 2>&1 &
  fi
  "$ADB" -s "$SERIAL" wait-for-device
  until [ "$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 3; done
  # Chrome without first-run screens (userdebug image), driven by the e2e script over its DevTools socket
  "$ADB" -s "$SERIAL" shell "echo '_ --disable-fre --no-default-browser-check --no-first-run' > /data/local/tmp/chrome-command-line"
  "$ADB" -s "$SERIAL" shell am set-debug-app --persistent com.android.chrome > /dev/null
  reverse_ports
  echo "$SERIAL ready: Chrome $("$ADB" -s "$SERIAL" shell dumpsys package com.android.chrome | grep -m1 versionName | tr -d ' \r' | cut -d= -f2)," \
    "Play services $("$ADB" -s "$SERIAL" shell dumpsys package com.google.android.gms | grep -m1 versionName | tr -d '\r' | cut -d= -f2 | cut -d' ' -f1)"
}

build() {
  (cd apps/wallet && npm run gen:config > /dev/null && CI=1 npx expo prebuild --platform android --no-install > /dev/null)
  (cd apps/wallet/android && ./gradlew :app:assembleRelease -PreactNativeArchitectures="$ABI" --console=plain -q)
  "$ADB" -s "$SERIAL" install -r apps/wallet/android/app/build/outputs/apk/release/app-release.apk > /dev/null
  reverse_ports
  echo "wallet installed on $SERIAL (dev.vctrust.wallet)"
}

case "${1:-}" in
  setup) setup ;;
  start) start ;;
  build) build ;;
  *) sed -n '2,14p' "$0"; exit 1 ;;
esac
