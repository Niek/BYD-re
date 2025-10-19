#!/bin/bash
#
# Captures BYD-Xposed logs into samples/raw_hooks.log after rebuilding and reinstalling the module.

set -euo pipefail

APP_PACKAGE="com.byd.bydautolink"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_OUTPUT="${SCRIPT_DIR}/samples/raw_hooks.log"

cd "$SCRIPT_DIR"

echo "Building and installing BYD-Xposed module..."
./gradlew assembleDebug
adb install -r build/outputs/apk/debug/xposed-debug.apk

echo "Capturing logs for ${APP_PACKAGE}..."
adb shell am force-stop "$APP_PACKAGE" || true
adb logcat -c

rm -f "$LOG_OUTPUT"
adb logcat -s BYD-Xposed > "$LOG_OUTPUT" &
LOGCAT_PID=$!

trap 'kill "$LOGCAT_PID" >/dev/null 2>&1 || true' EXIT

# Wake up the screen and launch the app to trigger logging
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
adb shell monkey -p "$APP_PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 10
adb shell input swipe 500 200 500 1600 200 >/dev/null 2>&1
sleep 5

echo "Stopping log capture..."
kill "$LOGCAT_PID" >/dev/null 2>&1 || true
wait "$LOGCAT_PID" 2>/dev/null || true

trap - EXIT

echo "Captured logs at ${LOG_OUTPUT}"
