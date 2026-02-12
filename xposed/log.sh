#!/bin/bash
#
# Captures BYD-Xposed logs into samples/raw_hooks.log after rebuilding and reinstalling the module.

set -euo pipefail

APP_PACKAGE="com.byd.bydautolink"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_OUTPUT="${SCRIPT_DIR}/samples/raw_hooks.log"
TMP_LOG="${LOG_OUTPUT}.raw"
LOG_REMOTE_PRIMARY="/sdcard/Android/data/${APP_PACKAGE}/files/byd-hooks/raw_hooks.log"

cd "$SCRIPT_DIR"

echo "Clearing logcat buffers..."
adb logcat -b all -c

echo "Starting logcat stream..."
rm -f "$TMP_LOG"
LOGCAT_PID=""
adb logcat 'BYD-Xposed:*' '*:S' > "$TMP_LOG" &
LOGCAT_PID=$!
cleanup_logcat() {
  if [[ -n "${LOGCAT_PID}" ]] && kill -0 "$LOGCAT_PID" 2>/dev/null; then
    kill "$LOGCAT_PID" 2>/dev/null || true
    wait "$LOGCAT_PID" 2>/dev/null || true
  fi
}
trap cleanup_logcat EXIT

echo "Building and installing BYD-Xposed module..."
./gradlew clean assembleDebug --no-configuration-cache --rerun-tasks
adb install -r build/outputs/apk/debug/xposed-debug.apk

echo "Capturing logs for ${APP_PACKAGE}..."
adb shell am force-stop "$APP_PACKAGE" || true
adb shell rm -f "$LOG_REMOTE_PRIMARY"

rm -f "$LOG_OUTPUT"

# Clear app data to force login flow
#echo "Clearing app data for fresh login..."
#adb shell pm clear "$APP_PACKAGE"

# Wake up the screen
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
# Unlock the screen
adb shell input keyevent KEYCODE_MENU >/dev/null 2>&1

# Launch the app
echo "Launching app..."
adb shell monkey -p "$APP_PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1

echo "Waiting 20 seconds for app to start. Please interact with the device..."
sleep 20

#echo "Stopping log capture..."
#adb pull "$LOG_REMOTE_PRIMARY" "$LOG_OUTPUT"

echo "Stopping logcat stream..."
cleanup_logcat
trap - EXIT

echo "Reconstructing logcat output..."
# macOS/BSD sed will error ("RE error: illegal byte sequence") if logcat output contains
# invalid UTF-8/control bytes (some BYD payloads include these). Force bytewise processing.
LC_ALL=C sed -En '
  / CHUNK [0-9]+ 1\/[0-9]+ len=[0-9]+ /{
    h
    :chunk
    n
    / CHUNK [0-9]+ [0-9]+\/[0-9]+ len=[0-9]+ /{
      / CHUNK [0-9]+ ([0-9]+)\/\1 len=[0-9]+ /{
        s/^.* CHUNK [0-9]+ [0-9]+\/[0-9]+ len=[0-9]+ //
        H
        x
        s/(.*) CHUNK [0-9]+ 1\/[0-9]+ len=[0-9]+ /\1/
        s/\n//g
        p
        d
      }
      s/^.* CHUNK [0-9]+ [0-9]+\/[0-9]+ len=[0-9]+ //
      H
      b chunk
    }
    x
    s/(.*) CHUNK [0-9]+ 1\/[0-9]+ len=[0-9]+ /\1/
    s/\n//g
    p
    x
  }
  p
' "$TMP_LOG" > "$LOG_OUTPUT"
rm -f "$TMP_LOG"

echo "Captured logs at ${LOG_OUTPUT}"

echo "Pulling native memory dumps..."
DUMP_REMOTE_DIR="/data/data/${APP_PACKAGE}/files/byd-native-dumps"
DUMP_INTERMEDIATE_DIR="/sdcard/Download/byd-native-dumps"
DUMP_LOCAL_DIR="${SCRIPT_DIR}/../byd"

# Copy to sdcard using root to bypass /data/data restrictions
adb shell "su -c 'rm -rf ${DUMP_INTERMEDIATE_DIR} && mkdir -p ${DUMP_INTERMEDIATE_DIR} && cp -r ${DUMP_REMOTE_DIR}/* ${DUMP_INTERMEDIATE_DIR}/ && chmod -R 777 ${DUMP_INTERMEDIATE_DIR}'"

mkdir -p "$DUMP_LOCAL_DIR"
adb pull "${DUMP_INTERMEDIATE_DIR}/." "${DUMP_LOCAL_DIR}/" || echo "Failed to pull dumps"

echo "Dumps updated in ${DUMP_LOCAL_DIR}"
