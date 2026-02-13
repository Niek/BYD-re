#!/bin/bash
#
# Decode MQTT payloads (MQTT_PUBLISH ... payload=... text=...) from BYD-Xposed hook logs.
#
# Usage:
#   ./xposed/mqtt.sh
#   ./xposed/mqtt.sh /path/to/raw_hooks.log
#   ./xposed/mqtt.sh /path/to/raw_hooks.log <keyHex>
#
# Key selection:
#   - If <keyHex> is provided, it is used as-is.
#   - Otherwise this script attempts to derive the AES-128 key (MD5(token.encryToken)) from the
#     /app/account/login HTTP call in the same log (via decompile.js state learning).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_PATH="${1:-${SCRIPT_DIR}/samples/raw_hooks.log}"
KEY_HEX="${2:-}"
STATE_FILE="${TMPDIR:-/tmp}/byd-mqtt-dec-state-$$.json"

if [[ ! -f "$LOG_PATH" ]]; then
  echo "Missing log file: $LOG_PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Missing jq (required for key derivation and pretty-printing)" >&2
  exit 1
fi

trap 'rm -f "$STATE_FILE"' EXIT

derive_key_from_log() {
  local reqLine respLine req resp

  # Use the last /app/account/login line that contains request/response bodies.
  # Guard grep with `|| true` because set -e + pipefail would otherwise exit on no matches.
  reqLine="$(
    grep -E 'HTTP method=POST .*/app/account/login.*reqBody=len=' "$LOG_PATH" | tail -n 1 || true
  )"
  respLine="$(
    grep -E 'HTTP method=POST .*/app/account/login.*respBody=len=' "$LOG_PATH" | tail -n 1 || true
  )"

  if [[ -z "${reqLine//[[:space:]]/}" || -z "${respLine//[[:space:]]/}" ]]; then
    return 1
  fi

  # Extract the `text=<JSON>` payloads using bash parameter expansion.
  req="${reqLine#*reqBody=len=}"
  req="${req#* text=}"
  req="${req%% respCode=*}"
  req="${req%$'\r'}"

  resp="${respLine#*respBody=len=}"
  resp="${resp#* text=}"
  resp="${resp%$'\r'}"

  if [[ -z "${req//[[:space:]]/}" || -z "${resp//[[:space:]]/}" ]]; then
    return 1
  fi

  node "${ROOT_DIR}/decompile.js" http-dec "$req" --state-file "$STATE_FILE" >/dev/null
  node "${ROOT_DIR}/decompile.js" http-dec "$resp" --state-file "$STATE_FILE" >/dev/null

  jq -er '.keys // [] | map(select(.source == "token.encryToken" and (.keyHex | type == "string"))) | .[0].keyHex' "$STATE_FILE"
}

if [[ -z "${KEY_HEX// }" ]]; then
  if ! KEY_HEX="$(derive_key_from_log)"; then
    echo "Missing key argument and could not derive it from /app/account/login in $LOG_PATH" >&2
    echo "Pass key as: ./xposed/mqtt.sh '$LOG_PATH' '<keyHex>'" >&2
    exit 2
  fi
fi

if [[ ! "$KEY_HEX" =~ ^[0-9A-Fa-f]{32}$ ]]; then
  echo "Invalid key hex: expected 32 hex chars" >&2
  exit 2
fi

extract_payloads() {
  local line topic claimedLen hex hexLen

  while IFS= read -r line; do
    topic="${line#*topic=}"
    topic="${topic%% *}"
    if (( ${#topic} < 3 || ${#topic} > 256 )); then
      continue
    fi

    claimedLen="${line#*payload=len=}"
    claimedLen="${claimedLen%% *}"
    if [[ "$claimedLen" =~ ^([0-9]+) ]]; then
      claimedLen="${BASH_REMATCH[1]}"
    else
      continue
    fi

    hex="${line#*text=}"
    hex="${hex%% *}"
    if [[ "$hex" =~ ^([0-9A-Fa-f]+) ]]; then
      hex="${BASH_REMATCH[1]}"
    else
      continue
    fi

    hexLen="${#hex}"
    if (( (hexLen % 2) != 0 )); then
      echo "Skipping odd-length hex payload topic=$topic hexchars=$hexLen" >&2
      continue
    fi
    if [[ "$claimedLen" != "$hexLen" ]]; then
      echo "Warning: payload len mismatch topic=$topic claimed=$claimedLen hexchars=$hexLen" >&2
    fi
    printf '%s\t%s\n' "$topic" "$hex"
  done < <(
    # `|| true` because no matches should not abort the script under set -e + pipefail.
    grep -E '(MQTT_PUBLISH|MQTT_FALLBACK).*topic=[A-Za-z0-9_./-]+.*payload=len=[0-9]+[[:space:]]+text=[0-9A-Fa-f]+' "$LOG_PATH" || true
  )
}

found=0
while IFS=$'\t' read -r topic hex; do
  found=1
  echo "# topic=${topic} hexchars=${#hex}"
  printf '%s\n' "$hex" | node "${ROOT_DIR}/mqtt_decode.js" "$KEY_HEX" | jq .
  echo
done < <(extract_payloads)

if [[ $found -eq 0 ]]; then
  echo "No MQTT payload entries found in $LOG_PATH" >&2
  exit 1
fi
