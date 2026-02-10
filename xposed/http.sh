#!/bin/bash
#
# Decode HTTP request/response payloads from BYD-Xposed hook logs.
#
# Usage:
#   ./xposed/http.sh
#   ./xposed/http.sh /path/to/raw_hooks.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_PATH="${1:-${SCRIPT_DIR}/samples/raw_hooks.log}"
STATE_FILE="${TMPDIR:-/tmp}/byd-http-dec-state-$$.json"

if [[ ! -f "$LOG_PATH" ]]; then
  echo "Missing log file: $LOG_PATH" >&2
  exit 1
fi

trap 'rm -f "$STATE_FILE"' EXIT

extract_http_calls() {
  grep "HTTP method=" "$LOG_PATH" \
    | perl -pe 's/HTTP method=/\nHTTP method=/g' \
    | grep "HTTP method=" \
    | perl -ne '
        use strict;
        use warnings;
        chomp;
        my $line = $_;
        if ($line =~ /HTTP method=(\S+)\s+url=(\S+).*?\breqBody=len=\d+\s+text=(.*?)\s+respCode=\d+\s+respBody=len=\d+\s+text=(.*)\s*$/s) {
          print join("\t", $1, $2, $3, $4), "\n";
          next;
        }
        if ($line =~ /HTTP method=(\S+)\s+url=(\S+).*?\breqBody=len=\d+\s+text=(.*)\s*$/s) {
          print join("\t", $1, $2, $3, ""), "\n";
        }
      '
}

decode_payload() {
  local payload="$1"
  if [[ -z "${payload// }" ]]; then
    echo "(empty)"
    return
  fi
  BYD_DECODE_STATE_FILE="$STATE_FILE" node "${ROOT_DIR}/decompile.js" http-dec "$payload"
}

found=0
while IFS=$'\t' read -r method url req_text resp_text; do
  found=1
  echo "${method} ${url}"
  echo "Request:"
  decode_payload "$req_text"
  echo "Response:"
  decode_payload "$resp_text"
  echo
done < <(extract_http_calls)

if [[ $found -eq 0 ]]; then
  echo "No HTTP method entries found in $LOG_PATH" >&2
  exit 1
fi
