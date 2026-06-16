#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="${PCAP:-$ROOT/test/chromium-perdu.com-quick.pcap}"

if ! python3 -c 'import cryptography' >/dev/null 2>&1; then
  echo "SKIP QUIC: Python cryptography module unavailable"
  exit 0
fi

output="$(python3 "$ROOT/fanfp.py" "$PCAP")"

check() {
  local pattern="$1"
  printf '%s\n' "$output" | grep -F "$pattern" >/dev/null
}

failures=0

check '"protocol": "quic"' || failures=$((failures + 1))
check '"role": "client"' || failures=$((failures + 1))
check '"role": "server"' || failures=$((failures + 1))
check '"features": "quic|client|v=1|tls_v=771|c=4865-4866-4867|' || failures=$((failures + 1))
check '|alpn=h3|' || failures=$((failures + 1))
check '"features": "quic|server|v=1|tls_v=771|c=4865|e=51-43|sv=772"' || failures=$((failures + 1))
check '"fingerprint": "fan1:quic:client:passive:' || failures=$((failures + 1))
check '"fingerprint": "fan1:quic:server:passive:' || failures=$((failures + 1))

if [ "$failures" -ne 0 ]; then
  printf '%s\n' "$output"
  echo "FAIL QUIC: $failures checks failed"
  exit 1
fi

printf '%s\n' "$output" | grep -E '"features": "quic|"|"fingerprint": "fan1:quic:'
