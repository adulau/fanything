#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NSE="${NSE:-$ROOT/fanything-tls.nse}"
HOST="${HOST:-127.0.0.1}"
BASE_PORT="${BASE_PORT:-19443}"
OUTDIR="${OUTDIR:-/tmp/fanything-nse-openssl-$(date +%s)}"

CIPHER12='ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA:@SECLEVEL=0'
CIPHER13='TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'

mkdir -p "$OUTDIR"

CERT="$OUTDIR/server.crt"
KEY="$OUTDIR/server.key"
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$KEY" -out "$CERT" -days 1 >"$OUTDIR/cert.log" 2>&1

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

supports_s_server_option() {
  local opt="$1"
  openssl s_server -help 2>&1 | grep -q -- "$opt"
}

wait_port() {
  local port="$1"
  local i
  for i in $(seq 1 50); do
    if (: >"/dev/tcp/$HOST/$port") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_server() {
  local version="$1"
  local port="$2"
  local opt="$3"
  local log="$OUTDIR/server-$version.log"

  if ! supports_s_server_option "$opt"; then
    echo "SKIP $version: openssl s_server has no $opt" | tee "$OUTDIR/$version.status"
    return 1
  fi

  openssl s_server -quiet -accept "$HOST:$port" -cert "$CERT" -key "$KEY" \
    "$opt" -www -cipher "$CIPHER12" -ciphersuites "$CIPHER13" \
    >"$log" 2>&1 &
  local pid="$!"
  PIDS+=("$pid")

  sleep 0.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "SKIP $version: openssl server exited early; see $log" | tee "$OUTDIR/$version.status"
    return 1
  fi
  if ! wait_port "$port"; then
    echo "SKIP $version: port $port did not open; see $log" | tee "$OUTDIR/$version.status"
    return 1
  fi

  return 0
}

check_output() {
  local version="$1"
  local outfile="$2"
  if ! grep -Eq 'mode: active' "$outfile"; then
    return 1
  fi
  case "$version" in
    TLSv1.3)
      grep -Eq 'features: tls\|server\|v=771\|.*\|sv=772' "$outfile"
      ;;
    TLSv1.2)
      grep -Eq 'features: tls\|server\|v=771\|' "$outfile"
      ;;
    TLSv1.1)
      grep -Eq 'features: tls\|server\|v=770\|' "$outfile"
      ;;
    TLSv1.0)
      grep -Eq 'features: tls\|server\|v=769\|' "$outfile"
      ;;
    SSLv3)
      grep -Eq 'features: tls\|server\|v=768\|' "$outfile"
      ;;
    SSLv2)
      grep -Eq 'features: tls\|server\|v=2\|' "$outfile"
      ;;
    *)
      return 1
      ;;
  esac
}

print_values() {
  local outfile="$1"
  grep -E 'features: tls\|server\||fingerprint: fan1:tls:server:active:' "$outfile" \
    | sed 's/^[|_[:space:]]*//'
}

run_case() {
  local version="$1"
  local opt="$2"
  local port="$3"
  local outfile="$OUTDIR/nmap-$version.txt"

  if ! start_server "$version" "$port" "$opt"; then
    return 0
  fi

  nmap -Pn -p "$port" --script "$NSE" \
    --script-args "fanything-tls.force=true,fanything-tls.tls-version=$version" "$HOST" \
    >"$outfile" 2>&1

  if check_output "$version" "$outfile"; then
    echo "PASS $version -> $outfile" | tee "$OUTDIR/$version.status"
    print_values "$outfile"
    return 0
  fi

  echo "FAIL $version -> $outfile" | tee "$OUTDIR/$version.status"
  print_values "$outfile"
  return 1
}

run_default_first_success() {
  local port="$1"
  local name="default-first-success"
  local log="$OUTDIR/server-$name.log"
  local outfile="$OUTDIR/nmap-$name.txt"
  local count

  if ! supports_s_server_option -min_protocol || ! supports_s_server_option -max_protocol; then
    echo "SKIP $name: openssl s_server has no min/max protocol options" | tee "$OUTDIR/$name.status"
    return 0
  fi

  openssl s_server -quiet -accept "$HOST:$port" -cert "$CERT" -key "$KEY" \
    -www -cipher "$CIPHER12" -ciphersuites "$CIPHER13" \
    -min_protocol TLSv1 -max_protocol TLSv1.2 >"$log" 2>&1 &
  local pid="$!"
  PIDS+=("$pid")

  sleep 0.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "SKIP $name: openssl server exited early; see $log" | tee "$OUTDIR/$name.status"
    return 0
  fi
  if ! wait_port "$port"; then
    echo "SKIP $name: port $port did not open; see $log" | tee "$OUTDIR/$name.status"
    return 0
  fi

  nmap -Pn -p "$port" --script "$NSE" \
    --script-args "fanything-tls.force=true" "$HOST" >"$outfile" 2>&1

  count="$(grep -Ec 'features: tls\|server\|' "$outfile")"
  if [ "$count" = "1" ] && grep -Eq 'features: tls\|server\|v=771\|' "$outfile"; then
    echo "PASS $name -> $outfile" | tee "$OUTDIR/$name.status"
    print_values "$outfile"
    return 0
  fi

  echo "FAIL $name: expected one TLSv1.2 feature, got $count -> $outfile" | tee "$OUTDIR/$name.status"
  print_values "$outfile"
  return 1
}

failures=0

run_case TLSv1.3 -tls1_3 "$((BASE_PORT + 0))" || failures=$((failures + 1))
run_case TLSv1.2 -tls1_2 "$((BASE_PORT + 1))" || failures=$((failures + 1))
run_case TLSv1.1 -tls1_1 "$((BASE_PORT + 2))" || failures=$((failures + 1))
run_case TLSv1.0 -tls1 "$((BASE_PORT + 3))" || failures=$((failures + 1))
run_default_first_success "$((BASE_PORT + 5))" || failures=$((failures + 1))

if supports_s_server_option -ssl3; then
  run_case SSLv3 -ssl3 "$((BASE_PORT + 4))" || failures=$((failures + 1))
else
  echo "SKIP SSLv3: openssl s_server has no -ssl3" | tee "$OUTDIR/SSLv3.status"
fi

echo "SKIP SSLv2: OpenSSL s_server does not provide SSLv2 server mode" | tee "$OUTDIR/SSLv2.status"

echo "results: $OUTDIR"
exit "$failures"
