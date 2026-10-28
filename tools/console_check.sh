#!/bin/bash
# console_check.sh - load every page in headless Chrome and count policy refusals and failed loads.
#   bash tools/console_check.sh --root <built site> --out <file> [--port 8787]
#   bash tools/console_check.sh --live --out <file> [--host www.theclauditor.ai]
# --root serves the build with its _headers (tools/serve_headers.py, 127.0.0.1 only) and first
# proves the server answering is that one (Server: clauditor-local, index.html byte-equal), so a
# different program already on the port can never be measured by mistake.
# Per page: "PASS|FAIL <path> csp=<n> net=<n>"; csp counts log lines matching
# "Content Security Policy|Refused to", net counts "ERR_|Failed to load resource".
# Exits 1 on any FAIL. bash 3.2-compatible. Needs Google Chrome.
set -u
usage() { echo "usage: console_check.sh (--root <dir> | --live [--host <host>]) --out <file> [--port N]" >&2; exit 2; }
ROOT=""; LIVE=0; HOST="theclauditor.ai"; OUT=""; PORT=8787
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || usage; ROOT="$2"; shift 2 ;;
    --live) LIVE=1; shift ;;
    --host) [ $# -ge 2 ] || usage; HOST="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || usage; OUT="$2"; shift 2 ;;
    --port) [ $# -ge 2 ] || usage; PORT="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
{ [ "$LIVE" = "1" ] && [ -z "$ROOT" ]; } || { [ "$LIVE" = "0" ] && [ -f "$ROOT/index.html" ]; } || usage
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[ -x "$CHROME" ] || { echo "console_check: Google Chrome not found at $CHROME (G17 is SKIP)" >&2; exit 3; }
PAGES="/ /services/ /how-we-work/ /sample-report/ /about/ /proof/ /security-policy/ /contact/ /404.html"
T="${TMPDIR:-/tmp}"; T="${T%/}"
WORK="$(mktemp -d "$T/console-check.XXXXXX")"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; }
trap cleanup EXIT

if [ "$LIVE" = "0" ]; then
  TOOLS="$(cd "$(dirname "$0")" && pwd)"
  python3 -B "$TOOLS/serve_headers.py" --root "$ROOT" --port "$PORT" > "$WORK/serve.log" 2>&1 &
  SRV=$!
  sleep 1
  sv="$(curl -s --max-time 5 -D - -o "$WORK/probe.html" "http://127.0.0.1:$PORT/" | tr -d '\r' | grep -i '^server:')"
  if ! kill -0 "$SRV" 2>/dev/null || [ "$sv" != "Server: clauditor-local" ] || ! cmp -s "$WORK/probe.html" "$ROOT/index.html"; then
    echo "console_check: port $PORT is answered by something else ($sv) or serve_headers did not start; pick another --port" >&2
    exit 4
  fi
  BASEURL="http://127.0.0.1:$PORT"
else
  BASEURL="https://$HOST"
fi

{
  echo "console_check.sh — $(date '+%Y-%m-%d %H:%M %Z') — $BASEURL ($( [ "$LIVE" = 1 ] && echo live || echo "root $ROOT"))"
  echo "Chrome: $("$CHROME" --version 2>/dev/null)"
} > "$WORK/report.txt"
fails=0; tcsp=0; tnet=0
for p in $PAGES; do
  log="$WORK/$(printf '%s' "$p" | tr '/.' '__').log"
  perl -e 'alarm 60; exec @ARGV' "$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
    --disable-background-networking --disable-component-update --disable-sync --disable-extensions \
    --user-data-dir="$(mktemp -d "$T/console-profile.XXXXXX")" --enable-logging=stderr --v=1 \
    --virtual-time-budget=5000 --dump-dom "$BASEURL$p" 2>"$log" >/dev/null
  csp="$(grep -c -E 'Content Security Policy|Refused to' "$log" || true)"
  net="$(grep -c -E 'ERR_|Failed to load resource' "$log" || true)"
  st=PASS; { [ "$csp" = "0" ] && [ "$net" = "0" ]; } || { st=FAIL; fails=$((fails+1)); }
  tcsp=$((tcsp+csp)); tnet=$((tnet+net))
  printf '%s %s csp=%s net=%s\n' "$st" "$p" "$csp" "$net" | tee -a "$WORK/report.txt"
  if [ "$st" = "FAIL" ]; then grep -E 'Content Security Policy|Refused to|ERR_|Failed to load resource' "$log" | head -5 | sed 's/^/    /' | tee -a "$WORK/report.txt"; fi
done
echo "TOTAL: $fails page(s) FAIL · csp=$tcsp net=$tnet across 9 pages" | tee -a "$WORK/report.txt"
cp "$WORK/report.txt" "$OUT"
echo "written: $OUT (raw Chrome logs kept in $WORK/)"
[ "$fails" = "0" ]
