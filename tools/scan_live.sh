#!/bin/bash
# scan_live.sh - read the live theclauditor.ai: headers, TLS, files, mail and DNS records (L01-L18).
#   bash tools/scan_live.sh --out scan.txt [--section headers|dns|all] [--host theclauditor.ai]
#                           [--stage <built site>] [--observatory]
# Read-only: curl GET (never HEAD-only), dig against 1.1.1.1, openssl s_client.
# One "Lnn PASS|FAIL|INFO|SKIP — <what>" line per check; [GATE] marks what a GO needs.
# --stage <dir> turns on L11 (every built file served byte-identical) and the theme.js
# byte check in L18. --observatory sends the one POST to Mozilla's HTTP Observatory (L12).
# Exits 1 when any line is FAIL. bash 3.2-compatible; runs on macOS and on Ubuntu.
set -u

# The target Content-Security-Policy (orders A5). check_site.py G04 asserts _headers carries
# the same string, and L03 asserts the live site serves it.
CSP_TARGET="default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; base-uri 'none'; form-action mailto:; frame-ancestors 'none'; upgrade-insecure-requests"
STS_EXPECTED="max-age=31536000; includeSubDomains; preload"
# Cloudflare's CA set (developers.cloudflare.com/ssl/reference/certificate-authorities/,
# "CAA record content"), carried over from the 2026-10-26 scan.
CAA_CAS="letsencrypt.org
pki.goog; cansignhttpexchanges=yes
ssl.com
sectigo.com"
REPO_STRING="github.com/The-Clauditor/theclauditor-ai"
PAGES="/ /services/ /how-we-work/ /sample-report/ /about/ /proof/ /security-policy/ /contact/"
PATHS="$PAGES /assets/site.css /assets/theme.js /.well-known/security.txt"
NPATHS=11

usage() { echo "usage: scan_live.sh --out <path> [--section headers|dns|all] [--host theclauditor.ai] [--stage <dir>] [--observatory]" >&2; exit 2; }
OUT=""; SECTION="all"; HOST="theclauditor.ai"; STAGE=""; OBS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || usage; OUT="$2"; shift 2 ;;
    --section) [ $# -ge 2 ] || usage; SECTION="$2"; shift 2 ;;
    --host) [ $# -ge 2 ] || usage; HOST="$2"; shift 2 ;;
    --stage) [ $# -ge 2 ] || usage; STAGE="$2"; shift 2 ;;
    --observatory) OBS=1; shift ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
case "$SECTION" in headers|dns|all) ;; *) usage ;; esac
[ -z "$STAGE" ] || [ -f "$STAGE/index.html" ] || { echo "scan_live: --stage has no index.html" >&2; exit 2; }

BASE="$(cd "$(dirname "$0")/.." && pwd)"
REF="$BASE/src/static"
HOSTS="$HOST www.$HOST"
PRIV="PRIVATE"; PRIV="$PRIV KEY"   # split so this file never matches a grep for the marker
T="${TMPDIR:-/tmp}"; T="${T%/}"
TMP="$(mktemp -d "$T/scan-live.XXXXXX")"
RES="$TMP/results.txt"; : > "$RES"
trap 'rm -rf "$TMP"' EXIT

emit() { printf '%s %s — %s\n' "$1" "$2" "$3" | tee -a "$RES"; }
lc() { tr '[:upper:]' '[:lower:]'; }
key() { printf '%s%s' "$1" "$2" | tr '/.:?' '____'; }
final_block() { tr -d '\r' < "$1" | awk 'BEGIN{RS=""} {b=$0} END{print b}'; }   # skips 103 Early Hints
hcount() { grep -i -c "^$1:" "$2" 2>/dev/null || true; }
hval() { grep -i "^$1:" "$2" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//'; }
code() { cat "$TMP/$(key "$1" "$2").code" 2>/dev/null; }

fetch() { # host path -> $TMP/<key>.{h,b,hf,code}; no redirects followed
  local k; k="$(key "$1" "$2")"
  curl -s --max-time 25 -D "$TMP/$k.h" -o "$TMP/$k.b" -w '%{http_code}' "https://$1$2" > "$TMP/$k.code" 2>/dev/null \
    || echo "000" > "$TMP/$k.code"
  [ -f "$TMP/$k.h" ] || : > "$TMP/$k.h"
  [ -f "$TMP/$k.b" ] || : > "$TMP/$k.b"
  final_block "$TMP/$k.h" > "$TMP/$k.hf"
}

# every_path <check-fn> : runs fn host path for 11 paths x 2 hosts; collects failures in $bad
every_path() { bad=""; for h in $HOSTS; do for p in $PATHS; do "$1" "$h" "$p" || bad="$bad $h$p"; done; done; }

{
  echo "scan_live.sh — $(date '+%Y-%m-%d %H:%M %Z') — host $HOST — section $SECTION — stage ${STAGE:-none}"
} | tee "$RES.head"

OPENSSL=openssl
[ -x /opt/homebrew/opt/openssl@3/bin/openssl ] && OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl

if [ "$SECTION" != "dns" ]; then
  for h in $HOSTS; do for p in $PATHS /.well-known/pgp-key.txt /sitemap.xml /robots.txt /favicon.svg /about /nope-404-test /404.html /assets/coin3d.js; do fetch "$h" "$p"; done; done

  c_acao() { [ "$(hcount access-control-allow-origin "$TMP/$(key "$1" "$2").hf")" = "0" ]; }
  every_path c_acao
  if [ -z "$bad" ]; then emit L01 PASS "[GATE] access-control-allow-origin absent on $NPATHS paths x 2 hosts"
  else emit L01 FAIL "[GATE] access-control-allow-origin present on:$bad"; fi

  c_sts() { local f; f="$TMP/$(key "$1" "$2").hf"
    [ "$(hcount strict-transport-security "$f")" = "1" ] && [ "$(hval strict-transport-security "$f")" = "$STS_EXPECTED" ]; }
  every_path c_sts
  if [ -z "$bad" ]; then emit L02 PASS "[GATE] exactly one strict-transport-security = \"$STS_EXPECTED\" on $NPATHS paths x 2 hosts"
  else emit L02 FAIL "[GATE] want one STS = \"$STS_EXPECTED\"; wrong on:$bad"; fi

  c_csp() { local f; f="$TMP/$(key "$1" "$2").hf"
    [ "$(hcount content-security-policy "$f")" = "1" ] && [ "$(hval content-security-policy "$f")" = "$CSP_TARGET" ]; }
  every_path c_csp
  if [ -z "$bad" ]; then emit L03 PASS "[GATE] CSP byte-equal to the target on $NPATHS paths x 2 hosts"
  else emit L03 FAIL "[GATE] CSP differs from the target or is missing on:$bad"; fi

  for spec in "x-frame-options|DENY" "x-content-type-options|nosniff" \
              "referrer-policy|strict-origin-when-cross-origin" \
              "permissions-policy|camera=(), microphone=(), geolocation=()" \
              "cross-origin-opener-policy|same-origin" "cross-origin-resource-policy|same-origin"; do
    name="${spec%%|*}"; want="${spec#*|}"; ok=0; bad=""
    for h in $HOSTS; do for p in $PATHS; do f="$TMP/$(key "$h" "$p").hf"
      if [ "$(hcount "$name" "$f")" = "1" ] && [ "$(hval "$name" "$f")" = "$want" ]; then ok=$((ok+1)); else bad="$bad $h$p"; fi
    done; done
    if [ -z "$bad" ]; then emit L04 PASS "[GATE] $name: $want ($ok/$((NPATHS*2)))"
    else emit L04 FAIL "[GATE] $name: $want only $ok/$((NPATHS*2)); wrong on:$bad"; fi
  done

  c_cookie() { [ "$(hcount set-cookie "$TMP/$(key "$1" "$2").hf")" = "0" ]; }
  every_path c_cookie
  if [ -z "$bad" ]; then emit L05 PASS "[GATE] no set-cookie on GET of $NPATHS paths x 2 hosts"
  else emit L05 FAIL "[GATE] set-cookie on:$bad"; fi

  bad=""; for h in $HOSTS; do k="$(key "$h" /.well-known/security.txt)"
    c="$(code "$h" /.well-known/security.txt)"; ct="$(hval content-type "$TMP/$k.hf" | lc)"
    np="$(grep -c '^Policy: ' "$TMP/$k.b" 2>/dev/null || true)"; ne="$(grep -c '^Encryption: ' "$TMP/$k.b" 2>/dev/null || true)"
    same=0; cmp -s "$TMP/$k.b" "$REF/.well-known/security.txt" && same=1
    case "$ct" in text/plain*) ctok=1 ;; *) ctok=0 ;; esac
    { [ "$c" = "200" ] && [ "$ctok" = "1" ] && [ "$np" -ge 1 ] && [ "$ne" = "2" ] && [ "$same" = "1" ]; } \
      || bad="$bad $h($c, $ct, Policy x$np, Encryption x$ne, identical=$same)"
  done
  if [ -z "$bad" ]; then emit L06 PASS "[GATE] security.txt 200 text/plain, Policy: + two Encryption:, byte-identical to src, both hosts"
  else emit L06 FAIL "[GATE] security.txt:$bad"; fi

  # v1.1: theme.js loads on every page, the policy page included; no other script may appear.
  bad=""; for h in $HOSTS; do k="$(key "$h" /security-policy/)"; c="$(code "$h" /security-policy/)"
    ns="$(grep -o -i '<script' "$TMP/$k.b" | wc -l | tr -d ' ')"; nt="$(grep -o '<script src="/assets/theme.js"></script>' "$TMP/$k.b" | wc -l | tr -d ' ')"
    { [ "$c" = "200" ] && [ "$ns" = "$nt" ] && [ "$ns" -le 1 ] && grep -q "$REPO_STRING" "$TMP/$k.b"; } \
      || bad="$bad $h($c, scripts $ns, theme.js tags $nt, repo string $(grep -c "$REPO_STRING" "$TMP/$k.b"))"
  done
  if [ -z "$bad" ]; then emit L07 PASS "[GATE] /security-policy/ 200, no script but theme.js, names $REPO_STRING, both hosts"
  else emit L07 FAIL "[GATE] /security-policy/:$bad"; fi

  bad=""; for h in $HOSTS; do k="$(key "$h" /.well-known/pgp-key.txt)"; c="$(code "$h" /.well-known/pgp-key.txt)"
    first="$(head -1 "$TMP/$k.b" 2>/dev/null | tr -d '\r')"
    { [ "$c" = "200" ] && [ "$first" = "-----BEGIN PGP PUBLIC KEY BLOCK-----" ] && ! grep -q "$PRIV" "$TMP/$k.b" \
      && cmp -s "$TMP/$k.b" "$REF/.well-known/pgp-key.txt"; } || bad="$bad $h($c)"
  done
  if [ -z "$bad" ]; then emit L08 PASS "[GATE] /.well-known/pgp-key.txt 200, public block, byte-identical to src, both hosts"
  else emit L08 FAIL "[GATE] pgp-key.txt:$bad"; fi

  M="$TMP/mta"
  curl -s --max-time 25 -D "$M.h" -o "$M.b" -w '%{http_code}' "https://mta-sts.$HOST/.well-known/mta-sts.txt" > "$M.code" 2>/dev/null
  rc=$?
  if [ "$rc" != "0" ]; then emit L09 FAIL "[GATE] mta-sts.$HOST unreachable (curl exit $rc)"
  else
    final_block "$M.h" > "$M.hf"; c="$(cat "$M.code")"; ct="$(hval content-type "$M.hf" | lc)"
    same="differs from"; cmp -s "$M.b" "$REF/.well-known/mta-sts.txt" && same="="
    if [ "$c" = "200" ] && case "$ct" in text/plain*) true ;; *) false ;; esac \
       && grep -qx 'mode: testing' "$M.b" && [ "$same" = "=" ]; then
      emit L09 PASS "[GATE] mta-sts.txt 200 $ct, mode: testing, body = src copy"
    else emit L09 FAIL "[GATE] mta-sts.txt status $c, content-type $ct, mode $(grep '^mode:' "$M.b"), body $same src copy"; fi
  fi

  ov="$("$OPENSSL" version 2>&1)"
  emit L10 INFO "openssl: $OPENSSL ($ov)"
  sl0=""; "$OPENSSL" ciphers 'DEFAULT@SECLEVEL=0' >/dev/null 2>&1 && sl0="-cipher DEFAULT@SECLEVEL=0"
  for v in tls1 tls1_1 tls1_2 tls1_3; do
    o="$(perl -e 'alarm 20; exec @ARGV' "$OPENSSL" s_client -connect "$HOST:443" -servername "$HOST" -"$v" $sl0 </dev/null 2>&1)"
    if printf '%s' "$o" | grep -q 'no protocols available'; then st=SKIP; what="-$v: this openssl cannot offer it"
    elif printf '%s' "$o" | grep -q '^New, TLSv'; then
      neg="$(printf '%s' "$o" | grep '^New, TLSv' | head -1)"
      case "$v" in tls1|tls1_1) st=FAIL; what="-$v ACCEPTED: $neg" ;; *) st=PASS; what="-$v accepted: $neg" ;; esac
    elif printf '%s' "$o" | grep -q -E 'alert protocol version|handshake failure|unsupported protocol|wrong version'; then
      case "$v" in tls1|tls1_1) st=PASS; what="-$v refused by the server" ;; *) st=FAIL; what="-$v refused" ;; esac
    else st=SKIP; what="-$v: no clear answer ($(printf '%s' "$o" | tail -1))"; fi
    emit L10 "$st" "$what"
  done

  if [ -z "$STAGE" ]; then emit L11 SKIP "[GATE] no --stage: served-vs-built comparison not run"
  else
    n=0; same=0; diffs=""
    for f in $(cd "$STAGE" && find . -type f ! -name _headers | sed 's#^\./##' | sort); do
      u="/$f"; case "$f" in index.html) u="/" ;; */index.html) u="/${f%index.html}" ;; esac
      hs="$HOST"; case "$f" in *.html) hs="$HOSTS" ;; esac
      for h in $hs; do
        n=$((n+1)); g="$TMP/l11-$(key "$h" "$u")"
        curl -s --max-time 25 -o "$g" "https://$h$u" 2>/dev/null || : > "$g"
        if cmp -s "$g" "$STAGE/$f"; then same=$((same+1)); else diffs="$diffs $h$u"; fi
      done
    done
    if [ "$same" = "$n" ]; then emit L11 PASS "[GATE] $same/$n served files byte-identical to the stage (HTML on both hosts)"
    else emit L11 FAIL "[GATE] $same/$n identical; differ:$diffs"; fi
  fi

  SH="$TMP/sh"
  curl -s --max-time 45 -D "$SH.h" -o /dev/null "https://securityheaders.com/?q=$HOST&followRedirects=on&hide=on" 2>/dev/null
  final_block "$SH.h" > "$SH.hf" 2>/dev/null || : > "$SH.hf"
  g="$(hval x-grade "$SH.hf")"
  if [ -n "$g" ]; then emit L12 INFO "securityheaders x-grade: $g"
  else emit L12 INFO "securityheaders.com gave no x-grade (often a bot challenge); read the grade in a browser"; fi
  if [ "$OBS" = "1" ]; then
    o="$(curl -s --max-time 60 -X POST "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=$HOST" 2>/dev/null)"
    emit L12 INFO "Observatory: $(printf '%s' "$o" | python3 -B -I -c 'import json,sys
try: d=json.load(sys.stdin); print("grade %s, score %s, tests passed %s/%s" % (d.get("grade"), d.get("score"), d.get("tests_passed"), d.get("tests_quantity")))
except Exception: print("no JSON answer")')"
  else emit L12 INFO "Observatory POST not sent (pass --observatory; Leg 6 sends the one POST)"; fi

  HP="$TMP/hp.json"
  if curl -s --max-time 30 -o "$HP" "https://hstspreload.org/api/v2/preloadable?domain=$HOST" 2>/dev/null; then
    emit L13 INFO "preloadable: $(python3 -B -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); f=lambda xs: " / ".join(x.get("code","?") for x in xs) or "none"
    print("%d error(s) [%s]; %d warning(s) [%s]" % (len(d.get("errors",[])), f(d.get("errors",[])), len(d.get("warnings",[])), f(d.get("warnings",[]))))
except Exception: print("not JSON")' "$HP")"
  else emit L13 INFO "hstspreload.org unreachable"; fi
  if curl -s --max-time 30 -o "$HP.s" "https://hstspreload.org/api/v2/status?domain=$HOST" 2>/dev/null; then
    emit L13 INFO "status: $(python3 -B -I -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("status","?"))
except Exception: print("not JSON")' "$HP.s")"
  fi

  bad=""
  for h in $HOSTS; do
    for p in $PAGES; do [ "$(code "$h" "$p")" = "200" ] || bad="$bad $h$p=$(code "$h" "$p")"; done
    k="$(key "$h" /about)"; loc="$(hval location "$TMP/$k.hf")"
    { [ "$(code "$h" /about)" = "308" ] && { [ "$loc" = "/about/" ] || [ "$loc" = "https://$h/about/" ]; }; } || bad="$bad $h/about=$(code "$h" /about)->$loc"
    k="$(key "$h" /nope-404-test)"
    { [ "$(code "$h" /nope-404-test)" = "404" ] && grep -q '<title>Not found — The Clauditor</title>' "$TMP/$k.b"; } || bad="$bad $h/nope-404-test=$(code "$h" /nope-404-test)"
    [ "$(code "$h" /404.html)" = "200" ] || bad="$bad $h/404.html=$(code "$h" /404.html)"
  done
  if [ -z "$bad" ]; then emit L15 PASS "[GATE] 8 pages 200 on both hosts; /about 308 -> /about/; /nope-404-test 404 with the custom page; /404.html 200"
  else emit L15 FAIL "[GATE] pages:$bad"; fi

  files=""; for h in $HOSTS; do for p in $PAGES /404.html /assets/site.css; do files="$files $TMP/$(key "$h" "$p").b"; done; done
  t="$(python3 -B -I -c '
import re, sys
ORIGIN = "https://" + sys.argv[1] + "/"
bad = []
for f in sys.argv[2:]:
    t = open(f, encoding="utf-8", errors="replace").read()
    refs = re.findall(r"url\(\s*[\x27\"]?([^\x27\")\s]*)", t) + re.findall(r"@import\s+(?:url\()?\s*[\x27\"]?([^\x27\")\s;]+)", t)
    refs += re.findall(r"\ssrc\s*=\s*[\x27\"]?([^\x27\"\s>]*)", t, re.I) + re.findall(r"\sposter\s*=\s*[\x27\"]?([^\x27\"\s>]*)", t, re.I)
    refs += re.findall(r"\sdata\s*=\s*[\x27\"]?([^\x27\"\s>]*)", t, re.I)
    for v in re.findall(r"\ssrcset\s*=\s*[\x27\"]([^\x27\"]*)", t, re.I):
        refs += [p.strip().split(" ")[0] for p in v.split(",") if p.strip()]
    for tag in re.findall(r"<link\b[^>]*>", t, re.I):
        m = re.search(r"\shref\s*=\s*[\x27\"]?([^\x27\"\s>]*)", tag, re.I)
        if m: refs.append(m.group(1))
    for u in refs:
        if not ((u.startswith("/") and not u.startswith("//")) or u.startswith(ORIGIN)):
            bad.append(u)
    n = t.count("googleapis") + t.count("gstatic")
    if n: bad.append("googleapis/gstatic x%d" % n)
print("%d|%s" % (len(bad), " ".join(sorted(set(bad))[:6])))
' "$HOST" $files)"
  if [ "${t%%|*}" = "0" ]; then emit L16 PASS "[GATE] no third-party resource in the served HTML and CSS (9 pages + site.css x 2 hosts); googleapis/gstatic 0"
  else emit L16 FAIL "[GATE] references outside the rule (third-party, or not root-relative): ${t#*|}"; fi

  bad=""; for h in $HOSTS; do k="$(key "$h" /sitemap.xml)"; ct="$(hval content-type "$TMP/$k.hf" | lc)"
    nl="$(grep -o '<loc>' "$TMP/$k.b" | wc -l | tr -d ' ')"
    case "$ct" in application/xml*|text/xml*) ctok=1 ;; *) ctok=0 ;; esac
    { [ "$(code "$h" /sitemap.xml)" = "200" ] && [ "$ctok" = "1" ] && [ "$nl" = "8" ]; } || bad="$bad $h/sitemap.xml($(code "$h" /sitemap.xml), $ct, $nl loc)"
    grep -qx "Sitemap: https://$HOST/sitemap.xml" "$TMP/$(key "$h" /robots.txt).b" || bad="$bad $h/robots.txt(no Sitemap line)"
  done
  if [ -z "$bad" ]; then emit L17 PASS "[GATE] /sitemap.xml 200 xml with 8 <loc>; /robots.txt has the Sitemap line; both hosts"
  else emit L17 FAIL "[GATE]$bad"; fi

  bad=""; nf=0
  css="$TMP/$(key "$HOST" /assets/site.css).b"
  [ "$(code "$HOST" /assets/site.css)" = "200" ] && case "$(hval content-type "$TMP/$(key "$HOST" /assets/site.css).hf" | lc)" in text/css*) true ;; *) false ;; esac \
    || bad="$bad site.css($(code "$HOST" /assets/site.css))"
  for u in $(grep -o 'url(/fonts/[^)]*)' "$css" 2>/dev/null | sed -e 's#^url(##' -e 's#)$##' | sort -u); do
    nf=$((nf+1))
    r="$(curl -s --max-time 25 -o /dev/null -w '%{http_code} %{content_type}' "https://$HOST$u" 2>/dev/null)"
    [ "$r" = "200 font/woff2" ] || bad="$bad $u($r)"
  done
  [ "$nf" -gt 0 ] || bad="$bad no-fonts-in-site.css"
  k="$(key "$HOST" /assets/theme.js)"; ct="$(hval content-type "$TMP/$k.hf" | lc)"
  case "$ct" in text/javascript*|application/javascript*) ctok=1 ;; *) ctok=0 ;; esac
  { [ "$(code "$HOST" /assets/theme.js)" = "200" ] && [ "$ctok" = "1" ]; } || bad="$bad theme.js($(code "$HOST" /assets/theme.js), $ct)"
  if [ -n "$STAGE" ]; then cmp -s "$TMP/$k.b" "$STAGE/assets/theme.js" || bad="$bad theme.js(differs from stage)"
  else cmp -s "$TMP/$k.b" "$REF/assets/theme.js" || bad="$bad theme.js(differs from src)"; fi
  k="$(key "$HOST" /favicon.svg)"; ct="$(hval content-type "$TMP/$k.hf" | lc)"
  { [ "$(code "$HOST" /favicon.svg)" = "200" ] && case "$ct" in image/svg+xml*) true ;; *) false ;; esac && ! grep -q '@import' "$TMP/$k.b"; } \
    || bad="$bad favicon.svg($(code "$HOST" /favicon.svg), $ct, @import x$(grep -c '@import' "$TMP/$k.b"))"
  if [ -z "$bad" ]; then emit L18 PASS "[GATE] $nf woff2 200 font/woff2; site.css 200 text/css; theme.js 200 $ct, byte-equal; favicon.svg 200 image/svg+xml, no @import"
  else emit L18 FAIL "[GATE]$bad"; fi

  for h in $HOSTS; do emit L18 INFO "retired /assets/coin3d.js on $h: $(code "$h" /assets/coin3d.js) (404 once the services site is live)"; done
fi

if [ "$SECTION" != "headers" ]; then
  d() { dig +short "$@" @1.1.1.1 2>/dev/null; }

  dm="$(d TXT "_dmarc.$HOST" | tr -d '"')"
  if printf '%s' "$dm" | grep -q -E '(^|; *)p=(quarantine|reject)(;|$)'; then emit L14 PASS "[GATE] DMARC: $dm"
  else emit L14 FAIL "[GATE] DMARC needs p=quarantine or p=reject: '${dm}'"; fi

  spf="$(d TXT "$HOST" | tr -d '"' | grep '^v=spf1' || true)"
  if [ -n "$spf" ]; then emit L14 PASS "SPF present: $spf"; else emit L14 FAIL "SPF absent"; fi

  dk="$(d TXT "google._domainkey.$HOST" | tr -d '" ')"
  if printf '%s' "$dk" | grep -q 'v=DKIM1' && printf '%s' "$dk" | grep -q 'p=[A-Za-z0-9+/]'; then emit L14 PASS "DKIM selector google._domainkey present"
  else emit L14 FAIL "DKIM selector google._domainkey absent"; fi

  ms="$(d TXT "_mta-sts.$HOST" | tr -d '"')"
  if printf '%s' "$ms" | grep -q '^v=STSv1; *id='; then emit L14 PASS "[GATE] _mta-sts: $ms"; else emit L14 FAIL "[GATE] _mta-sts TXT absent or malformed: '${ms}'"; fi

  tr_="$(d TXT "_smtp._tls.$HOST" | tr -d '"')"
  if printf '%s' "$tr_" | grep -q '^v=TLSRPTv1; *rua='; then emit L14 PASS "[GATE] _smtp._tls: $tr_"; else emit L14 FAIL "[GATE] _smtp._tls TXT absent or malformed: '${tr_}'"; fi

  caa="$(d CAA "$HOST")"; miss=""
  while IFS= read -r ca; do
    [ -n "$ca" ] || continue
    for tag in issue issuewild; do printf '%s\n' "$caa" | grep -qxF "0 $tag \"$ca\"" || miss="$miss | 0 $tag \"$ca\""; done
  done <<EOF
$CAA_CAS
EOF
  if [ -z "$caa" ]; then emit L14 FAIL "[GATE] CAA absent on $HOST"
  elif [ -z "$miss" ]; then emit L14 PASS "[GATE] CAA includes issue + issuewild for all 4 Cloudflare CAs ($(printf '%s\n' "$caa" | wc -l | tr -d ' ') records live)"
  else emit L14 FAIL "[GATE] CAA missing:${miss# |}"; fi

  ds="$(d DS "$HOST")"
  ad="$(dig "$HOST" +dnssec @1.1.1.1 2>/dev/null | grep -c -E 'flags:[^;]* ad[ ;]' || true)"
  if [ -n "$ds" ] && [ "$ad" -ge 1 ]; then emit L14 PASS "[GATE] DNSSEC: DS published ($(printf '%s' "$ds" | head -1 | cut -c1-40)...) and the AD flag set by 1.1.1.1"
  else emit L14 FAIL "[GATE] DNSSEC: DS '${ds:-absent}', AD flag lines $ad"; fi
  emit L14 INFO "MX: $(d MX "$HOST" | tr '\n' ' ')"
fi

np="$(grep -c ' PASS — ' "$RES" || true)"; nf="$(grep -c ' FAIL — ' "$RES" || true)"
ns="$(grep -c ' SKIP — ' "$RES" || true)"; ni="$(grep -c ' INFO — ' "$RES" || true)"
gf="$(grep ' FAIL — \[GATE\]' "$RES" | awk '{print $1}' | sort -u | tr '\n' ' ')"
echo "TOTAL: $np PASS · $nf FAIL · $ns SKIP · $ni INFO · GATE failures: ${gf:-none}" | tee -a "$RES"
cat "$RES.head" "$RES" > "$OUT"
echo "written: $OUT"
[ "$nf" = "0" ]
