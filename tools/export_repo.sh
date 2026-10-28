#!/bin/bash
# export_repo.sh - fill the public repository's working copy from the allowlist, then scan it.
#   bash tools/export_repo.sh --dest <dir> [--update] [--dry-run]
# Reads tools/REPO-FILES.txt (one path per line, relative to the release folder; a path under
# repo/ is published at the root: repo/README.md -> README.md). Refuses if a listed file is
# missing or a line is not a plain relative path. Copies file by file (mkdir -p + cp, never a
# folder copy) and sets every file to mode 644. Then runs tools/secret_scan.py on the result
# with the private denylist (PRIVATE-DENYLIST.txt beside tools/, which must exist), and
# gitleaks when it is installed. Prints the tree with each file's sha256.
#   --dest     the working copy; it must not exist or must be empty, unless --update.
#   --update   replace the listed files in an existing working copy; .git is never touched;
#              a file there that is not on the list is reported and the run fails.
#   --dry-run  copy into a fresh folder under $TMPDIR (or into --dest, which must then be
#              empty) and print the list; nothing outside that folder is written.
# Exits 1 on a refusal or any scan hit. Runs no git command. bash 3.2-compatible.
set -u
usage() { echo "usage: export_repo.sh --dest <dir> [--update] [--dry-run]" >&2; exit 2; }
DEST=""; UPDATE=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) [ $# -ge 2 ] || usage; DEST="$2"; shift 2 ;;
    --update) UPDATE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    *) usage ;;
  esac
done
TOOLS="$(cd "$(dirname "$0")" && pwd)"
BASE="$(dirname "$TOOLS")"
LIST="$TOOLS/REPO-FILES.txt"
DENY="$BASE/PRIVATE-DENYLIST.txt"
fail() { echo "export_repo: REFUSED - $1" >&2; exit 1; }

if [ "$DRY" = "1" ] && [ -z "$DEST" ]; then
  T="${TMPDIR:-/tmp}"; T="${T%/}"
  DEST="$(mktemp -d "$T/repo-export.XXXXXX")"
fi
[ -n "$DEST" ] || usage
[ "$DRY" = "1" ] && [ "$UPDATE" = "1" ] && fail "--dry-run and --update together"
[ -f "$LIST" ] || fail "no $LIST"
[ -f "$DENY" ] || fail "no private denylist at $DENY (the scan would not check internal names)"
if [ -e "$DEST" ] && [ ! -d "$DEST" ]; then fail "$DEST exists and is not a folder"; fi
if [ -d "$DEST" ] && [ -n "$(ls -A "$DEST")" ] && [ "$UPDATE" = "0" ]; then
  fail "$DEST exists and is not empty (use --update for an existing working copy)"
fi
if [ "$UPDATE" = "1" ] && [ ! -d "$DEST" ]; then fail "--update, but $DEST does not exist"; fi
case "$DEST" in "$BASE"|"$BASE"/*) fail "--dest is inside the release folder" ;; esac

# Read the list: plain relative paths only.
PAIRS="$(mktemp "${TMPDIR:-/tmp}/repo-pairs.XXXXXX")"
trap 'rm -f "$PAIRS"' EXIT
missing=""
while IFS= read -r p || [ -n "$p" ]; do
  case "$p" in ""|"#"*) continue ;; esac
  case "$p" in
    /*|*..*|*'*'*|*'?'*|*'['*|*" "*) fail "not a plain relative path in the list: $p" ;;
  esac
  [ -f "$BASE/$p" ] || missing="$missing $p"
  case "$p" in repo/*) out="${p#repo/}" ;; *) out="$p" ;; esac
  printf '%s\t%s\n' "$p" "$out" >> "$PAIRS"
done < "$LIST"
[ -z "$missing" ] || fail "listed but missing:$missing"
dups="$(cut -f2 "$PAIRS" | sort | uniq -d)"
[ -z "$dups" ] || fail "two list lines publish the same path: $dups"

# Copy, file by file.
mkdir -p "$DEST" || fail "cannot create $DEST"
n=0
while IFS="$(printf '\t')" read -r p out; do
  mkdir -p "$(dirname "$DEST/$out")" && cp "$BASE/$p" "$DEST/$out" && chmod 644 "$DEST/$out" \
    || fail "copy failed: $p"
  n=$((n + 1))
done < "$PAIRS"

# In an existing working copy, anything not on the list is reported.
extra=""
if [ "$UPDATE" = "1" ]; then
  extra="$( ( cd "$DEST" && find . -type f ! -path './.git/*' ! -path './dist/*' ! -path './out/*' \
      ! -name '.DS_Store' ! -name '._*' ! -name '*.zip' | sed 's|^\./||' ) | while IFS= read -r f; do
      cut -f2 "$PAIRS" | grep -qxF "$f" || echo "$f"; done )"
fi

# The tree, with each file's sha256.
echo "export_repo: $n files -> $DEST"
while IFS="$(printf '\t')" read -r p out; do
  printf '%s  %s\n' "$(shasum -a 256 "$DEST/$out" | cut -c1-64)" "$out"
done < "$PAIRS"

rc=0
if [ -n "$extra" ]; then
  echo "export_repo: FAIL - in the working copy but not on the list (remove them with git rm, or list them):"
  echo "$extra" | sed 's/^/  /'
  rc=1
fi
python3 -B "$TOOLS/secret_scan.py" "$DEST" --deny-file "$DENY" --require-private || rc=1
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --no-git --source "$DEST" --no-banner || rc=1
else
  echo "gitleaks: not installed - SKIP"
fi
[ "$DRY" = "1" ] && echo "export_repo: dry run - nothing outside $DEST was written"
if [ "$rc" = "0" ]; then echo "export_repo: OK - $n files, 0 scan hits"; else echo "export_repo: FAILED - nothing should be committed" >&2; fi
exit "$rc"
