#!/usr/bin/env python3
"""secret_scan.py - refuse a tree that carries a secret, a personal number or an internal name.

  python3 -B tools/secret_scan.py <dir> [--allow <literal>]... [--deny-file <file>]... [--require-private]

Walks every file under <dir> (a .git folder excepted) and prints each hit as
"file:line: <pattern name> (<masked match>)". Exits 1 on any hit, 2 on a usage error, 0 when clean.

Built-in patterns: private-key markers, GitHub / AWS / Anthropic / Slack token shapes, an EIN,
SSN and phone-number shape, and "password" followed by ":" or "=". The patterns are assembled
from pieces so this file never matches itself.
Private literals - internal names, addresses, numbers - are never written into this public file.
They are read, one per line ("#" lines skipped), from $HOME/.config/clauditor/denylist.txt and
from each --deny-file, and matched case-insensitively. --require-private makes it an error when
no private literal was loaded.
A line that contains an --allow literal is excused, and so is the header line of a published
PGP public key (a public key is meant to be published; a private-key header still trips).
Binary files are checked for every pattern except the three number shapes.
Python 3.9+ standard library only.
"""
import argparse
import os
import re
import sys

D5 = "-" * 5
PATTERNS = [  # (name, regex, applies to binary files too)
    ("private key", re.compile("PRIVATE" + " KEY"), True),
    ("private key block", re.compile("BEGIN (RSA|OPENSSH|PGP " + "PRIVATE)"), True),
    ("GitHub token", re.compile("gh" + "p_[A-Za-z0-9]{20,}"), True),
    ("GitHub fine-grained token", re.compile("github" + "_pat_"), True),
    ("AWS access key", re.compile("AK" + "IA[0-9A-Z]{16}"), True),
    ("Anthropic key", re.compile("sk" + "-ant-"), True),
    ("Slack token", re.compile("xo" + "x[bp]-"), True),
    ("armored block", re.compile(D5 + "BEGIN"), True),
    ("EIN shape", re.compile(r"\b\d{2}-\d{7}\b"), False),
    ("SSN shape", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), False),
    ("phone shape", re.compile(r"\b\d{3}[-. ]\d{3}[-. ]\d{4}\b"), False),
    ("password assignment", re.compile("pass" + r"word\s*[:=]", re.I), True),
]
BUILTIN_ALLOW = [D5 + "BEGIN PGP PUBLIC KEY BLOCK" + D5]
HOME_LIST = os.path.join(os.path.expanduser("~"), ".config", "clauditor", "denylist.txt")


def mask(s):
    s = s.strip()
    return "%s…(%d chars)" % (s[:2], len(s)) if len(s) > 2 else "…(%d chars)" % len(s)


def load_literals(paths):
    lits, used = [], []
    for p in paths:
        if os.path.isfile(p):
            used.append(p)
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if line.strip() and not line.startswith("#"):
                        lits.append(line)
    return lits, used


def main():
    ap = argparse.ArgumentParser(description="Refuse a tree that carries a secret or an internal name.")
    ap.add_argument("dir")
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--deny-file", action="append", default=[], dest="deny")
    ap.add_argument("--require-private", action="store_true", dest="require")
    args = ap.parse_args()
    if not os.path.isdir(args.dir):
        sys.stderr.write("secret_scan: not a folder: %s\n" % args.dir)
        sys.exit(2)
    for p in args.deny:
        if not os.path.isfile(p):
            sys.stderr.write("secret_scan: --deny-file not found: %s\n" % p)
            sys.exit(2)
    lits, used = load_literals([HOME_LIST] + args.deny)
    if args.require and not lits:
        sys.stderr.write("secret_scan: --require-private, but no private literal was loaded\n")
        sys.exit(2)
    allow = BUILTIN_ALLOW + args.allow
    lowered = [(i + 1, l.lower()) for i, l in enumerate(lits)]

    hits, nfiles = 0, 0
    root = os.path.abspath(args.dir)
    for r, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for f in sorted(files):
            path = os.path.join(r, f)
            rel = os.path.relpath(path, root)
            nfiles += 1
            with open(path, "rb") as fh:
                data = fh.read()
            binary = b"\0" in data[:8192]
            text = data.decode("utf-8" if not binary else "latin-1", "replace")
            for n, line in enumerate(text.split("\n"), 1):
                if any(a in line for a in allow):
                    continue
                for name, rx, on_binary in PATTERNS:
                    if binary and not on_binary:
                        continue
                    for m in rx.finditer(line):
                        hits += 1
                        print("%s:%d: %s (%s)" % (rel, n, name, mask(m.group(0))))
                low = line.lower()
                for i, lit in lowered:
                    if lit in low:
                        hits += 1
                        print("%s:%d: private denylist entry %d (%s)" % (rel, n, i, mask(lit)))
    print("secret_scan: %d files, %d hit(s); private literals: %d from %s"
          % (nfiles, hits, len(lits), ", ".join(os.path.basename(u) for u in used) or "none"))
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
