#!/usr/bin/env python3
"""build_zip.py - build a fresh stage and zip it for the Cloudflare Pages upload.

  python3 -B tools/build_zip.py --build-date YYYY-MM-DD [--out <zip>]

Builds src/ with build.py into $TMPDIR/clauditor-services/stage (wiped first), passing
--securityplus-url from SECURITYPLUS-URL.txt and --copy from COPY-services-site-v1.md when those
files sit beside tools/. Zips the stage root-relative with Python's zipfile (never the zip
command on a network mount) into a temp file, moves it into place with mv -f, prints its sha256
and entry count, and writes out/BUILD-<date>.txt (the per-file sha256 list).
The zip is deterministic: sorted entries, one timestamp (the build date), fixed permissions.
Python 3.9+ standard library only.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

TOOLS = os.path.dirname(os.path.realpath(__file__))
SITE = os.path.dirname(TOOLS)
ZIP_NAME = "theclauditor-ai-site-2026-10-27-services.zip"


def die(msg):
    sys.stderr.write("build_zip: FAIL - " + msg + "\n")
    sys.exit(1)


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Build and zip theclauditor.ai.")
    ap.add_argument("--build-date", required=True, dest="build_date")
    ap.add_argument("--out", default=os.path.join(SITE, "out", ZIP_NAME))
    args = ap.parse_args()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.build_date):
        die("--build-date must be YYYY-MM-DD")

    tmp_root = os.path.realpath(os.environ.get("TMPDIR") or tempfile.gettempdir())
    work = os.path.join(tmp_root, "clauditor-services")
    stage = os.path.join(work, "stage")
    if os.path.isdir(stage):
        shutil.rmtree(stage)  # under $TMPDIR only: a stage may be wiped there
    os.makedirs(work, exist_ok=True)

    cmd = [sys.executable, "-B", os.path.join(TOOLS, "build.py"), "--src", os.path.join(SITE, "src"),
           "--dest", stage, "--build-date", args.build_date]
    sp_file = os.path.join(SITE, "SECURITYPLUS-URL.txt")
    sp_set = os.path.isfile(sp_file) and open(sp_file, encoding="utf-8").read().strip() != ""
    if sp_set:
        cmd += ["--securityplus-url", open(sp_file, encoding="utf-8").read().strip()]
    copy = os.path.join(SITE, "COPY-services-site-v1.md")
    if os.path.isfile(copy):
        cmd += ["--copy", copy]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        die("build.py failed")

    y, m, d = (int(x) for x in args.build_date.split("-"))
    stamp = (y, m, d, 0, 0, 0)
    files, dirs = [], set()
    for root, dnames, fnames in os.walk(stage):
        dnames.sort()
        for f in sorted(fnames):
            rel = os.path.relpath(os.path.join(root, f), stage).replace(os.sep, "/")
            if f == ".DS_Store" or f.startswith("._") or f.startswith(".smbdelete"):
                die("litter in the stage: " + rel)
            files.append(rel)
            parts = rel.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]) + "/")
    entries = sorted(list(dirs) + files)

    fd, tmpzip = tempfile.mkstemp(suffix=".zip", dir=work)
    os.close(fd)
    with zipfile.ZipFile(tmpzip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in entries:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.create_system = 3
            if name.endswith("/"):
                info.external_attr = (0o40755 << 16) | 0x10
                z.writestr(info, b"")
            else:
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(os.path.join(stage, name), "rb") as fh:
                    z.writestr(info, fh.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    r = subprocess.run(["mv", "-f", tmpzip, args.out])
    if r.returncode != 0:
        die("mv -f into place failed")
    digest = sha_file(args.out)

    lines = ["BUILD %s" % args.build_date,
             "Security+ link: %s" % ("set" if sp_set else "not set"),
             "zip: %s" % os.path.basename(args.out),
             "zip sha256: %s" % digest,
             "entries: %d files + %d directories" % (len(files), len(dirs)),
             "", "per-file sha256 (stage):"]
    lines += ["%s  %s" % (sha_file(os.path.join(stage, f)), f) for f in files]
    report = os.path.join(os.path.dirname(os.path.abspath(args.out)), "BUILD-%s.txt" % args.build_date)
    with open(report, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("build_zip: %s" % args.out)
    print("build_zip: sha256 %s · %d files + %d directory entries · Security+ link %s"
          % (digest, len(files), len(dirs), "set" if sp_set else "not set"))
    print("build_zip: stage %s · report %s" % (stage, report))


if __name__ == "__main__":
    main()
