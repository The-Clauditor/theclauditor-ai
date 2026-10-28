#!/usr/bin/env python3
"""check_site.py - the static gates for a built theclauditor.ai (G03-G16, G18-G22, G24).

  python3 -B tools/check_site.py --dist dist [--securityplus-url URL]
  python3 -B tools/check_site.py --dist <stage> --src src --ref <10-26 src> --copy <COPY.md> [--zip <zip>] [--report <file>]
  python3 -B tools/check_site.py --zip <zip> --src src --ref <10-26 src> --copy <COPY.md> --report <file>

One line per gate: "Gnn PASS|FAIL|SKIP|INFO - <what>". Exits 1 on any FAIL.
Without --ref, G03's byte check is SKIP; without --copy, the G10 anchors are SKIP; never PASS.
With --zip and no --dist, the zip is unpacked to a temp folder and checked as the build;
G16 then compares it with a fresh build of --src (build date read from its sitemap.xml).
G19-G21 run only with --src, and only once the repository tools exist beside this file.
--securityplus-url names the Security+ link the build was given (G07 then allows its host on
/about/ and /proof/); beside the source it is read from SECURITYPLUS-URL.txt, and the two must agree.
Python 3.9+ standard library only.
"""
import argparse
import datetime
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from html.parser import HTMLParser

TOOLS = os.path.dirname(os.path.realpath(__file__))
BASE = os.path.dirname(TOOLS)

CSP_TARGET = ("default-src 'none'; script-src 'self'; img-src 'self'; style-src 'self'; "
              "font-src 'self'; base-uri 'none'; form-action mailto:; frame-ancestors 'none'; "
              "upgrade-insecure-requests")
HEADERS_EXPECTED = (
    "/*\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "  Content-Security-Policy: " + CSP_TARGET + "\n"
    "  X-Content-Type-Options: nosniff\n"
    "  X-Frame-Options: DENY\n"
    "  Referrer-Policy: strict-origin-when-cross-origin\n"
    "  Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
    "  Cross-Origin-Opener-Policy: same-origin\n"
    "  Cross-Origin-Resource-Policy: same-origin\n"
    "  ! Access-Control-Allow-Origin\n")
ROBOTS_EXPECTED = "User-agent: *\nAllow: /\nSitemap: https://theclauditor.ai/sitemap.xml\n"
ORIGIN = "https://theclauditor.ai"
REPO_URL = "https://github.com/The-Clauditor/theclauditor-ai"
NAV = [("/services/", "Services"), ("/how-we-work/", "How we work"),
       ("/sample-report/", "Sample report"), ("/proof/", "Proof"), ("/about/", "About")]
PAGES = ["/", "/services/", "/how-we-work/", "/sample-report/", "/about/", "/proof/",
         "/security-policy/", "/contact/"]
UNCHANGED = [".well-known/security.txt", ".well-known/pgp-key.txt", ".well-known/mta-sts.txt"]
FONTS = [
    "i7dMIFZifjKcF5UAWdDRaPpZUFWaHi6WZ3Q.woff2", "i7dMIFZifjKcF5UAWdDRaPpZUFqaHi6WZ3S_Yg.woff2",
    "i7dMIFZifjKcF5UAWdDRaPpZUFuaHi6WZ3S_Yg.woff2", "i7dPIFZifjKcF5UAWdDRYE58RXi4EwSsbg.woff2",
    "i7dPIFZifjKcF5UAWdDRYE98RXi4EwSsbg.woff2", "i7dPIFZifjKcF5UAWdDRYEF8RXi4EwQ.woff2",
    "jizBRFtNs2ka5fXjeivQ4LroWlx-6zUTjnTLgNs.woff2", "jizBRFtNs2ka5fXjeivQ4LroWlx-6zsTjnTLgNuZ5w.woff2",
    "jizHRFtNs2ka5fXjeivQ4LroWlx-6zAjgn7Motmp5r61.woff2", "jizHRFtNs2ka5fXjeivQ4LroWlx-6zAjjH7Motmp5g.woff2",
    "V8mDoQDjQSkFtoMM3T6r8E7mPb54C_k3HqUtEw.woff2", "V8mDoQDjQSkFtoMM3T6r8E7mPb94C_k3HqUtEw.woff2",
    "V8mDoQDjQSkFtoMM3T6r8E7mPbF4C_k3HqU.woff2"]
OFL = ["OFL-InstrumentSerif.txt", "OFL-SpaceGrotesk.txt", "OFL-SpaceMono.txt"]
ALLOWLIST = sorted(UNCHANGED + [
    "assets/og.jpg", "assets/theme.js", "assets/site.css", "_headers", "robots.txt", "favicon.svg",
    "sitemap.xml", "404.html", "index.html", "services/index.html", "how-we-work/index.html",
    "sample-report/index.html", "about/index.html", "proof/index.html", "security-policy/index.html",
    "contact/index.html"] + ["fonts/" + f for f in FONTS + OFL])
SCANNER_HOSTS = {"securityheaders.com", "developer.mozilla.org", "www.ssllabs.com", "mxtoolbox.com"}
THEME_FORBIDDEN = ["style", "cookie", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                   "eval", "Function(", "fetch", "XMLHttpRequest", "sendBeacon", "WebSocket", "import",
                   "http", "setTimeout", "setInterval"]
FORBIDDEN = ["Enterprise-grade", "gold standard", "etired", "federal trial", "most capable",
             "air-gapped", "HIPAA", "reseller", "our clients", "paying client", "[CONFIRM-", "[B-",
             "{{", "<!--SP:", "fonts.googleapis"]
FORBIDDEN_CI = ["medallion", "Hardened by hand", "steel", "tempered", "Element 6", "periodic table", "armor"]
# Internal names are never written into this public file. They are read, one literal per line
# (case-insensitive), from these private lists when present; neither is in the repository.
PRIVATE_LISTS = [os.path.join(BASE, "PRIVATE-DENYLIST.txt"),
                 os.path.join(os.path.expanduser("~"), ".config", "clauditor", "denylist.txt")]


def private_literals():
    found, lits = [], []
    for f in PRIVATE_LISTS:
        if os.path.isfile(f):
            found.append(f)
            with open(f, encoding="utf-8") as fh:
                lits += [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]
    return found, lits
TOKENS = ["--bg", "--surface", "--raise", "--line", "--fg", "--muted", "--accent", "--accent-fill", "--link"]
LIGHT = dict(zip(TOKENS, ["#F4F1EC", "#FBF9F5", "#ECE7DE", "#D9D2C5", "#0A0B0C", "#5D5850", "#7E5F2E",
                          "#B0894F", "#2F5F6E"]))
DARK = dict(zip(TOKENS, ["#0A0B0C", "#131517", "#1B1E21", "#2B2D30", "#F4F1EC", "#A39E95", "#C29A5E",
                         "#C29A5E", "#5E93A4"]))
DROPPED = ["body::before", ".hero::before", ".hero::after", ".cone", ".coinstage", ".coin3d", "coinspin",
           ".billet", ".dim", "gradient("]
SAMPLE_BANNER = ("SAMPLE — Alder & Finch Bookkeeping is a fictional firm. Every finding, name and number "
                 "on this page is illustrative. Real reports are confidential and prepared for one client.")

RESULTS = []


def gate(gid, status, what):
    RESULTS.append((gid, status, what))
    print("%s %s — %s" % (gid, status, what), flush=True)


def norm(s):
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def strip_tags(s):
    s = re.sub(r"<head\b.*?</head>", " ", s, flags=re.S | re.I)
    s = re.sub(r"<script\b.*?</script>", " ", s, flags=re.S | re.I)
    s = re.sub(r"<!--.*?-->", " ", s, flags=re.S)
    return norm(re.sub(r"<[^>]+>", "", s))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rb(path):
    with open(path, "rb") as fh:
        return fh.read()


def rt(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def file_for(dist, path):
    if path == "/404.html":
        return os.path.join(dist, "404.html")
    return os.path.join(dist, path.strip("/"), "index.html") if path != "/" else os.path.join(dist, "index.html")


def path_for(rel):
    if rel == "index.html":
        return "/"
    if rel == "404.html":
        return "/404.html"
    return "/" + rel[:-len("index.html")]


def list_files(root):
    out = []
    for r, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            out.append(os.path.relpath(os.path.join(r, f), root).replace(os.sep, "/"))
    return out


def ids_in(text):
    return set(re.findall(r'\sid="([^"]+)"', text))


def luminance(hx):
    def chan(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = int(hx[1:3], 16), int(hx[3:5], 16), int(hx[5:7], 16)
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


class TagCounter(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.opens, self.closes = {}, {}

    def handle_starttag(self, tag, attrs):
        self.opens[tag] = self.opens.get(tag, 0) + 1

    def handle_endtag(self, tag):
        self.closes[tag] = self.closes.get(tag, 0) + 1


def parse_copy(copy_text):
    """Titles, descriptions and anchors per path, from the copy of record."""
    meta, path = {}, None
    for line in copy_text.splitlines():
        m = re.match(r"^## §\d+ — .*?`(/[^`]*)`", line)
        if m:
            path = m.group(1)
            meta.setdefault(path, {})
            continue
        if line.startswith("## "):
            path = None
        m = re.match(r"^### 9\.1 `(/404\.html)`", line)
        if m:
            path = "/404.html"
            meta.setdefault(path, {})
            continue
        if path is None:
            continue
        m = re.match(r"^\*\*Title:\*\* `([^`]+)`", line) or re.match(r"^Title `([^`]+)`", line)
        if m:
            meta[path]["title"] = m.group(1)
        m = re.match(r"^\*\*Meta description:\*\* `([^`]+)`", line)
        if m:
            meta[path]["description"] = m.group(1)
    anchors = {}
    for m in re.finditer(r"```anchors (\S+)\n(.*?)\n```", copy_text, re.S):
        anchors[m.group(1)] = [l.strip() for l in m.group(2).splitlines() if l.strip()]
    return meta, anchors


def resource_refs(text, is_css):
    """Every URL that would load a resource: src, srcset, <link href>, url(), @import, poster, data."""
    refs = []
    if is_css:
        refs += re.findall(r"url\(\s*['\"]?([^'\")\s]*)", text)
        refs += re.findall(r"@import\s+(?:url\()?\s*['\"]?([^'\")\s;]+)", text)
        return refs
    refs += re.findall(r"\ssrc\s*=\s*[\"']?([^\"'\s>]*)", text, re.I)
    for v in re.findall(r"\ssrcset\s*=\s*[\"']([^\"']*)", text, re.I):
        refs += [p.strip().split(" ")[0] for p in v.split(",") if p.strip()]
    for tag in re.findall(r"<link\b[^>]*>", text, re.I):
        m = re.search(r"\shref\s*=\s*[\"']?([^\"'\s>]*)", tag, re.I)
        if m:
            refs.append(m.group(1))
    refs += re.findall(r"\sposter\s*=\s*[\"']?([^\"'\s>]*)", text, re.I)
    refs += re.findall(r"\sdata\s*=\s*[\"']?([^\"'\s>]*)", text, re.I)
    for v in re.findall(r"<style\b[^>]*>(.*?)</style>", text, re.S | re.I):
        refs += resource_refs(v, True)
    return refs


def local_ref(u):
    return (u.startswith("/") and not u.startswith("//")) or u.startswith(ORIGIN + "/")


def sp_file_url(args):
    if not args.src:
        return ""
    spf = os.path.join(os.path.dirname(os.path.realpath(args.src)), "SECURITYPLUS-URL.txt")
    return rt(spf).strip() if os.path.isfile(spf) else ""


def main():
    ap = argparse.ArgumentParser(description="Static gates for a built theclauditor.ai.")
    ap.add_argument("--dist")
    ap.add_argument("--src")
    ap.add_argument("--ref")
    ap.add_argument("--copy")
    ap.add_argument("--zip", dest="zip")
    ap.add_argument("--report")
    ap.add_argument("--build-date", dest="build_date")
    ap.add_argument("--securityplus-url", dest="sp_url", default="")
    args = ap.parse_args()
    if not args.dist and not args.zip:
        ap.error("give --dist, --zip, or both")

    header = "check_site.py — %s — dist=%s zip=%s src=%s ref=%s copy=%s" % (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), args.dist or "(from zip)", args.zip or "-",
        args.src or "-", args.ref or "-", args.copy or "-")
    print(header)
    tmp = tempfile.mkdtemp(prefix="check-site.")
    try:
        dist = args.dist
        if not dist:
            dist = os.path.join(tmp, "unzipped")
            with zipfile.ZipFile(args.zip) as z:
                z.extractall(dist)
        dist = os.path.realpath(dist)
        run_gates(args, dist, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    fails = sorted({g for g, s, _ in RESULTS if s == "FAIL"})
    last = "ALL GATES PASS" if not fails else "FAILED: " + " ".join(fails)
    print(last)
    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header + "\n")
            for g, s, w in RESULTS:
                fh.write("%s %s — %s\n" % (g, s, w))
            fh.write(last + "\n")
        print("report: " + args.report)
    sys.exit(1 if fails else 0)


def run_gates(args, dist, tmp):
    files = list_files(dist)
    html_files = [f for f in files if f.endswith(".html")]
    pages = {path_for(f): rt(os.path.join(dist, f)) for f in html_files}
    texts = {p: strip_tags(t) for p, t in pages.items()}
    norms = {p: norm(t) for p, t in pages.items()}
    css_path = os.path.join(dist, "assets", "site.css")
    css = rt(css_path) if os.path.isfile(css_path) else ""
    copy_text = rt(args.copy) if args.copy else ""
    copy_meta, anchors = parse_copy(copy_text) if copy_text else ({}, {})
    sp_url, sp_clash = args.sp_url.strip(), ""
    file_url = sp_file_url(args)
    if sp_url and file_url and sp_url != file_url:
        sp_clash = "--securityplus-url differs from SECURITYPLUS-URL.txt"
    sp_url = sp_url or file_url
    missing_pages = [p for p in PAGES + ["/404.html"] if p not in pages]

    # G03 - the unchanged files; no retired art.
    retired = [f for f in files if os.path.basename(f).startswith("coin") or f.endswith("ptable-fragment.webp")]
    if retired:
        gate("G03", "FAIL", "retired files in the build: " + ", ".join(retired))
    elif not args.ref:
        gate("G03", "SKIP", "no --ref: byte check of the 3 unchanged files not run (no coin*/ptable file present)")
    else:
        bad = [f for f in UNCHANGED if not os.path.isfile(os.path.join(dist, f))
               or rb(os.path.join(dist, f)) != rb(os.path.join(args.ref, f))]
        gate("G03", "FAIL" if bad else "PASS",
             ("differ from --ref: " + ", ".join(bad)) if bad else
             "3 unchanged files sha256-equal to --ref; no coin*/ptable file")

    # G04 - _headers.
    hp = os.path.join(dist, "_headers")
    hb = rb(hp) if os.path.isfile(hp) else b""
    problems = []
    if hb.decode("utf-8", "replace") != HEADERS_EXPECTED:
        problems.append("_headers differs from the expected file")
    if b"\r" in hb:
        problems.append("CRLF line endings")
    if hb.count(b"\n") != 10:
        problems.append("%d lines, want 10" % hb.count(b"\n"))
    scan = os.path.join(TOOLS, "scan_live.sh")
    m = re.search(r'^CSP_TARGET="([^"]*)"', rt(scan), re.M) if os.path.isfile(scan) else None
    if not m or m.group(1) != CSP_TARGET:
        problems.append("scan_live.sh CSP_TARGET missing or different")
    if args.ref:
        old = rt(os.path.join(args.ref, "_headers")).splitlines()
        new = hb.decode("utf-8", "replace").splitlines()
        diff = [i for i in range(max(len(old), len(new)))
                if i >= len(old) or i >= len(new) or old[i] != new[i]]
        if len(diff) != 1 or not new[diff[0]].strip().startswith("Content-Security-Policy:"):
            problems.append("diff vs --ref is not the CSP line alone (lines %s)" % diff)
    gate("G04", "FAIL" if problems else "PASS", "; ".join(problems) if problems else
         "_headers = the expected 10 LF lines; CSP = target = scan_live.sh constant%s"
         % ("; diff vs --ref = the CSP line only" if args.ref else ""))

    # G05 - fonts.
    problems = []
    for u in re.findall(r"url\(\s*['\"]?([^'\")\s]*)", css):
        if not u.startswith("/fonts/") or not os.path.isfile(os.path.join(dist, u.lstrip("/"))):
            problems.append("unresolved " + u)
    woff = [f for f in files if f.endswith(".woff2")]
    for f in woff:
        if rb(os.path.join(dist, f))[:4] != b"wOF2":
            problems.append(f + " is not woff2")
    ofl = [f for f in files if re.match(r"fonts/OFL.*\.txt$", f)]
    if len(ofl) != 3:
        problems.append("%d OFL files, want 3" % len(ofl))
    for f in files:
        b = rb(os.path.join(dist, f))
        if b"googleapis" in b or b"gstatic" in b:
            problems.append("googleapis/gstatic in " + f)
    gate("G05", "FAIL" if problems else "PASS", "; ".join(problems) if problems else
         "%d url(/fonts/...) resolve; %d woff2 start wOF2; 3 OFL files; no googleapis/gstatic anywhere"
         % (len(re.findall(r"url\(", css)), len(woff)))

    # G06 - zero external resource loads.
    problems = []
    for f in files:
        if f.endswith(".html") or f.endswith(".css"):
            t = rt(os.path.join(dist, f))
            for u in resource_refs(t, f.endswith(".css")):
                if not local_ref(u):
                    problems.append("%s: %s" % (f, u or "(empty)"))
            for tag in ("<iframe", "<object", "<embed", "<form"):
                if tag in t.lower():
                    problems.append("%s: %s" % (f, tag))
    gate("G06", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "every src/srcset/link href/url()/@import/poster/data is root-relative or theclauditor.ai; no iframe/object/embed/form")

    # G07 - external anchors.
    problems = [sp_clash] if sp_clash else []
    sp_host = re.sub(r"^https://([^/]+).*$", r"\1", sp_url) if sp_url else ""
    for p, t in pages.items():
        allowed = {"github.com"}
        if p == "/proof/":
            allowed |= SCANNER_HOSTS
        if p in ("/about/", "/proof/") and sp_host:
            allowed.add(sp_host)
        for u in re.findall(r"<a\b[^>]*\shref=\"([^\"]+)\"", t):
            if u.startswith("mailto:"):
                if u != "mailto:hello@theclauditor.ai":
                    problems.append("%s: %s" % (p, u))
            elif re.match(r"https?://", u):
                host = re.sub(r"^https?://([^/?#]+).*$", r"\1", u)
                if host not in allowed or not u.startswith("https://"):
                    problems.append("%s: %s" % (p, u))
    if "/proof/" in pages:
        for h in SCANNER_HOSTS:
            if "https://" + h not in pages["/proof/"]:
                problems.append("/proof/ lacks a %s link" % h)
    gate("G07", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "external anchors: github.com on every page; scanner hosts on /proof/ only; Security+ host %s"
         % (sp_host or "not set"))

    # G08 - scripts and styles.
    problems = []
    tag = '<script src="/assets/theme.js"></script>'
    for p, t in pages.items():
        if re.search(r"\sstyle\s*=", t, re.I):
            problems.append(p + " style=")
        if re.search(r"<style", t, re.I):
            problems.append(p + " <style")
        if len(re.findall(r"<script", t, re.I)) != 1 or not re.search(re.escape(tag) + r"\s*</head>", t):
            problems.append(p + " script is not the single theme.js tag ending <head>")
        if re.search(r"<[^>]*\son[a-z]+\s*=", t, re.I):
            problems.append(p + " inline handler")
        if "javascript:" in t.lower():
            problems.append(p + " javascript:")
    for f in files:
        if (f.endswith(".html") or f.endswith(".css")) and "coin" in rt(os.path.join(dist, f)).lower():
            problems.append(f + " mentions coin")
    tj = os.path.join(dist, "assets", "theme.js")
    if os.path.isfile(tj):
        js = rt(tj)
        if len(rb(tj)) > 1536:
            problems.append("theme.js is %d bytes" % len(rb(tj)))
        problems += ["theme.js has " + s for s in THEME_FORBIDDEN if s in js]
    else:
        problems.append("theme.js missing")
    gate("G08", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "%d pages: style= 0, <style 0, one theme.js tag last in <head>, no handlers, no javascript:; theme.js %d bytes, 0 forbidden strings; coin 0"
         % (len(pages), len(rb(tj))))

    # G09 - no relative asset paths.
    problems = []
    for p, t in pages.items():
        for u in re.findall(r"\s(?:src|href)=\"([^\"]*)\"", t):
            if not re.match(r"(/|#|https://|mailto:)", u):
                problems.append("%s: %s" % (p, u))
    gate("G09", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "every src/href is root-absolute, #fragment, https:// or mailto:")

    # G10 - forbidden strings, then the anchors.
    problems = []
    for p, t in norms.items():
        for s in FORBIDDEN:
            if s in t:
                problems.append("%s: %s" % (p, s))
        for s in FORBIDDEN_CI:
            if s.lower() in t.lower():
                problems.append("%s: %s" % (p, s))
        if p != "/proof/" and "Run your own scan" in t:
            problems.append(p + ": Run your own scan")
    plists, plits = private_literals()
    for p, t in norms.items():
        for i, s in enumerate(plits):
            if s.lower() in t.lower():
                problems.append("%s: private denylist entry %d" % (p, i + 1))
    gate("G10", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "0 forbidden strings across %d pages (%d public, %d case-insensitive, %d private); 'Run your own scan' only on /proof/"
         % (len(pages), len(FORBIDDEN), len(FORBIDDEN_CI), len(plits)))
    if not plists:
        gate("G10", "INFO", "no private denylist here (as in CI): internal names not checked by this run")
    if not copy_text:
        gate("G10-anchors", "SKIP", "no --copy")
    else:
        problems, n = [], 0
        for p, lines in sorted(anchors.items()):
            if p not in texts:
                problems.append("%s: page not built (%d anchors)" % (p, len(lines)))
                continue
            for line in lines:
                n += 1
                if norm(line) not in texts[p]:
                    problems.append("%s: missing %r" % (p, line))
        gate("G10-anchors", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
             "%d anchor lines from COPY present on %d pages" % (n, len(anchors)))

    # G11 - required strings.
    req = [("/about/", "nothing on this site is legal advice", False),
           ("/about/", "It is not affiliated with, endorsed by or in partnership with Anthropic.", False),
           ("/how-we-work/", "It is not affiliated with, endorsed by or in partnership with Anthropic.", False),
           ("/proof/", "No affiliation with Anthropic", False),
           ("/", "We assess only systems the client owns or is authorized to control", False),
           ("/how-we-work/", "We assess only systems the client owns or is authorized to control", False),
           ("/about/", "former civil trial lawyer", True),
           ("/about/", "earned June 2026, valid through June 2029", False),
           ("/proof/", "earned June 2026, valid through June 2029", False),
           ("/proof/", 'href="%s"' % REPO_URL, False)]
    problems = []
    for p, s, ci in req:
        if p not in pages:
            problems.append("%s not built (%s)" % (p, s[:40]))
        elif s.startswith("href="):
            if s not in pages[p]:
                problems.append("%s lacks %s" % (p, s))
        elif (s.lower() not in texts[p].lower()) if ci else (s not in texts[p]):
            problems.append("%s lacks %r" % (p, s))
    if "/sample-report/" in texts and texts["/sample-report/"].count(SAMPLE_BANNER) != 2:
        problems.append("/sample-report/ SAMPLE banner x%d" % texts["/sample-report/"].count(SAMPLE_BANNER))
    for p, t in pages.items():
        foot = re.search(r"<footer\b.*?</footer>", t, re.S)
        ft = foot.group(0) if foot else ""
        for s in ("Nothing on this site is legal advice.", "No cookies. No trackers. No third-party requests.",
                  'href="/security-policy/"', 'href="%s"' % REPO_URL):
            if s not in ft:
                problems.append("%s footer lacks %s" % (p, s))
    gate("G11", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "required statements present on their pages and in every footer")

    # G12 - links, nav and footer.
    problems = []
    navs, foots = {}, {}
    for p, t in pages.items():
        for u in re.findall(r"\shref=\"(/[^\"]*)\"", t):
            if u.startswith("//"):
                continue
            target, _, frag = u.partition("#")
            target = target.split("?")[0]
            fp = os.path.join(dist, target.lstrip("/"))
            if target.endswith("/") or os.path.isdir(fp):
                fp = os.path.join(fp, "index.html")
            if not os.path.isfile(fp):
                problems.append("%s -> %s missing" % (p, u))
            elif frag and frag not in ids_in(rt(fp)):
                problems.append("%s -> %s: no id %s" % (p, u, frag))
        for frag in re.findall(r"\shref=\"#([^\"]*)\"", t):
            if frag not in ids_in(t):
                problems.append("%s -> #%s: no such id" % (p, frag))
        n1 = re.search(r'<ul class="nav-links">(.*?)</ul>', t, re.S)
        n2 = re.search(r'<ul class="menu-links">(.*?)</ul>', t, re.S)
        if not n1 or not n2:
            problems.append(p + ": nav lists missing")
        else:
            if n1.group(1).strip() != n2.group(1).strip():
                problems.append(p + ": the two nav lists differ")
            hrefs = re.findall(r'href="([^"]+)"', n1.group(1))
            if hrefs != [h for h, _ in NAV]:
                problems.append(p + ": nav order " + " ".join(hrefs))
        want = 2 if p in [h for h, _ in NAV] else 0
        got = t.count('aria-current="page"')
        if got != want:
            problems.append("%s: aria-current x%d, want %d" % (p, got, want))
        nv = re.search(r'<a class="skip".*?</nav>', t, re.S)
        ft = re.search(r"<footer\b.*?</footer>", t, re.S)
        navs[p] = nv.group(0).replace(' aria-current="page"', "") if nv else ""
        foots[p] = ft.group(0) if ft else ""
    if len(set(navs.values())) > 1:
        problems.append("nav markup differs between pages")
    if len(set(foots.values())) > 1:
        problems.append("footer markup differs between pages")
    gate("G12", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "every internal href resolves (fragments included); nav lists identical and in order; aria-current right; nav and footer identical on %d pages" % len(pages))

    # G13 - page basics.
    problems = []
    for p, t in pages.items():
        checks = [('<html lang="en"', 1), ('<meta charset="utf-8">', 1),
                  ('<meta name="viewport" content="width=device-width, initial-scale=1">', 1),
                  ('<main id="main">', 1)]
        for s, want in checks:
            if t.count(s) != want:
                problems.append("%s: %s x%d" % (p, s, t.count(s)))
        if len(re.findall(r"<h1[\s>]", t)) != 1:
            problems.append(p + ": h1 count")
        title = re.search(r"<title>(.*?)</title>", t, re.S)
        desc = re.search(r'<meta name="description" content="([^"]*)">', t)
        title = html.unescape(title.group(1)) if title else ""
        desc = html.unescape(desc.group(1)) if desc else ""
        cm = copy_meta.get(p, {})
        if cm.get("title") and title != cm["title"]:
            problems.append("%s: title %r != COPY" % (p, title))
        if cm.get("description") and desc != cm["description"]:
            problems.append("%s: description != COPY" % p)
        if not title or not desc:
            problems.append(p + ": title or description empty")
        if '<link rel="canonical" href="%s%s">' % (ORIGIN, p) not in t:
            problems.append(p + ": canonical")
        for prop in ("og:title", "og:description", "og:url", "og:image"):
            if '<meta property="%s" content="' % prop not in t:
                problems.append("%s: %s" % (p, prop))
        body = re.search(r"<body[^>]*>\s*(<[^>]+>)", t)
        if not body or body.group(1) != '<a class="skip" href="#main">':
            problems.append(p + ": skip link not first in <body>")
        for img in re.findall(r"<img\b[^>]*>", t):
            if not re.search(r"\salt=", img):
                problems.append(p + ": img without alt")
        if t.count("<details") != len(re.findall(r"<details[^>]*>\s*<summary", t)):
            problems.append(p + ": details without summary")
    gate("G13", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "%d pages: lang, charset, viewport, one h1, one main, title + description%s, canonical, og:*, skip link first, img alt, details summary"
         % (len(pages), " = COPY" if copy_text else ""))

    # G14 - sitemap, robots, 404.
    problems = []
    sm = rt(os.path.join(dist, "sitemap.xml")) if os.path.isfile(os.path.join(dist, "sitemap.xml")) else ""
    locs = re.findall(r"<loc>([^<]*)</loc>", sm)
    mods = set(re.findall(r"<lastmod>([^<]*)</lastmod>", sm))
    if sorted(locs) != sorted(ORIGIN + p for p in PAGES):
        problems.append("sitemap has %d of the 8 pages" % len([l for l in locs if l[len(ORIGIN):] in PAGES]))
    bd = args.build_date
    if not bd and "/security-policy/" in texts:
        m = re.search(r"Last updated (\d{4}-\d{2}-\d{2})\.", texts["/security-policy/"])
        bd = m.group(1) if m else None
    if len(mods) != 1 or (bd and mods != {bd}):
        problems.append("lastmod %s, build date %s" % (sorted(mods), bd))
    rob = rb(os.path.join(dist, "robots.txt")) if os.path.isfile(os.path.join(dist, "robots.txt")) else b""
    if rob.decode("utf-8", "replace") != ROBOTS_EXPECTED:
        problems.append("robots.txt differs from COPY 9.2")
    if copy_text:
        m = re.search(r"### 9\.2 .*?\n```\n(.*?)```", copy_text, re.S)
        if not m or m.group(1) != ROBOTS_EXPECTED:
            problems.append("COPY 9.2 robots block differs from the checker's copy")
    if "/404.html" not in pages:
        problems.append("404.html missing")
    gate("G14", "FAIL" if problems else "PASS", "; ".join(problems) if problems else
         "sitemap.xml: the 8 pages, lastmod %s; robots.txt = COPY 9.2; 404.html present" % bd)

    # G15 - the file allowlist.
    litter = [f for f in files if re.search(r"(^|/)(\.DS_Store|__MACOSX|\._|\.smbdelete)", f)]
    extra = sorted(set(files) - set(ALLOWLIST))
    lacking = sorted(set(ALLOWLIST) - set(files))
    ok = not (litter or extra or lacking)
    gate("G15", "PASS" if ok else "FAIL", "%d files = the %d-file allowlist exactly" % (len(files), len(ALLOWLIST))
         if ok else "extra: %s; missing: %s; litter: %s" % (extra or "-", lacking or "-", litter or "-"))

    # G16 - the zip.
    if not args.zip:
        gate("G16", "SKIP", "no --zip")
    else:
        g16(args, dist, tmp, sp_url)

    # G18 - HTML parses; containers balance.
    problems = []
    for p, t in pages.items():
        tc = TagCounter()
        try:
            tc.feed(t)
            tc.close()
        except Exception as e:  # html.parser rarely raises; any raise is a FAIL
            problems.append("%s: %s" % (p, e))
            continue
        for tg in ("section", "div", "table", "details", "ul", "main", "nav", "footer"):
            if tc.opens.get(tg, 0) != tc.closes.get(tg, 0):
                problems.append("%s: <%s> %d open, %d closed" % (p, tg, tc.opens.get(tg, 0), tc.closes.get(tg, 0)))
    gate("G18", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "%d pages parse; section/div/table/details/ul/main/nav/footer balanced" % len(pages))
    tidy = shutil.which("tidy")
    if tidy:
        noisy = []
        for f in html_files:
            r = subprocess.run([tidy, "-q", "-e", "-utf8", os.path.join(dist, f)], capture_output=True, text=True)
            errs = [l for l in r.stderr.splitlines() if "Error:" in l]
            if errs:
                noisy.append("%s (%d)" % (f, len(errs)))
        ver = subprocess.run([tidy, "-v"], capture_output=True, text=True).stdout.strip().splitlines()
        ver = ver[0] if ver else tidy
        gate("G18", "INFO", "%s reports errors in: %s (a pre-HTML5 tidy flags nav/main/details itself)"
             % (ver, ", ".join(noisy)) if noisy else "%s: warnings only" % ver)

    g19_g21(args, tmp)

    # G22 - the sample report.
    if "/sample-report/" not in texts:
        gate("G22", "FAIL", "/sample-report/ not built")
    else:
        t = texts["/sample-report/"]
        doms = set(re.findall(r"(?<![\w.@-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", t))
        problems = sorted(doms - {"alderfinch.example", "theclauditor.ai"})
        n_fic, n_sam, n_par = t.lower().count("fictional"), t.count("SAMPLE"), t.count("(sample)")
        ok = not problems and n_fic >= 2 and n_sam >= 2 and n_par >= 4
        gate("G22", "PASS" if ok else "FAIL", "domains %s; fictional x%d; SAMPLE x%d; (sample) x%d%s"
             % (sorted(doms), n_fic, n_sam, n_par, (" — other domains: %s" % problems) if problems else ""))

    g24(css)
    if missing_pages:
        gate("INFO", "INFO", "pages not in this build: " + ", ".join(missing_pages))


def g16(args, dist, tmp, sp_url):
    problems = []
    r = subprocess.run(["unzip", "-tq", args.zip], capture_output=True, text=True)
    if r.returncode != 0:
        problems.append("unzip -t: " + (r.stdout + r.stderr).strip()[:120])
    with zipfile.ZipFile(args.zip) as z:
        names = z.namelist()
        entries = sorted(n for n in names if not n.endswith("/"))
        dirs = sorted(n for n in names if n.endswith("/"))
        if any(n.startswith("/") or ".." in n.split("/") for n in names):
            problems.append("entries are not root-relative")
        if ".well-known/security.txt" not in entries:
            problems.append(".well-known/ missing from the zip")
        if entries != ALLOWLIST:
            problems.append("entries != allowlist (extra %s, missing %s)"
                            % (sorted(set(entries) - set(ALLOWLIST)), sorted(set(ALLOWLIST) - set(entries))))
        compare_to, what = dist, "the checked build"
        if args.src:
            sm = z.read("sitemap.xml").decode("utf-8") if "sitemap.xml" in entries else ""
            m = re.search(r"<lastmod>(\d{4}-\d{2}-\d{2})</lastmod>", sm)
            fresh = os.path.join(tmp, "fresh")
            cmd = [sys.executable, "-B", os.path.join(TOOLS, "build.py"), "--src", args.src, "--dest", fresh,
                   "--build-date", m.group(1) if m else "0000-00-00"]
            if sp_url:
                cmd += ["--securityplus-url", sp_url]
            b = subprocess.run(cmd, capture_output=True, text=True)
            if b.returncode != 0:
                problems.append("fresh build failed: " + b.stderr.strip()[-160:])
            compare_to, what = fresh, "a fresh build of --src"
        for n in entries:
            fp = os.path.join(compare_to, n)
            if not os.path.isfile(fp) or rb(fp) != z.read(n):
                problems.append("%s differs from %s" % (n, what))
    gate("G16", "FAIL" if problems else "PASS", "; ".join(problems[:6]) if problems else
         "unzip -t OK; %d files (byte-equal to %s) + %d directory entries, root-relative; .well-known/ inside"
         % (len(entries), what, len(dirs)))


def g19_g21(args, tmp):
    secret = os.path.join(TOOLS, "secret_scan.py")
    export = os.path.join(TOOLS, "export_repo.sh")
    listing = os.path.join(TOOLS, "REPO-FILES.txt")
    wf = os.path.join(BASE, "repo", ".github", "workflows", "site-check.yml")
    if not os.path.isfile(wf):
        wf = os.path.join(BASE, ".github", "workflows", "site-check.yml")
    if not args.src:
        for g in ("G19", "G20", "G21"):
            gate(g, "SKIP", "no --src (repository checks run beside the source only)")
        return
    tree = os.path.join(tmp, "export")
    if os.path.isfile(export) and os.path.isfile(listing):
        r = subprocess.run(["bash", export, "--dry-run", "--dest", tree], capture_output=True, text=True)
        want = set()
        for line in rt(listing).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                want.add(line[len("repo/"):] if line.startswith("repo/") else line)
        got = set(list_files(tree)) if os.path.isdir(tree) else set()
        bad = [f for f in got if re.search(r"(^|/)(out/|COPY-|SECURITYPLUS-URL|PRIVATE-DENYLIST|GITHUB-AND-DEPLOY|summary-)", f)]
        ok = r.returncode == 0 and got == want and not bad
        gate("G20", "PASS" if ok else "FAIL", "export --dry-run: %d files == REPO-FILES.txt" % len(got) if ok else
             "export rc=%d; extra %s; missing %s; forbidden %s" % (r.returncode, sorted(got - want)[:5],
                                                                  sorted(want - got)[:5], bad))
    else:
        gate("G20", "SKIP", "tools/export_repo.sh or tools/REPO-FILES.txt not written yet (Leg 2)")
    if os.path.isfile(secret) and os.path.isdir(tree):
        scratch = os.path.join(tmp, "scratch")
        os.makedirs(scratch)
        with open(os.path.join(scratch, "trip.txt"), "w") as fh:
            fh.write("gh" + "p_" + "A" * 24 + "\nAK" + "IA" + "B" * 16 + "\npass" + "word = x\n")
        deny = [a for f in PRIVATE_LISTS[:1] if os.path.isfile(f) for a in ("--deny-file", f, "--require-private")]
        trip = subprocess.run([sys.executable, "-B", secret, scratch], capture_output=True, text=True)
        clean = subprocess.run([sys.executable, "-B", secret, tree] + deny, capture_output=True, text=True)
        ok = trip.returncode != 0 and clean.returncode == 0
        gate("G19", "PASS" if ok else "FAIL", "secret_scan trips on the scratch file (rc=%d) and finds 0 hits in the export (rc=%d, private list %s)%s"
             % (trip.returncode, clean.returncode, "loaded" if deny else "absent",
                "" if ok else ": " + clean.stdout.strip()[:160]))
    else:
        gate("G19", "SKIP", "tools/secret_scan.py or the export tree not present yet (Leg 2)")
    if not os.path.isfile(wf):
        gate("G21", "SKIP", "workflow file not written yet (Leg 2)")
        return
    y = rt(wf)
    problems = []
    uses = re.findall(r"uses:\s*([\w.-]+/[\w.-]+)@(\S+)", y)
    if not uses:
        problems.append("no uses: lines")
    for repo, ref in uses:
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            problems.append("%s not pinned to a SHA" % repo)
            continue
        try:
            req = urllib.request.Request("https://api.github.com/repos/%s/commits/%s" % (repo, ref),
                                         headers={"User-Agent": "check_site"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                json.load(resp)
        except Exception as e:
            problems.append("%s@%s does not resolve (%s)" % (repo, ref[:7], e))
    perms = re.findall(r"^\s*permissions:\s*(.*)$", y, re.M)
    if not perms or not re.search(r"permissions:\s*\n\s+contents:\s*read\s*\n(?!\s+\w+:\s*(read|write))", y):
        problems.append("permissions is not contents: read alone")
    if "secrets." in y:
        problems.append("uses secrets.")
    if "0 15 * * 1" not in y:
        problems.append("schedule line missing")
    if "60 days" not in y:
        problems.append("60-day comment missing")
    # the public build must carry the same Security+ link as the deployed build
    wf_sp = set(u.strip("'\"") for u in re.findall(r"--securityplus-url\s+(\S+)", y))
    file_url = sp_file_url(args)
    if len(wf_sp) > 1:
        problems.append("the workflow's --securityplus-url values differ")
    elif file_url and wf_sp != {file_url}:
        problems.append("the workflow's Security+ link is not SECURITYPLUS-URL.txt's")
    gate("G21", "FAIL" if problems else "PASS", "; ".join(problems) if problems else
         "%d uses: pinned to resolving SHAs; contents: read only; no secrets.; schedule + 60-day comment; "
         "Security+ link %s" % (len(uses), "= SECURITYPLUS-URL.txt" if file_url else
                                ("set" if wf_sp else "not set")))


def g24(css):
    problems = []
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    pats = [("light", r":root\s*\{([^}]*)\}", LIGHT, "light dark"),
            ("dark (device)", r"@media\s*\(prefers-color-scheme:\s*dark\)\s*\{\s*:root:not\(\[data-theme=\"light\"\]\)\s*\{([^}]*)\}\s*\}", DARK, "dark"),
            ("dark (chosen)", r":root\[data-theme=\"dark\"\]\s*\{([^}]*)\}", DARK, "dark"),
            ("light (chosen)", r":root\[data-theme=\"light\"\]\s*\{([^}]*)\}", LIGHT, "light")]
    last, spans, parsed = -1, [], {}
    for name, pat, want, scheme in pats:
        m = re.search(pat, body)
        if not m:
            problems.append("token block missing: " + name)
            continue
        if m.start() < last:
            problems.append("token block out of order: " + name)
        last = m.start()
        spans.append((m.start(), m.end()))
        decl = dict((k.strip(), v.strip()) for k, _, v in
                    (d.partition(":") for d in m.group(1).split(";") if d.strip()))
        parsed[name] = decl
        for tok in TOKENS:
            if decl.get(tok, "").upper() != want[tok].upper():
                problems.append("%s: %s = %s, want %s" % (name, tok, decl.get(tok), want[tok]))
        if decl.get("color-scheme") != scheme:
            problems.append("%s: color-scheme %r" % (name, decl.get("color-scheme")))
    worst = []
    for theme, block, ref in (("light", "light", LIGHT), ("dark", "dark (chosen)", DARK)):
        # contrast is measured on the colors the stylesheet actually carries
        got = parsed.get(block, {})
        t = dict((k, got[k] if re.fullmatch(r"#[0-9A-Fa-f]{6}", got.get(k, "")) else ref[k]) for k in TOKENS)
        for fg in ("--fg", "--muted", "--accent", "--link"):
            for bg in ("--bg", "--surface", "--raise"):
                c = contrast(t[fg], t[bg])
                worst.append((c, theme, fg, bg))
                if c < 4.5:
                    problems.append("%s %s on %s = %.2f" % (theme, fg, bg, c))
        c = contrast("#0A0B0C", t["--accent-fill"])
        worst.append((c, theme, "#0A0B0C", "--accent-fill"))
        if c < 4.5:
            problems.append("%s #0A0B0C on --accent-fill = %.2f" % (theme, c))
    for s in DROPPED:
        if s in css:
            problems.append("dropped item present: " + s)
    if css.count("!important") != 1 or not re.search(r"\[hidden\]\s*\{\s*display:\s*none\s*!important\s*\}", css):
        problems.append("!important x%d (want once, on [hidden])" % css.count("!important"))
    outside = body
    for a, b in reversed(spans):
        outside = outside[:a] + outside[b:]
    hexes = sorted(set(h.upper() for h in re.findall(r"#[0-9A-Fa-f]{3,8}\b", outside)) - {"#0A0B0C"})
    if hexes or re.search(r"\b(rgba?|hsla?|oklch|color-mix)\(", outside):
        problems.append("raw colors outside the token blocks: %s" % hexes)
    if re.search(r"box-shadow|animation|@keyframes", body):
        problems.append("box-shadow/animation present")
    for v in re.findall(r"transition:\s*([^;}]*)", body):
        for part in v.split(","):
            bits = part.split()
            if len(bits) < 2 or bits[0] not in ("color", "background-color") or bits[1] not in ("150ms", ".15s", "0.15s"):
                problems.append("transition %r" % part.strip())
    w = min(worst)
    gate("G24", "FAIL" if problems else "PASS", "; ".join(problems[:8]) if problems else
         "4 token blocks in order with the A7 values and color-scheme; lowest contrast %.2f (%s %s on %s); no dropped item; one !important; no raw color outside the tokens"
         % w)


if __name__ == "__main__":
    main()
