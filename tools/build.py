#!/usr/bin/env python3
"""build.py - assemble theclauditor.ai from src/ into a fresh folder.

  python3 -B tools/build.py --src src --dest dist --build-date YYYY-MM-DD [--securityplus-url URL] [--copy FILE]

Each src/pages/*.html starts with a <!--PAGE ... --> header (title, description, path,
body_class; og_title and og_description optional). The page body is wrapped in
src/partials/{head,nav,footer,tail}.html, src/static/ is copied verbatim, and sitemap.xml
is written from the page list. Every replacement is asserted by exact count; any failure
exits non-zero and leaves no claim of success. --copy names the copy of record: if it is
given, the build stops while it carries an open marker or lacks RESOLVED.
Python 3.9+ standard library only.
"""
import argparse
import datetime
import os
import re
import shutil
import sys

ORIGIN = "https://theclauditor.ai"
NAV = [("/services/", "Services"), ("/how-we-work/", "How we work"),
       ("/sample-report/", "Sample report"), ("/proof/", "Proof"), ("/about/", "About")]
SITEMAP = ["/", "/services/", "/how-we-work/", "/sample-report/", "/about/", "/proof/",
           "/security-policy/", "/contact/"]
PARTIAL_TOKENS = {
    "head.html": {"{{TITLE}}": 1, "{{DESCRIPTION}}": 1, "{{PATH}}": 2, "{{OG_TITLE}}": 1,
                  "{{OG_DESCRIPTION}}": 1, "{{BODY_CLASS}}": 1},
    "nav.html": {"{{NAV_LINKS}}": 2},
    "footer.html": {},
    "tail.html": {},
}
MARKER_RE = re.compile(r"\[(CONFIRM|B-SLOT|B-RULES|B-SUPPLIES)-[0-9]")
HEADER_RE = re.compile(r"\A<!--PAGE\n(.*?)\n-->\n", re.S)
SP_RE = re.compile(r"<!--SP:WITH-->(.*?)<!--/SP:WITH--><!--SP:WITHOUT-->(.*?)<!--/SP:WITHOUT-->", re.S)
LITTER = (".DS_Store", "__MACOSX")


def die(msg):
    sys.stderr.write("build: FAIL - " + msg + "\n")
    sys.exit(1)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def litter(name):
    return name in LITTER or name.startswith("._") or name.startswith(".smbdelete")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def nav_links(current):
    rows = []
    for href, label in NAV:
        cur = ' aria-current="page"' if href == current else ""
        rows.append('      <li><a href="%s"%s>%s</a></li>' % (href, cur, label))
    return "\n".join(rows)


def parse_page(path):
    text = read(path)
    m = HEADER_RE.match(text)
    if not m:
        die("%s: no <!--PAGE ... --> header on its first lines" % path)
    meta = {}
    for line in m.group(1).splitlines():
        key, sep, value = line.partition(":")
        if not sep or not value.strip():
            die("%s: bad header line %r" % (path, line))
        meta[key.strip()] = value.strip()
    for key in ("title", "description", "path", "body_class"):
        if key not in meta:
            die("%s: header lacks %s" % (path, key))
    meta.setdefault("og_title", meta["title"])
    meta.setdefault("og_description", meta["description"])
    return meta, text[m.end():]


def resolve_sp(body, url, name):
    pairs = len(SP_RE.findall(body))
    if body.count("<!--SP:") != 2 * pairs or body.count("<!--/SP:") != 2 * pairs:
        die("%s: unbalanced SP:WITH / SP:WITHOUT markers" % name)
    body = SP_RE.sub(lambda m: m.group(1) if url else m.group(2), body)
    if url:
        body = body.replace("{{SECURITYPLUS_URL}}", esc(url))
    return body


def main():
    ap = argparse.ArgumentParser(description="Assemble theclauditor.ai from src/.")
    ap.add_argument("--src", required=True)
    ap.add_argument("--dest", required=True)
    ap.add_argument("--build-date", required=True, dest="build_date")
    ap.add_argument("--securityplus-url", dest="sp_url", default="")
    ap.add_argument("--copy", dest="copy", default="")
    args = ap.parse_args()

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.build_date):
        die("--build-date must be YYYY-MM-DD")
    datetime.date.fromisoformat(args.build_date)
    url = args.sp_url.strip()
    if url and not re.fullmatch(r"https://[A-Za-z0-9.-]+/[^\s\"<>]*", url):
        die("--securityplus-url must be a plain https:// URL")
    if args.copy:
        copy = read(args.copy)
        if MARKER_RE.search(copy):
            die("the copy of record carries an open marker; no page is built")
        if "RESOLVED" not in "".join(copy.splitlines(True)[:12]):
            die("the copy of record's status line does not say RESOLVED")

    src, dest = os.path.abspath(args.src), os.path.abspath(args.dest)
    if os.path.exists(dest) and os.listdir(dest):
        die("--dest exists and is not empty: " + dest)
    partials = {}
    for name, tokens in PARTIAL_TOKENS.items():
        text = read(os.path.join(src, "partials", name))
        for tok, want in tokens.items():
            if text.count(tok) != want:
                die("partials/%s: %s found %d times, want %d" % (name, tok, text.count(tok), want))
        partials[name] = text

    # Static files, verbatim.
    static = os.path.join(src, "static")
    for root, dirs, files in os.walk(static):
        dirs[:] = sorted(d for d in dirs if not litter(d))
        for f in sorted(files):
            if litter(f):
                continue
            rel = os.path.relpath(os.path.join(root, f), static)
            os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(root, f), os.path.join(dest, rel))

    built = []
    pages_dir = os.path.join(src, "pages")
    for name in sorted(os.listdir(pages_dir)):
        if not name.endswith(".html") or litter(name):
            continue
        meta, body = parse_page(os.path.join(pages_dir, name))
        path = meta["path"]
        if path in [b for b in built]:
            die("%s: path %s is used twice" % (name, path))
        if MARKER_RE.search(body):
            die("%s: open marker in the page source" % name)
        body = resolve_sp(body, url, name).replace("{{BUILD_DATE}}", args.build_date)
        head = partials["head.html"]
        for tok, key in (("{{TITLE}}", "title"), ("{{DESCRIPTION}}", "description"),
                         ("{{OG_TITLE}}", "og_title"), ("{{OG_DESCRIPTION}}", "og_description"),
                         ("{{BODY_CLASS}}", "body_class")):
            head = head.replace(tok, esc(meta[key]))
        head = head.replace("{{PATH}}", esc(path))
        nav = partials["nav.html"].replace("{{NAV_LINKS}}", nav_links(path))
        html = head + nav + body + partials["footer.html"] + partials["tail.html"]
        for bad in ("{{", "}}", "<!--SP:", "<!--/SP:", "<!--PAGE"):
            if bad in html:
                die("%s: %s left in the built page" % (name, bad))
        if html.count('<main id="main">') != 1:
            die("%s: want exactly one <main id=\"main\">" % name)
        if path == "/404.html":
            out = os.path.join(dest, "404.html")
        elif path.startswith("/") and path.endswith("/"):
            out = os.path.join(dest, path.strip("/"), "index.html")
        else:
            die("%s: path must be /404.html or end with /" % name)
        write(out, html)
        built.append(path)

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for p in SITEMAP:
        if p in built:
            lines.append("  <url><loc>%s%s</loc><lastmod>%s</lastmod></url>" % (ORIGIN, p, args.build_date))
        else:
            sys.stderr.write("build: note - no page for %s yet; left out of sitemap.xml\n" % p)
    lines.append("</urlset>")
    write(os.path.join(dest, "sitemap.xml"), "\n".join(lines) + "\n")
    extra = [p for p in built if p not in SITEMAP and p != "/404.html"]
    if extra:
        die("pages outside the sitemap list: " + ", ".join(extra))
    print("build: OK - %d pages, Security+ link %s, build date %s -> %s"
          % (len(built), "set" if url else "not set", args.build_date, dest))


if __name__ == "__main__":
    main()
