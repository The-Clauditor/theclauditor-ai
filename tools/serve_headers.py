#!/usr/bin/env python3
"""serve_headers.py - serve a built site on 127.0.0.1 the way Cloudflare Pages will.

  python3 -B tools/serve_headers.py --root dist [--port 8787]

- Every response carries every header of the /* block of <root>/_headers
  ("! Name" lines remove a header on Pages; here they are simply not sent).
- A folder is answered with its index.html; a folder asked for without its slash is
  forwarded to the slash with a 308, as Pages does.
- An unknown path is answered with 404.html and status 404.
- _headers and Finder/SMB litter are never served.
Binds 127.0.0.1 only. Python 3.9+ standard library only. Stop it with Ctrl-C or kill.
"""
import argparse
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".xml": "application/xml",
    ".txt": "text/plain; charset=utf-8",
    ".woff2": "font/woff2",
    ".webp": "image/webp",
    ".jpg": "image/jpeg",
    ".png": "image/png",
}


def litter(name):
    return name == ".DS_Store" or name.startswith("._") or name.startswith(".smbdelete")


def read_headers(root):
    out, in_block = [], False
    with open(os.path.join(root, "_headers"), encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            if not line.strip():
                continue
            if not line[0].isspace():
                in_block = line.strip() == "/*"
                continue
            if in_block and not line.strip().startswith("!"):
                name, _, value = line.strip().partition(":")
                out.append((name.strip(), value.strip()))
    if not out:
        raise SystemExit("serve_headers: _headers has no /* block")
    return out


def make_handler(root, headers):
    class Handler(BaseHTTPRequestHandler):
        def version_string(self):
            return "clauditor-local"  # console_check.sh checks it to know this server answered

        def resolve(self, path):
            rel = unquote(path).lstrip("/")
            target = os.path.realpath(os.path.join(root, rel))
            if target != root and not target.startswith(root + os.sep):
                return None
            if os.path.isdir(target):
                if not path.endswith("/"):
                    return ("forward", path + "/")
                target = os.path.join(target, "index.html")
            if not os.path.isfile(target):
                return None
            name = os.path.relpath(target, root).replace(os.sep, "/")
            if name == "_headers" or any(litter(p) for p in name.split("/")):
                return None
            return target

        def send_file(self, target, status, head_only):
            with open(target, "rb") as fh:
                body = fh.read()
            ext = os.path.splitext(target)[1].lower()
            self.send_response(status)
            self.send_header("Content-Type", TYPES.get(ext, "application/octet-stream"))
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def handle_any(self, head_only):
            parts = urlsplit(self.path)
            found = self.resolve(parts.path)
            if isinstance(found, tuple):
                self.send_response(308)
                self.send_header("Location", found[1] + ("?" + parts.query if parts.query else ""))
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif found is None:
                self.send_file(os.path.join(root, "404.html"), 404, head_only)
            else:
                self.send_file(found, 200, head_only)

        def do_GET(self):
            self.handle_any(False)

        def do_HEAD(self):
            self.handle_any(True)

        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Serve a built site with its _headers.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    root = os.path.realpath(args.root)
    if not os.path.isfile(os.path.join(root, "404.html")):
        raise SystemExit("serve_headers: no 404.html in " + root)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(root, read_headers(root)))
    print("serve_headers: %s at http://127.0.0.1:%d" % (root, args.port), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
