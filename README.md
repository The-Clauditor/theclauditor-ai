# theclauditor.ai

The source of [theclauditor.ai](https://theclauditor.ai/), the website of The Clauditor LLC — a small, defensive digital-security and digital-succession practice in California.

This repository exists so the site can be inspected, not just visited: the pages, the stylesheet, the fonts, the HTTP headers, and the scripts that build and check them are all here, and a public workflow re-checks the live site's headers, mail and DNS records on every change and on a schedule.

## What is here

- `src/pages/` — one file per page; `src/partials/` — the shared head, navigation and footer.
- `src/static/` — the assets (the stylesheet, the theme switch, the share image), the self-hosted fonts, `.well-known/` (security.txt, the PGP key, the MTA-STS policy), `_headers` (the security headers Cloudflare Pages serves) and `robots.txt`.
- `tools/` — `build.py` assembles the site into `dist/`; `check_site.py` enforces the rules (no inline styles or scripts, no third-party loads, root-absolute paths, every link resolves, a file allowlist); `scan_live.sh` reads the live site's headers, TLS, mail and DNS records; `serve_headers.py` and `console_check.sh` serve a build with its headers and read a headless browser's console for policy violations; `secret_scan.py` runs before anything is committed.
- `.github/workflows/site-check.yml` — the public check.

## What is not here

- The practice's assessment methodology — the engagement framework, the procedures, the forms and the report templates. It is private; a curated copy is available to a reviewer on request.
- Any client material. There is none in this repository and never will be.
- A deployment path. A change here deploys nothing. The site is published by hand, by its owner, from a build whose checks have passed, to Cloudflare Pages.

## Build and check

```
python3 -B tools/build.py --src src --dest dist --build-date YYYY-MM-DD
python3 -B tools/check_site.py --dist dist
bash tools/scan_live.sh --out scan.txt
```

Python 3.9+ standard library only; bash; curl, dig and openssl. No packages, no build chain.

## Reporting a security problem

See [SECURITY.md](SECURITY.md) and <https://theclauditor.ai/security-policy/>.

## Rights

The scripts, the stylesheet and the page templates are released under the MIT License ([LICENSE](LICENSE)). The prose, the images and the name The Clauditor are © 2026 The Clauditor LLC, all rights reserved ([LICENSE-CONTENT.md](LICENSE-CONTENT.md)). The fonts are under the SIL Open Font License; their license files sit beside them in `src/static/fonts/`.

Commits to this repository are signed. Maintained by Bryan John Kemler.

Not a law practice; nothing here is legal advice. The Clauditor is not affiliated with Anthropic.
