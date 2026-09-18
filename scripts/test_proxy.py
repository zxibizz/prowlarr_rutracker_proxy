#!/usr/bin/env python3
"""Exercise the proxy on its own, without Prowlarr in the way.

    python3 scripts/test_proxy.py [--base http://localhost:8790] [--query matrix]

Checks, in order:
  1. the local endpoints answer
  2. the tracker is served in origin form and the session is logged in
  3. a search returns rows
  4. the first row's download link is a real torrent
  5. no foreign mirror hostname leaks into the page
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

LOGGED_IN = b'id="logged-in-username"'
ROW_RE = re.compile(rb'<a[^>]+class="[^"]*tr-dl[^"]*"[^>]+href="([^"]+)"', re.I)
ALT_ROW_RE = re.compile(rb'href="(dl\.php\?t=\d+)"', re.I)

PASSED = 0
FAILED = 0


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  ok    {name}" + (f" - {detail}" if detail else ""))
    else:
        FAILED += 1
        print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))
    return ok


def fetch(url: str, timeout: float = 180.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:8790")
    parser.add_argument("--query", default="matrix")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    print("local endpoints")
    status, body, _ = fetch(f"{base}/healthz", timeout=10)
    check("/healthz", status == 200 and json.loads(body).get("ok") is True)

    status, body, _ = fetch(f"{base}/status", timeout=30)
    state = json.loads(body) if status == 200 else {}
    check("/status", status == 200, json.dumps(state.get("upstream", {}), ensure_ascii=False))

    print("\nthe tracker, in origin form")
    status, body, _ = fetch(f"{base}/forum/index.php")
    if not check(
        "index.php returns content",
        status == 200 and len(body) > 1000,
        f"HTTP {status}, {len(body)} bytes",
    ):
        return report()
    check("session is logged in", LOGGED_IN in body)

    print("\nsearch")
    query = urllib.parse.quote(args.query)
    status, body, _ = fetch(f"{base}/forum/tracker.php?nm={query}")
    check("tracker.php answers", status == 200, f"HTTP {status}, {len(body)} bytes")
    check("results table is present", b"tor-tbl" in body)
    check("no foreign mirror hostname leaked", b"rutracker.net" not in body)

    links = ROW_RE.findall(body) or ALT_ROW_RE.findall(body)
    if not check("at least one download link", bool(links), f"{len(links)} found"):
        return report()

    href = links[0].decode("ascii", "replace").replace("&amp;", "&")
    url = href if href.startswith("http") else f"{base}/forum/{href.lstrip('/')}"
    print(f"\ndownload ({url})")
    status, blob, headers = fetch(url)
    check(
        "the link yields a torrent",
        status == 200 and blob.startswith(b"d8:announce"),
        f"HTTP {status}, {len(blob)} bytes, {headers.get('Content-Type')}",
    )

    return report()


def report() -> int:
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
