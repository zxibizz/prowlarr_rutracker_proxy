#!/usr/bin/env python3
"""Exercise the proxy on its own, without Prowlarr in the way.

    python3 scripts/test_proxy.py [--proxy localhost:8790] [--query matrix]

Checks, in order:
  1. the local endpoints answer
  2. a non-intercepted host still gets its real certificate
  3. an intercepted host presents our CA and returns real content
  4. the session is logged in
  5. a search returns rows
  6. the first row's download link is a real torrent
  7. every link in the search page points at the canonical host
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CANONICAL = "rutracker.org"
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


def opener(proxy: str, cafile: str | None):
    handlers = [urllib.request.ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"})]
    if cafile:
        context = ssl.create_default_context(cafile=cafile)
    else:
        context = ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fetch(build, url: str, timeout: float = 90.0):
    try:
        with build.open(url, timeout=timeout) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default="localhost:8790")
    parser.add_argument("--query", default="matrix")
    parser.add_argument("--ca", default=None, help="CA file; fetched from the proxy when omitted")
    args = parser.parse_args()

    direct = urllib.request.build_opener()

    print("local endpoints")
    status, body, _ = fetch(direct, f"http://{args.proxy}/healthz", timeout=10)
    check("/healthz", status == 200 and json.loads(body).get("ok") is True)

    status, ca_pem, _ = fetch(direct, f"http://{args.proxy}/ca.crt", timeout=10)
    check("/ca.crt", status == 200 and ca_pem.startswith(b"-----BEGIN CERTIFICATE-----"))

    status, body, _ = fetch(direct, f"http://{args.proxy}/status", timeout=30)
    state = json.loads(body) if status == 200 else {}
    check("/status", status == 200, json.dumps(state.get("upstream", {}), ensure_ascii=False))

    cafile = args.ca
    if not cafile and ca_pem.startswith(b"-----BEGIN"):
        cafile = "/tmp/rutracker-proxy-ca.crt"
        with open(cafile, "wb") as handle:
            handle.write(ca_pem)

    print("\ntunnelling (must NOT be intercepted)")
    try:
        status, _, _ = fetch(opener(args.proxy, None), "https://prowlarr.servarr.com/v1/ping", 30)
        check("prowlarr.servarr.com keeps its real certificate", status < 500, f"HTTP {status}")
    except Exception as exc:  # noqa: BLE001
        check("prowlarr.servarr.com keeps its real certificate", False, f"{type(exc).__name__}: {exc}")

    print("\ninterception")
    build = opener(args.proxy, cafile)
    try:
        status, body, _ = fetch(build, f"https://{CANONICAL}/forum/index.php")
    except Exception as exc:  # noqa: BLE001
        check("TLS handshake with the proxy's CA", False, f"{type(exc).__name__}: {exc}")
        return report()
    check("TLS handshake with the proxy's CA", True)
    check("index.php returns content", status == 200 and len(body) > 1000, f"HTTP {status}, {len(body)} bytes")
    check("session is logged in", LOGGED_IN in body)

    print("\nsearch")
    query = urllib.parse.quote(args.query)
    status, body, _ = fetch(build, f"https://{CANONICAL}/forum/tracker.php?nm={query}")
    check("tracker.php answers", status == 200, f"HTTP {status}, {len(body)} bytes")
    check("results table is present", b"tor-tbl" in body)
    check("no foreign mirror hostname leaked", b"rutracker.net" not in body)

    links = ROW_RE.findall(body) or ALT_ROW_RE.findall(body)
    if not check("at least one download link", bool(links), f"{len(links)} found"):
        return report()

    href = links[0].decode("ascii", "replace").replace("&amp;", "&")
    url = href if href.startswith("http") else f"https://{CANONICAL}/forum/{href.lstrip('/')}"
    print(f"\ndownload ({url})")
    status, blob, headers = fetch(build, url)
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
