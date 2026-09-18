#!/usr/bin/env python3
"""End-to-end through Prowlarr: the indexer test, a search, and a grab.

    python3 scripts/test_indexer.py [--query matrix] [--grab]

Needs PROWLARR_API_KEY, or a config/config.xml from the compose stack.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROWLARR = os.environ.get("PROWLARR_URL", "http://localhost:9696").rstrip("/")
CANONICAL = "rutracker.org"


def api_key() -> str:
    key = os.environ.get("PROWLARR_API_KEY")
    if key:
        return key
    config = os.path.join(ROOT, "config", "config.xml")
    if not os.path.exists(config):
        sys.exit(f"No API key: set PROWLARR_API_KEY or start the stack ({config} missing).")
    return ET.parse(config).getroot().find("ApiKey").text.strip()


KEY = api_key()


def api(path: str, method: str = "GET", body: object = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{PROWLARR}{path}", data=data, method=method)
    request.add_header("X-Api-Key", KEY)
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            raw = response.read().decode()
        return response.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw[:600]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default="matrix")
    parser.add_argument("--grab", action="store_true", help="also grab the first result")
    args = parser.parse_args()

    _, indexers = api("/api/v1/indexer")
    indexer = next(
        (i for i in (indexers or []) if (i.get("implementation") or "").lower() == "rutracker"), None
    )
    if not indexer:
        sys.exit("No RuTracker indexer in Prowlarr. Add it, then run scripts/configure_proxy.py.")
    print(f"indexer {indexer['name']!r} (id {indexer['id']}), tags {indexer.get('tags')}")

    if not indexer.get("tags"):
        print("  warning: no tags, so no indexer proxy applies - run scripts/configure_proxy.py")

    print("\ntest")
    status, detail = api(f"/api/v1/indexer/{indexer['id']}/test", "POST", indexer)
    if status >= 400:
        print(f"  FAIL  HTTP {status}: {detail}")
        return 1
    print("  ok    indexer test passed")

    print(f"\nsearch {args.query!r}")
    query = urllib.parse.urlencode({"query": args.query, "indexerIds": indexer["id"], "limit": 20})
    status, results = api(f"/api/v1/search?{query}")
    if status >= 400:
        print(f"  FAIL  HTTP {status}: {results}")
        return 1

    results = results or []
    print(f"  ok    {len(results)} result(s)")
    if not results:
        return 1

    foreign = [r for r in results if CANONICAL not in (r.get("infoUrl") or "")]
    if foreign:
        print(f"  FAIL  {len(foreign)} result(s) do not point at {CANONICAL}")
        print(f"        e.g. {foreign[0].get('infoUrl')}")
        return 1
    print(f"  ok    every result points at {CANONICAL}")

    for row in results[:5]:
        size = (row.get("size") or 0) / 1024 ** 3
        print(f"    {row.get('seeders'):>4}S {size:6.2f}G  {(row.get('title') or '')[:78]}")

    if args.grab:
        first = results[0]
        print(f"\ngrab {first.get('title', '')[:60]!r}")
        status, detail = api(
            "/api/v1/search",
            "POST",
            {"guid": first.get("guid"), "indexerId": indexer["id"]},
        )
        if status >= 400:
            print(f"  FAIL  HTTP {status}: {detail}")
            return 1
        print("  ok    grabbed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
