#!/usr/bin/env python3
"""Point Prowlarr's RuTracker indexer at this proxy by setting its Base Url.

    python3 scripts/configure_proxy.py                      # http://rutracker-proxy:8790/
    python3 scripts/configure_proxy.py http://box.lan:8790  # proxy elsewhere
    python3 scripts/configure_proxy.py --remove             # back to https://rutracker.org/

Prowlarr renders Base Url as a dropdown of the URLs compiled into its C# indexer,
but that is a UI constraint only: ``IndexerFactory`` never validates the stored
value, so the API accepts any address.

The trailing slash is not optional. Prowlarr builds every link by concatenating
``BaseUrl + "forum/" + href``, so without it you get ``...8790forum/``.

Also clears the tag and Http indexer proxy that older, MITM-based versions of
this project created, if they are still there.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROWLARR = os.environ.get("PROWLARR_URL", "http://localhost:9696").rstrip("/")
LEGACY_NAME = "rutracker-proxy"
DEFAULT_BASE_URL = "http://rutracker-proxy:8790/"
UPSTREAM_BASE_URL = "https://rutracker.org/"


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
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read().decode()
        return response.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw[:400]


def find_tag():
    _, tags = api("/api/v1/tag")
    return next((t for t in (tags or []) if t.get("label") == LEGACY_NAME), None)


def find_proxy():
    _, proxies = api("/api/v1/indexerproxy")
    return next((p for p in (proxies or []) if p.get("name") == LEGACY_NAME), None)


def find_indexer():
    _, indexers = api("/api/v1/indexer")
    for indexer in indexers or []:
        if (indexer.get("implementation") or "").lower() == "rutracker":
            return indexer
    return None


def set_field(payload: dict, name: str, value) -> None:
    for field in payload.get("fields", []):
        if field.get("name") == name:
            field["value"] = value
            return
    payload.setdefault("fields", []).append({"name": name, "value": value})


def get_field(payload: dict, name: str):
    for field in payload.get("fields", []):
        if field.get("name") == name:
            return field.get("value")
    return None


def drop_legacy_wiring() -> None:
    """Undo the tag + Http indexer proxy that the MITM-based version needed."""
    indexer = find_indexer()
    tag = find_tag()
    if indexer and tag and tag["id"] in (indexer.get("tags") or []):
        indexer["tags"] = [t for t in indexer["tags"] if t != tag["id"]]
        api(f"/api/v1/indexer/{indexer['id']}?forceSave=true", "PUT", indexer)
        print("removed the legacy tag from the RuTracker indexer")

    proxy = find_proxy()
    if proxy:
        api(f"/api/v1/indexerproxy/{proxy['id']}", "DELETE")
        print(f"deleted legacy indexer proxy {proxy['id']}")

    if tag:
        api(f"/api/v1/tag/{tag['id']}", "DELETE")
        print(f"deleted legacy tag {tag['id']}")


def normalise(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return url if url.endswith("/") else url + "/"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    removing = "--remove" in sys.argv
    base_url = UPSTREAM_BASE_URL if removing else normalise(args[0] if args else DEFAULT_BASE_URL)

    drop_legacy_wiring()

    indexer = find_indexer()
    if not indexer:
        print("\nNo RuTracker indexer found. Add it in Prowlarr, then re-run this script.")
        print("Leave its username/password blank: this proxy owns the tracker session.")
        return 1

    before = get_field(indexer, "baseUrl")
    set_field(indexer, "baseUrl", base_url)
    status, saved = api(f"/api/v1/indexer/{indexer['id']}?forceSave=true", "PUT", indexer)
    if status >= 400:
        sys.exit(f"could not set the Base Url: HTTP {status}: {saved}")

    print(f"indexer {indexer['name']!r} (id {indexer['id']}) base url: {before} -> {base_url}")
    if removing:
        print("\nNote: RuTracker is now reached directly, which is what this proxy existed to avoid.")
        return 0

    print("\nNext, test it:")
    print(f"  python3 scripts/test_indexer.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
