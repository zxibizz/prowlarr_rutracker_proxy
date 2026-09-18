#!/usr/bin/env python3
"""Wire the proxy into Prowlarr: a tag, an Http indexer proxy, and the RuTracker indexer.

This is what to do by hand in *Settings -> Indexer Proxies* (add an "Http" proxy
pointed at this service), plus a tag, plus that tag on the RuTracker indexer.

    python3 scripts/configure_proxy.py                      # rutracker-proxy:8790
    python3 scripts/configure_proxy.py myhost.local:8790    # proxy elsewhere
    python3 scripts/configure_proxy.py --remove             # undo

Prowlarr validates the address when it saves, so an unreachable host is rejected
with a clear error rather than silently breaking.
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
PROXY_NAME = "rutracker-proxy"
TAG_LABEL = "rutracker-proxy"
DEFAULT_ADDRESS = "rutracker-proxy:8790"
DEFAULT_PORT = 8790


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
    return next((t for t in (tags or []) if t.get("label") == TAG_LABEL), None)


def find_proxy():
    _, proxies = api("/api/v1/indexerproxy")
    return next((p for p in (proxies or []) if p.get("name") == PROXY_NAME), None)


def find_indexer():
    _, indexers = api("/api/v1/indexer")
    for indexer in indexers or []:
        if (indexer.get("implementation") or "").lower() == "rutracker":
            return indexer
    return None


def http_schema():
    _, schema = api("/api/v1/indexerproxy/schema")
    for candidate in schema or []:
        if (candidate.get("implementation") or "").lower() == "http":
            return candidate
    sys.exit("Prowlarr does not offer an 'Http' indexer proxy implementation.")


def set_field(payload: dict, name: str, value) -> None:
    for field in payload.get("fields", []):
        if field.get("name") == name:
            field["value"] = value
            return
    payload.setdefault("fields", []).append({"name": name, "value": value})


def remove() -> int:
    indexer = find_indexer()
    tag = find_tag()
    if indexer and tag and tag["id"] in (indexer.get("tags") or []):
        indexer["tags"] = [t for t in indexer["tags"] if t != tag["id"]]
        api(f"/api/v1/indexer/{indexer['id']}?forceSave=true", "PUT", indexer)
        print("removed the tag from the RuTracker indexer")

    proxy = find_proxy()
    if proxy:
        api(f"/api/v1/indexerproxy/{proxy['id']}", "DELETE")
        print(f"deleted indexer proxy {proxy['id']}")

    if tag:
        api(f"/api/v1/tag/{tag['id']}", "DELETE")
        print(f"deleted tag {tag['id']}")

    print("\nNote: RuTracker will now be reached directly, which is what this proxy existed to avoid.")
    return 0


def main() -> int:
    if "--remove" in sys.argv:
        return remove()

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    address = args[0] if args else DEFAULT_ADDRESS
    host, _, port_text = address.rpartition(":")
    if not host:
        host, port = address, DEFAULT_PORT
    else:
        port = int(port_text) if port_text.isdigit() else DEFAULT_PORT

    status, tag = api("/api/v1/tag", "POST", {"label": TAG_LABEL})
    if not isinstance(tag, dict) or "id" not in tag:
        tag = find_tag()
    if not tag:
        sys.exit(f"could not create the tag: HTTP {status}")
    print(f"tag {TAG_LABEL!r} -> id {tag['id']}")

    payload = find_proxy() or http_schema()
    payload["name"] = PROXY_NAME
    payload["tags"] = [tag["id"]]
    set_field(payload, "host", host)
    set_field(payload, "port", port)

    if "id" in payload:
        status, saved = api(f"/api/v1/indexerproxy/{payload['id']}", "PUT", payload)
    else:
        status, saved = api("/api/v1/indexerproxy", "POST", payload)
    if status >= 400:
        sys.exit(f"could not save the indexer proxy: HTTP {status}: {saved}")
    print(f"indexer proxy {PROXY_NAME!r} -> {host}:{port}")

    indexer = find_indexer()
    if not indexer:
        print("\nNo RuTracker indexer found. Add it in Prowlarr, then re-run this script.")
        print("Leave its username/password blank: this proxy owns the tracker session.")
        return 0

    tags = set(indexer.get("tags") or [])
    tags.add(tag["id"])
    indexer["tags"] = sorted(tags)
    status, saved = api(f"/api/v1/indexer/{indexer['id']}?forceSave=true", "PUT", indexer)
    if status >= 400:
        sys.exit(f"could not tag the indexer: HTTP {status}: {saved}")
    print(f"tagged indexer {indexer['name']!r} (id {indexer['id']})")

    print("\nNext: make sure Prowlarr trusts the proxy's CA, then test the indexer:")
    print(f"  curl -s -H 'X-Api-Key: ...' -X POST {PROWLARR}/api/v1/indexer/{indexer['id']}/test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
