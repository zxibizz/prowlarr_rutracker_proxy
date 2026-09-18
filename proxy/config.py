#!/usr/bin/env python3
"""Environment-backed settings for the RuTracker proxy.

Every knob the service has lives here so the rest of the modules never read the
environment themselves.
"""

from __future__ import annotations

import logging
import os
import sys


def _text(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def _int(name: str, default: int) -> int:
    raw = _text(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = _text(name, "")
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in _text(name, default).split(",") if item.strip()]


def _bool(name: str, default: bool) -> bool:
    raw = _text(name, "").lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


# ------------------------------------------------------------------ listener
BIND = _text("PROXY_BIND", "0.0.0.0")
PORT = _int("PROXY_PORT", 8790)

# Hosts whose CONNECT is terminated here with a cert minted by our own CA.
# Everything else is blind-tunnelled, which is what keeps Prowlarr's proxy health
# check against prowlarr.servarr.com working untouched.
MITM_HOSTS = [host.lower() for host in _list("MITM_HOSTS", "rutracker.org,rutracker.net")]

# Hosts whose blind tunnel is still routed through SOCKS5 rather than going direct.
# static.rutracker.cc serves the login captcha and is blocked in the same places
# the tracker itself is.
SOCKS_TUNNEL_SUFFIXES = [
    host.lower()
    for host in _list("SOCKS_TUNNEL_SUFFIXES", "rutracker.org,rutracker.net,rutracker.cc,rutracker.nl")
]

# ------------------------------------------------------------------ storage
STATE_DIR = _text("STATE_DIR", "/data")
CA_DIR = _text("CA_DIR", os.path.join(STATE_DIR, "ca"))
STATE_PATH = os.path.join(STATE_DIR, "session.json")

# ------------------------------------------------------------------ upstream
# The first entry is canonical: every other mirror's hostname is rewritten to it
# on the way back, so Prowlarr only ever sees rutracker.org.
MIRRORS = [url.rstrip("/") for url in _list("RUTRACKER_MIRRORS", "https://rutracker.org,https://rutracker.net")]
USERNAME = _text("RUTRACKER_USERNAME", "")
PASSWORD = os.environ.get("RUTRACKER_PASSWORD", "")

# Empty means "go direct", which is only useful when developing outside a blocked
# network. socks5h:// resolves DNS at the SOCKS endpoint, which is what you want
# when the tracker's name is poisoned locally.
SOCKS5_URL = _text("SOCKS5_URL", "")

HTTP_TIMEOUT = _float("HTTP_TIMEOUT", 30.0)
RETRIES = _int("RETRIES", 3)
MIRROR_FAIL_THRESHOLD = _int("MIRROR_FAIL_THRESHOLD", 2)
MIRROR_RECHECK_SECONDS = _float("MIRROR_RECHECK_SECONDS", 900.0)
REQUEST_DELAY = _float("REQUEST_DELAY", 0.25)

# ------------------------------------------------------------------ flaresolverr
FLARESOLVERR_URL = _text("FLARESOLVERR_URL", "http://flaresolverr:8191").rstrip("/")
FLARESOLVERR_TIMEOUT_MS = _int("FLARESOLVERR_TIMEOUT_MS", 60000)
FLARESOLVERR_SESSION_TTL_MINUTES = _int("FLARESOLVERR_SESSION_TTL_MINUTES", 30)
FLARESOLVERR_ENABLED = _bool("FLARESOLVERR_ENABLED", True)

# Used until FlareSolverr hands us the one its browser actually presented. A
# cf_clearance cookie is only valid together with the UA that earned it.
DEFAULT_USER_AGENT = _text(
    "PROXY_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)

LOG_LEVEL = _text("LOG_LEVEL", "INFO").upper()


def canonical_base() -> str:
    return MIRRORS[0]


def canonical_host() -> str:
    return MIRRORS[0].split("://", 1)[-1].split("/", 1)[0]


def mirror_hosts() -> list[str]:
    return [url.split("://", 1)[-1].split("/", 1)[0] for url in MIRRORS]


def is_mitm_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == entry or host.endswith("." + entry) for entry in MITM_HOSTS)


def tunnel_via_socks(host: str) -> bool:
    host = (host or "").lower()
    return any(host == entry or host.endswith("." + entry) for entry in SOCKS_TUNNEL_SUFFIXES)


def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-12s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
