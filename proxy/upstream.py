#!/usr/bin/env python3
"""The upstream half: SOCKS5, mirror failover, and hostname rewriting.

Everything that leaves this container for the tracker goes through here. Three
things happen on the way:

1. **SOCKS5.** All requests are issued through ``socks5h://``, so the tracker's
   name is resolved at the far end of the tunnel rather than locally.
2. **Mirror failover.** ``rutracker.org`` is tried first; when it stops
   answering the next mirror takes over for a cooldown, then the preferred one
   is probed again.
3. **Rewriting.** Whatever mirror actually served the response, every mention of
   its hostname is rewritten back to the canonical one on the way out, so
   Prowlarr's parsed links, redirects and cookies all stay on rutracker.org and
   therefore keep coming back through this proxy.

The rewrite is done on raw bytes rather than decoded text on purpose: RuTracker
serves windows-1251, and hostnames are ASCII, so byte substitution is both
encoding-safe and cheaper than a decode/encode round trip.
"""

from __future__ import annotations

import logging
import threading
import time

import requests

from . import config

log = logging.getLogger("upstream")

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    # requests has already decoded the body, so the original framing headers are lies.
    "content-encoding",
    "content-length",
}


class UpstreamError(Exception):
    """No mirror could serve the request."""


class UpstreamResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]], content: bytes, url: str, mirror: str):
        self.status = status
        self.headers = headers
        self.content = content
        self.url = url
        self.mirror = mirror

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    @property
    def is_html(self) -> bool:
        return "html" in (self.header("Content-Type") or "").lower()


class Upstream:
    def __init__(self) -> None:
        self.mirrors = list(config.MIRRORS)
        self.canonical_host = config.canonical_host()
        self._foreign_hosts = [host for host in config.mirror_hosts() if host != self.canonical_host]
        self._index = 0
        self._failures = 0
        self._demoted_at = 0.0
        self._state_lock = threading.Lock()
        self._gate_lock = threading.Lock()
        self._last_request = 0.0

        self.session = requests.Session()
        self.session.trust_env = False
        if config.SOCKS5_URL:
            self.session.proxies = {"http": config.SOCKS5_URL, "https": config.SOCKS5_URL}
            log.info("upstream traffic goes through %s", _redact(config.SOCKS5_URL))
        else:
            log.warning("SOCKS5_URL is empty; upstream traffic goes out directly")

    # ------------------------------------------------------------------ mirrors
    @property
    def active(self) -> str:
        with self._state_lock:
            self._maybe_restore_preferred()
            return self.mirrors[self._index]

    def _maybe_restore_preferred(self) -> None:
        if self._index == 0 or config.MIRROR_RECHECK_SECONDS <= 0:
            return
        if time.time() - self._demoted_at >= config.MIRROR_RECHECK_SECONDS:
            log.info("cooldown over, trying %s again", self.mirrors[0])
            self._index = 0
            self._failures = 0

    def _note_failure(self, mirror: str) -> None:
        with self._state_lock:
            if self.mirrors[self._index] != mirror:
                return
            self._failures += 1
            if self._failures < config.MIRROR_FAIL_THRESHOLD or len(self.mirrors) < 2:
                return
            self._index = (self._index + 1) % len(self.mirrors)
            self._failures = 0
            self._demoted_at = time.time()
            log.warning("%s keeps failing, switching to %s", mirror, self.mirrors[self._index])

    def _note_success(self, mirror: str) -> None:
        with self._state_lock:
            if self.mirrors[self._index] == mirror:
                self._failures = 0

    def _order(self) -> list[str]:
        start = self.mirrors.index(self.active)
        return self.mirrors[start:] + self.mirrors[:start]

    # ------------------------------------------------------------------ requests
    def request(
        self,
        method: str,
        path_qs: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        cookies: dict[str, str] | None = None,
    ) -> UpstreamResponse:
        """Issue one request against whichever mirror is healthy, and rewrite the answer."""
        if not path_qs.startswith("/"):
            path_qs = "/" + path_qs

        last_error: Exception | None = None
        for mirror in self._order():
            url = mirror + path_qs
            try:
                response = self._send(method, url, headers, body, cookies)
            except requests.RequestException as exc:
                last_error = exc
                log.warning("%s %s failed: %s", method, url, exc)
                self._note_failure(mirror)
                continue

            if response.status_code >= 500 and len(self.mirrors) > 1:
                log.warning("%s answered HTTP %s for %s", mirror, response.status_code, path_qs)
                self._note_failure(mirror)
                last_error = UpstreamError(f"{mirror} answered HTTP {response.status_code}")
                continue

            self._note_success(mirror)
            return self._project(response, mirror)

        raise UpstreamError(f"no mirror could serve {method} {path_qs}") from last_error

    def fetch(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> UpstreamResponse:
        """Fetch one absolute URL as-is - used for off-mirror assets like the captcha image."""
        response = self._send("GET", url, headers, None, cookies)
        return self._project(response, url)

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
        cookies: dict[str, str] | None,
    ) -> requests.Response:
        self._be_polite()
        log.debug("%s %s", method, url)
        return self.session.request(
            method,
            url,
            headers=headers or {},
            data=body,
            cookies=cookies or {},
            timeout=config.HTTP_TIMEOUT,
            allow_redirects=False,
        )

    def _be_polite(self) -> None:
        if config.REQUEST_DELAY <= 0:
            return
        with self._gate_lock:
            wait = self._last_request + config.REQUEST_DELAY - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    # ------------------------------------------------------------------ rewriting
    def _project(self, response: requests.Response, mirror: str) -> UpstreamResponse:
        headers: list[tuple[str, str]] = []
        for name, value in response.raw.headers.items() if response.raw else response.headers.items():
            if name.lower() in HOP_BY_HOP:
                continue
            headers.append((name, self.rewrite_text(value)))
        return UpstreamResponse(
            response.status_code, headers, self.rewrite_bytes(response.content), response.url, mirror
        )

    def rewrite_bytes(self, data: bytes) -> bytes:
        """Every mirror hostname becomes the canonical one."""
        if not data:
            return data
        canonical = self.canonical_host.encode("ascii")
        for host in self._foreign_hosts:
            data = data.replace(host.encode("ascii"), canonical)
        return data

    def rewrite_text(self, value: str) -> str:
        for host in self._foreign_hosts:
            value = value.replace(host, self.canonical_host)
        return value

    def status(self) -> dict:
        with self._state_lock:
            return {
                "active_mirror": self.mirrors[self._index],
                "mirrors": self.mirrors,
                "consecutive_failures": self._failures,
                "socks5": bool(config.SOCKS5_URL),
            }


def _redact(url: str) -> str:
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    return f"{scheme}://***@{rest.rpartition('@')[2]}"
