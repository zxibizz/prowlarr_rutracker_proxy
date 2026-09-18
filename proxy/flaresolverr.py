#!/usr/bin/env python3
"""FlareSolverr client and challenge detection.

FlareSolverr drives a real browser, so it is what gets past a Cloudflare or
DDoS-Guard interstitial. Two properties of it shape how it is used here:

* It returns **text**, never bytes. A ``.torrent`` file can therefore never be
  fetched through it, which is why it only ever solves the challenge and hands
  back cookies - the actual requests stay on the plain SOCKS5 client.
* The ``cf_clearance`` cookie it wins is bound to the User-Agent the browser
  presented. The two must travel together or the challenge simply comes back.

So the flow is always: request directly, notice an interstitial, solve once,
re-request directly with the cookie *and* the matching UA.
"""

from __future__ import annotations

import logging
import uuid

import requests

from . import config

log = logging.getLogger("flaresolverr")

CHALLENGE_STATUSES = {403, 429, 503}
CHALLENGE_MARKERS = (
    b"cf_chl_opt",
    b"cf-browser-verification",
    b"Just a moment",
    b"Checking your browser",
    b"Attention Required",
    b"ddos-guard",
    b"DDoS-Guard",
    b"__ddg_",
)


class FlareSolverrError(Exception):
    pass


def looks_like_challenge(status: int, headers: list[tuple[str, str]], body: bytes) -> bool:
    """Is this an interstitial rather than the page we asked for?"""
    for name, value in headers:
        if name.lower() == "cf-mitigated" and "challenge" in value.lower():
            return True
    if status not in CHALLENGE_STATUSES:
        return False
    head = body[:8192]
    return any(marker in head for marker in CHALLENGE_MARKERS)


class FlareSolverr:
    def __init__(self) -> None:
        self.url = config.FLARESOLVERR_URL
        self.enabled = config.FLARESOLVERR_ENABLED and bool(self.url)
        self._session_id: str | None = None
        self._http = requests.Session()
        self._http.trust_env = False

    # FlareSolverr itself is a neighbour on the compose network; only the browser
    # it drives needs the SOCKS tunnel, which is what this block asks for.
    def _proxy_block(self) -> dict | None:
        return {"url": config.SOCKS5_URL} if config.SOCKS5_URL else None

    def _post(self, payload: dict) -> dict:
        timeout = config.FLARESOLVERR_TIMEOUT_MS / 1000.0 + 30.0
        response = self._http.post(f"{self.url}/v1", json=payload, timeout=timeout)
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "ok":
            raise FlareSolverrError(body.get("message") or "FlareSolverr returned a non-ok status")
        return body

    def _ensure_session(self) -> str | None:
        """A reused browser session turns 'launch Chrome per solve' into 'reuse a tab'."""
        if config.FLARESOLVERR_SESSION_TTL_MINUTES <= 0:
            return None
        if self._session_id:
            return self._session_id

        session_id = f"rutracker-{uuid.uuid4().hex[:8]}"
        payload: dict = {"cmd": "sessions.create", "session": session_id}
        proxy = self._proxy_block()
        if proxy:
            payload["proxy"] = proxy
        try:
            self._post(payload)
        except Exception as exc:  # noqa: BLE001 - sessionless solving still works
            log.warning("could not create a FlareSolverr session: %s", exc)
            return None
        self._session_id = session_id
        log.info("created FlareSolverr session %s", session_id)
        return session_id

    def solve(self, url: str) -> tuple[dict[str, str], str]:
        """Return the cookies that clear the challenge, plus the UA they belong to."""
        if not self.enabled:
            raise FlareSolverrError("FlareSolverr is disabled")

        payload: dict = {
            "cmd": "request.get",
            "url": url,
            "maxTimeout": config.FLARESOLVERR_TIMEOUT_MS,
            "returnOnlyCookies": True,
        }
        session_id = self._ensure_session()
        if session_id:
            payload["session"] = session_id
            payload["session_ttl_minutes"] = config.FLARESOLVERR_SESSION_TTL_MINUTES
        else:
            proxy = self._proxy_block()
            if proxy:
                payload["proxy"] = proxy

        log.info("asking FlareSolverr to solve %s", url)
        try:
            body = self._post(payload)
        except FlareSolverrError:
            if not session_id:
                raise
            # A stale session id is the usual cause; drop it and try once without.
            log.warning("retrying without the FlareSolverr session")
            self._session_id = None
            payload.pop("session", None)
            payload.pop("session_ttl_minutes", None)
            proxy = self._proxy_block()
            if proxy:
                payload["proxy"] = proxy
            body = self._post(payload)

        solution = body.get("solution") or {}
        cookies = {
            cookie["name"]: cookie["value"]
            for cookie in solution.get("cookies") or []
            if cookie.get("name")
        }
        user_agent = solution.get("userAgent") or config.DEFAULT_USER_AGENT
        log.info("FlareSolverr returned %d cookie(s)", len(cookies))
        return cookies, user_agent

    def destroy(self) -> None:
        if not self._session_id:
            return
        try:
            self._post({"cmd": "sessions.destroy", "session": self._session_id})
        except Exception as exc:  # noqa: BLE001 - shutdown path, nothing to recover
            log.debug("could not destroy FlareSolverr session: %s", exc)
        self._session_id = None
