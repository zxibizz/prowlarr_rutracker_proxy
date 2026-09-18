#!/usr/bin/env python3
"""The RuTracker login session - owned here rather than by Prowlarr.

Prowlarr's RuTracker indexer would happily log in itself, but then the session
lives in Prowlarr's cookie jar where nothing can help it: a Cloudflare challenge
on ``login.php`` cannot be solved, a captcha cannot be answered, and every
restart starts over.

So this module owns it instead. It logs in once with the credentials in the
proxy's environment, persists ``bb_session`` to a volume, and injects it into
every upstream request. Prowlarr's own ``login.php`` calls never reach the
tracker at all - the handler answers them with a synthetic success - which means
**the username and password configured on the Prowlarr indexer are ignored**.

Two things can invalidate the session, and both are recovered from here:
a Cloudflare interstitial (solved via FlareSolverr, which yields a
``cf_clearance`` cookie plus the User-Agent it belongs to) and an expired
``bb_session`` (detected by the absence of ``id="logged-in-username"`` on a page
that should have it).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie

from . import config
from .flaresolverr import FlareSolverr, FlareSolverrError, looks_like_challenge
from .upstream import Upstream, UpstreamResponse

log = logging.getLogger("session")

LOGIN_PATH = "/forum/login.php"
INDEX_PATH = "/forum/index.php"

# The marker Prowlarr's own indexer uses to decide whether it is logged in.
LOGGED_IN_MARKER = b'id="logged-in-username"'

CAPTCHA_IMG_RE = re.compile(rb'<img[^>]+src="(https://static\.rutracker\.[a-z]+/captcha/[^"]+)"', re.I)
CAP_CODE_RE = re.compile(rb'name="(cap_code_[^"]+)"', re.I)
CAP_SID_RE = re.compile(rb'name="cap_sid"[^>]*value="([^"]*)"', re.I)
ERROR_RE = re.compile(
    rb'<h4 class="warnColor1[^"]*">(.*?)</h4>|<div class="msg-main">(.*?)</div>', re.I | re.S
)
TAG_RE = re.compile(rb"<[^>]+>")


class LoginFailed(Exception):
    pass


class CaptchaRequired(Exception):
    """The tracker wants a captcha solved; a human has to finish the login."""


class RuTrackerSession:
    def __init__(self, upstream: Upstream, solver: FlareSolverr) -> None:
        self.upstream = upstream
        self.solver = solver
        self.bb_session = ""
        self.cf_cookies: dict[str, str] = {}
        self.user_agent = config.DEFAULT_USER_AGENT
        self.updated_at = 0.0
        self.last_error = ""
        self.pending_captcha: dict | None = None

        self._login_lock = threading.Lock()
        self._clearance_lock = threading.Lock()
        self._generation = 0
        self._clearance_generation = 0

        self._load()

    # ------------------------------------------------------------------ state
    def _load(self) -> None:
        try:
            with open(config.STATE_PATH, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return
        except Exception as exc:  # noqa: BLE001 - a bad state file just means a fresh login
            log.warning("ignoring unreadable state file: %s", exc)
            return

        self.bb_session = state.get("bb_session") or ""
        self.cf_cookies = state.get("cf_cookies") or {}
        self.user_agent = state.get("user_agent") or config.DEFAULT_USER_AGENT
        self.updated_at = state.get("updated_at") or 0.0
        if self.bb_session:
            age = (time.time() - self.updated_at) / 3600.0
            log.info("restored a session from %s (%.1fh old)", config.STATE_PATH, age)

    def _save(self) -> None:
        state = {
            "bb_session": self.bb_session,
            "cf_cookies": self.cf_cookies,
            "user_agent": self.user_agent,
            "updated_at": self.updated_at,
            "mirror": self.upstream.active,
        }
        os.makedirs(os.path.dirname(config.STATE_PATH), exist_ok=True)
        tmp = config.STATE_PATH + ".tmp"
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp, config.STATE_PATH)

    # ------------------------------------------------------------------ cookies
    def cookies(self) -> dict[str, str]:
        jar = dict(self.cf_cookies)
        if self.bb_session:
            jar["bb_session"] = self.bb_session
        return jar

    def headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        base = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        if extra:
            base.update(extra)
        return base

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def clearance_generation(self) -> int:
        return self._clearance_generation

    # ------------------------------------------------------------------ challenge
    def refresh_clearance(self, seen_generation: int | None = None) -> bool:
        """Solve the interstitial once, however many callers noticed it at the same time."""
        with self._clearance_lock:
            if seen_generation is not None and seen_generation != self._clearance_generation:
                return True
            try:
                cookies, user_agent = self.solver.solve(self.upstream.active + "/forum/index.php")
            except (FlareSolverrError, Exception) as exc:  # noqa: BLE001 - surfaced to the caller
                self.last_error = f"FlareSolverr: {exc}"
                log.error("could not solve the challenge: %s", exc)
                return False

            # bb_session may come back too if the browser was already logged in.
            self.cf_cookies = {name: value for name, value in cookies.items() if name != "bb_session"}
            if cookies.get("bb_session"):
                self.bb_session = cookies["bb_session"]
            self.user_agent = user_agent
            self.updated_at = time.time()
            self._clearance_generation += 1
            self._save()
            return True

    # ------------------------------------------------------------------ login
    def ensure(self) -> None:
        if self.bb_session:
            return
        if not config.USERNAME or not config.PASSWORD:
            log.warning("no RUTRACKER_USERNAME/RUTRACKER_PASSWORD set; browsing anonymously")
            return
        self.relogin()

    def relogin(self, seen_generation: int | None = None, captcha_code: str | None = None) -> None:
        """Log in once, however many concurrent searches noticed the session was gone.

        One Prowlarr search fans out into several ``f=`` chunk requests, so without
        this the first expiry would start a login per chunk.
        """
        with self._login_lock:
            if seen_generation is not None and seen_generation != self._generation:
                return
            self._login(captcha_code)
            self._generation += 1

    def _login(self, captcha_code: str | None = None) -> None:
        if not config.USERNAME or not config.PASSWORD:
            raise LoginFailed("no credentials configured")

        log.info("logging in as %s", config.USERNAME)
        form = self._login_form()

        fields = {
            "login_username": config.USERNAME,
            "login_password": config.PASSWORD,
            "login": "Login",
        }
        if form.get("cap_sid"):
            if not captcha_code:
                self.pending_captcha = form
                raise CaptchaRequired(
                    "RuTracker is asking for a captcha; open /captcha and POST the code to /login"
                )
            fields["cap_sid"] = form["cap_sid"]
            fields[form["cap_code_field"]] = captcha_code

        body = urllib.parse.urlencode(fields, encoding="windows-1251", errors="replace").encode("ascii")
        response = self.upstream.request(
            "POST",
            LOGIN_PATH,
            headers=self.headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self.upstream.active + LOGIN_PATH,
                    "Origin": self.upstream.active,
                }
            ),
            body=body,
            cookies=self.cookies(),
        )
        self._absorb_cookies(response)

        if looks_like_challenge(response.status, response.headers, response.content):
            if not self.refresh_clearance():
                raise LoginFailed("a challenge blocks login.php and it could not be solved")
            return self._login(captcha_code)

        # A successful login answers 302; only the follow-up page carries the marker.
        if LOGGED_IN_MARKER not in response.content:
            probe = self.upstream.request(
                "GET", INDEX_PATH, headers=self.headers(), cookies=self.cookies()
            )
            self._absorb_cookies(probe)
            if LOGGED_IN_MARKER not in probe.content:
                message = _error_message(response.content) or _error_message(probe.content)
                self.last_error = message or "login rejected"
                raise LoginFailed(self.last_error)

        if not self.bb_session:
            raise LoginFailed("login looked successful but no bb_session cookie was issued")

        self.pending_captcha = None
        self.last_error = ""
        self.updated_at = time.time()
        self._save()
        log.info("logged in; bb_session stored")

    def _login_form(self) -> dict:
        """GET the login page, clear any challenge, and read the captcha fields if present."""
        response = self.upstream.request("GET", LOGIN_PATH, headers=self.headers(), cookies=self.cookies())
        self._absorb_cookies(response)

        if looks_like_challenge(response.status, response.headers, response.content):
            if not self.refresh_clearance():
                raise LoginFailed("a challenge blocks login.php and it could not be solved")
            response = self.upstream.request(
                "GET", LOGIN_PATH, headers=self.headers(), cookies=self.cookies()
            )
            self._absorb_cookies(response)

        image = CAPTCHA_IMG_RE.search(response.content)
        if not image:
            return {}

        code_field = CAP_CODE_RE.search(response.content)
        sid = CAP_SID_RE.search(response.content)
        if not code_field or not sid:
            log.warning("a captcha image is present but its fields could not be read")
            return {}

        form = {
            "image_url": image.group(1).decode("ascii", "replace"),
            "cap_code_field": code_field.group(1).decode("ascii", "replace"),
            "cap_sid": sid.group(1).decode("ascii", "replace"),
        }
        log.error("RuTracker is asking for a login captcha: %s", form["image_url"])
        return form

    def captcha_image(self) -> tuple[bytes, str]:
        if not self.pending_captcha:
            raise CaptchaRequired("no captcha is pending")
        response = self.upstream.fetch(
            self.pending_captcha["image_url"],
            headers=self.headers({"Referer": self.upstream.active + LOGIN_PATH}),
            cookies=self.cookies(),
        )
        return response.content, response.header("Content-Type") or "image/jpeg"

    # ------------------------------------------------------------------ helpers
    def _absorb_cookies(self, response: UpstreamResponse) -> None:
        for name, value in response.headers:
            if name.lower() != "set-cookie":
                continue
            jar = SimpleCookie()
            try:
                jar.load(value)
            except Exception:  # noqa: BLE001 - a malformed cookie is not fatal
                continue
            for key, morsel in jar.items():
                if key == "bb_session" and morsel.value:
                    self.bb_session = morsel.value
                elif key.startswith("cf_") or key.startswith("__ddg"):
                    self.cf_cookies[key] = morsel.value

    def status(self) -> dict:
        return {
            "logged_in": bool(self.bb_session),
            "session_age_seconds": int(time.time() - self.updated_at) if self.updated_at else None,
            "user_agent": self.user_agent,
            "clearance_cookies": sorted(self.cf_cookies),
            "captcha_pending": bool(self.pending_captcha),
            "last_error": self.last_error,
        }


def _error_message(body: bytes) -> str:
    match = ERROR_RE.search(body)
    if not match:
        return ""
    raw = match.group(1) or match.group(2) or b""
    return TAG_RE.sub(b" ", raw).decode("windows-1251", "replace").strip()
