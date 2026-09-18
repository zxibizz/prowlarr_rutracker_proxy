#!/usr/bin/env python3
"""A reverse proxy that makes Prowlarr's RuTracker indexer work from anywhere.

Prowlarr reaches this by pointing the RuTracker indexer's **Base Url** straight
at it, so every request arrives in ordinary origin form over plain HTTP:

    GET /forum/tracker.php?nm=... -> reissued upstream through SOCKS5

Prowlarr's Base Url renders as a dropdown built from URLs compiled into its C#
indexer, but that is a UI constraint only: ``IndexerFactory`` never validates
the stored value, so the API accepts any address. ``scripts/configure_proxy.py``
sets it. The trailing slash matters - Prowlarr builds links by concatenating
``BaseUrl + "forum/" + href``.

The proxy:

* answers ``login.php`` itself, so Prowlarr never authenticates against the
  tracker and **the credentials configured on the Prowlarr indexer are ignored**
  - the ones in this container's environment are what get used;
* reissues every other request through SOCKS5 against whichever mirror is
  currently healthy, falling back from rutracker.org to rutracker.net;
* rewrites the mirror's hostname back to rutracker.org in the body, and points
  redirects and cookies back at itself, so every link Prowlarr parses comes back
  through here;
* solves Cloudflare/DDoS-Guard interstitials through FlareSolverr and retries.

Everything under ``/forum/`` is the tracker. The rest is local:

    GET  /healthz    liveness probe
    GET  /           what this service is and how it is wired
    GET  /status     active mirror, session age, last error
    GET  /captcha    the pending login captcha image, when there is one
    POST /login      finish a captcha-blocked login: code=<what the image says>
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config
from .flaresolverr import FlareSolverr, looks_like_challenge
from .session import CaptchaRequired, LoginFailed, LOGGED_IN_MARKER, RuTrackerSession
from .upstream import Upstream, UpstreamError

log = logging.getLogger("proxy")

MAX_ATTEMPTS = 3
TORRENT_MAGIC = b"d8:announce"

# A page Prowlarr's indexer will accept as "logged in" without the tracker ever
# seeing Prowlarr's credentials.
SYNTHETIC_LOGIN = (
    b"<!DOCTYPE html><html><head><meta charset=\"windows-1251\">"
    b"<title>rutracker-proxy</title></head><body>"
    b"<div id=\"logged-in-username\">rutracker-proxy</div>"
    b"<p>Authenticated by prowlarr_rutracker_proxy.</p>"
    b"</body></html>"
)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RuTrackerProxy/1.0"

    # ------------------------------------------------------------------ requests
    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        if self.path.startswith("/"):
            self._handle_local(method, self.path)
            return
        # Absolute-form means someone is treating this as a forward proxy, which
        # it is not; relaying that would make it an open proxy.
        self.send_error(400, "this service only answers origin-form requests")

    def _read_body(self) -> bytes | None:
        length = self.headers.get("Content-Length")
        if not length or not length.isdigit() or int(length) <= 0:
            return None
        return self.rfile.read(int(length))

    # ------------------------------------------------------------------ the tracker
    def _handle_site(self, method: str, target: str) -> None:
        body = self._read_body()
        path = urllib.parse.urlsplit(target).path

        if path.startswith("/forum/login.php"):
            self._handle_login(method)
            return

        self._relay(method, target, body)

    def _handle_login(self, method: str) -> None:
        """Answer Prowlarr's auth calls locally; the real session is ours.

        A GET is Prowlarr looking for a captcha image before it offers a login
        form, so the page it gets back deliberately has none. A POST is the login
        itself: all it has to do is make sure *our* session is alive. Either way
        the credentials it submitted are discarded.
        """
        session = self.server.session
        if method == "POST":
            try:
                session.ensure()
                if not session.bb_session and config.USERNAME:
                    session.relogin()
            except CaptchaRequired as exc:
                self._send_bytes(503, "text/html; charset=windows-1251", _login_error(str(exc)))
                return
            except (LoginFailed, UpstreamError) as exc:
                log.error("login failed: %s", exc)
                self._send_bytes(403, "text/html; charset=windows-1251", _login_error(str(exc)))
                return

        self._send_bytes(200, "text/html; charset=windows-1251", SYNTHETIC_LOGIN)

    def _relay(self, method: str, target: str, body: bytes | None) -> None:
        session = self.server.session
        upstream = self.server.upstream

        try:
            session.ensure()
        except CaptchaRequired as exc:
            self._send_bytes(503, "text/plain; charset=utf-8", str(exc).encode())
            return
        except (LoginFailed, UpstreamError) as exc:
            log.error("cannot establish a session: %s", exc)
            self._send_bytes(502, "text/plain; charset=utf-8", str(exc).encode())
            return

        extra = {"Referer": upstream.active + "/forum/index.php"}
        content_type = self.headers.get("Content-Type")
        if content_type:
            extra["Content-Type"] = content_type

        response = None
        for attempt in range(MAX_ATTEMPTS):
            clearance_generation = session.clearance_generation
            login_generation = session.generation
            try:
                response = upstream.request(
                    method,
                    target,
                    headers=session.headers(extra),
                    body=body,
                    cookies=session.cookies(),
                )
            except UpstreamError as exc:
                log.error("%s %s: %s", method, target, exc)
                self._send_bytes(502, "text/plain; charset=utf-8", str(exc).encode())
                return

            if looks_like_challenge(response.status, response.headers, response.content):
                log.info("challenge on %s (attempt %d)", target, attempt + 1)
                if not session.refresh_clearance(
                    clearance_generation, urllib.parse.urlsplit(target).path
                ):
                    self._send_bytes(
                        502, "text/plain; charset=utf-8", b"a challenge could not be solved"
                    )
                    return
                continue

            if self._needs_relogin(response, target):
                log.info("session looks expired on %s (attempt %d)", target, attempt + 1)
                try:
                    session.relogin(login_generation)
                except CaptchaRequired as exc:
                    self._send_bytes(503, "text/plain; charset=utf-8", str(exc).encode())
                    return
                except (LoginFailed, UpstreamError) as exc:
                    log.error("re-login failed: %s", exc)
                    break
                continue

            break

        if response is None:
            self._send_bytes(502, "text/plain; charset=utf-8", b"no response from any mirror")
            return

        log.info(
            "%s %s -> %s (%s, %d bytes)",
            method,
            target,
            response.status,
            response.mirror,
            len(response.content),
        )
        self._send_upstream(response)

    def _needs_relogin(self, response, target: str) -> bool:
        """A logged-in page without the marker means the session died under us."""
        session = self.server.session
        if not session.bb_session or not config.USERNAME:
            return False
        path = urllib.parse.urlsplit(target).path

        if path.startswith("/forum/dl.php"):
            # FlareSolverr can never fetch this, so an HTML answer here is always
            # a lost session or an interstitial rather than a torrent.
            return response.status == 200 and not response.content.startswith(TORRENT_MAGIC)

        if response.status != 200 or not response.is_html:
            return False
        return LOGGED_IN_MARKER not in response.content

    # ------------------------------------------------------------------ local
    def _handle_local(self, method: str, target: str) -> None:
        parts = urllib.parse.urlsplit(target)
        path = parts.path

        # Prowlarr's Base Url points here, so tracker paths arrive in origin form.
        if path.startswith("/forum/"):
            self._handle_site(method, target)
            return

        if path == "/login" and method == "POST":
            self._finish_captcha(parts.query)
            return

        if method not in ("GET", "HEAD"):
            self.send_error(405, "unsupported method")
            return

        if path == "/healthz":
            self._send_json(200, {"ok": True})
        elif path == "/status":
            self._send_json(
                200,
                {
                    "upstream": self.server.upstream.status(),
                    "session": self.server.session.status(),
                    "flaresolverr": {
                        "enabled": self.server.solver.enabled,
                        "url": config.FLARESOLVERR_URL,
                    },
                },
            )
        elif path == "/captcha":
            self._serve_captcha()
        elif path == "/":
            self._send_json(
                200,
                {
                    "service": "prowlarr-rutracker-proxy",
                    "how_it_works": (
                        "point the RuTracker indexer's Base Url at this service, "
                        "trailing slash included; run scripts/configure_proxy.py to set it"
                    ),
                    "note": "the credentials on the Prowlarr indexer are ignored; this proxy owns the session",
                    "mirrors": config.MIRRORS,
                    "endpoints": {
                        "/forum/...": "the tracker itself",
                        "/healthz": "liveness probe",
                        "/status": "active mirror, session age, last error",
                        "/captcha": "pending login captcha image, if any",
                        "POST /login": "finish a captcha-blocked login: code=<value>",
                    },
                },
            )
        else:
            self.send_error(404, "no such endpoint")

    def _serve_captcha(self) -> None:
        try:
            blob, content_type = self.server.session.captcha_image()
        except CaptchaRequired as exc:
            self._send_json(404, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            self._send_json(502, {"error": f"{type(exc).__name__}: {exc}"})
            return
        self._send_bytes(200, content_type, blob)

    def _finish_captcha(self, query: str) -> None:
        raw = self._read_body() or b""
        fields = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        fields.update(urllib.parse.parse_qs(query))
        code = (fields.get("code") or [""])[0].strip()
        if not code:
            self._send_json(400, {"error": "POST code=<what the captcha image says>"})
            return

        try:
            self.server.session.relogin(captcha_code=code)
        except (CaptchaRequired, LoginFailed, UpstreamError) as exc:
            self._send_json(403, {"error": str(exc)})
            return
        self._send_json(200, {"ok": True, "session": self.server.session.status()})

    # ------------------------------------------------------------------ writing
    def _send_upstream(self, response) -> None:
        self.send_response(response.status)
        for name, value in response.headers:
            self.send_header(name, self._localise(name, value))
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.content)

    def _localise(self, name: str, value: str) -> str:
        """Keep redirects and cookies on this proxy rather than the tracker.

        Prowlarr talks to us by our own hostname, so a ``Location`` pointing at
        rutracker.org would send it straight at the blocked origin, and a
        ``Domain=rutracker.org`` cookie would be rejected as a domain mismatch.
        """
        host = self.headers.get("Host")
        if not host:
            return value

        lowered = name.lower()
        if lowered == "location":
            canonical = config.canonical_host()
            for scheme in ("https://", "http://"):
                prefix = scheme + canonical
                if value.startswith(prefix):
                    return f"http://{host}{value[len(prefix):]}"
            return value
        if lowered == "set-cookie":
            return _strip_cookie_domain(value)
        return value

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload: object) -> None:
        self._send_bytes(
            status,
            "application/json; charset=utf-8",
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
        )

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        log.debug("%s %s", self.address_string(), fmt % args)


def _login_error(message: str) -> bytes:
    safe = message.replace("<", "&lt;").encode("utf-8", "replace")
    return (
        b"<!DOCTYPE html><html><body><h4 class=\"warnColor1 tCenter mrg_16\">"
        + safe
        + b"</h4></body></html>"
    )


def _strip_cookie_domain(value: str) -> str:
    kept = [
        part
        for part in value.split(";")
        if part.strip().split("=", 1)[0].strip().lower() != "domain"
    ]
    return ";".join(kept)


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, upstream, session, solver):
        self.upstream = upstream
        self.session = session
        self.solver = solver
        super().__init__(address, handler)


def main() -> None:
    config.setup_logging()

    upstream = Upstream()
    solver = FlareSolverr()
    session = RuTrackerSession(upstream, solver)

    # Logging in can take a browser launch; do not hold up the listener for it.
    threading.Thread(target=_warm_up, args=(session,), daemon=True).start()

    server = ProxyServer((config.BIND, config.PORT), ProxyHandler, upstream, session, solver)
    log.info("listening on %s:%s", config.BIND, config.PORT)
    log.info("mirrors: %s", ", ".join(config.MIRRORS))
    log.info("point the RuTracker indexer's Base Url here, trailing slash included")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        solver.destroy()
        server.server_close()


def _warm_up(session: RuTrackerSession) -> None:
    try:
        session.ensure()
    except CaptchaRequired as exc:
        log.error("%s", exc)
    except Exception as exc:  # noqa: BLE001 - the listener must come up regardless
        log.error("could not establish a session at startup: %s", exc)


if __name__ == "__main__":
    main()
