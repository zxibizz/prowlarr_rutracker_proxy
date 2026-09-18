#!/usr/bin/env python3
"""A MITM HTTP proxy that makes Prowlarr's RuTracker indexer work from anywhere.

Prowlarr reaches this through its built-in **"Http" indexer proxy**, assigned to
the RuTracker indexer with a tag. Because RuTracker is an *https* site, every
request arrives as ``CONNECT rutracker.org:443`` rather than in absolute form,
so there is nothing to divert unless the TLS is terminated here. That is what
this does, and only for the hosts in ``MITM_HOSTS``:

    CONNECT rutracker.org:443     -> terminated here with a cert from our own CA
    CONNECT anything-else:443     -> blind TCP tunnel, real certificate intact

The second line matters: Prowlarr validates an indexer proxy by fetching
prowlarr.servarr.com through it, and that check has to keep working.

Inside the intercepted connection the proxy:

* answers ``login.php`` itself, so Prowlarr never authenticates against the
  tracker and **the credentials configured on the Prowlarr indexer are ignored**
  - the ones in this container's environment are what get used;
* reissues every other request through SOCKS5 against whichever mirror is
  currently healthy, falling back from rutracker.org to rutracker.net;
* rewrites the mirror's hostname back to rutracker.org in the body, the
  redirects and the cookies, so every link Prowlarr parses points at the
  canonical host and comes back through here;
* solves Cloudflare/DDoS-Guard interstitials through FlareSolverr and retries.

Local endpoints on the plain listener, for humans and health checks:

    GET  /healthz    liveness probe
    GET  /           what this service is and how it is wired
    GET  /status     active mirror, session age, last error
    GET  /ca.crt     the CA to install in Prowlarr's trust store
    GET  /captcha    the pending login captcha image, when there is one
    POST /login      finish a captcha-blocked login: code=<what the image says>
"""

from __future__ import annotations

import io
import json
import logging
import os
import select
import socket
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config
from .ca import CertificateAuthority
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


class _SocketWriter(io.BufferedIOBase):
    """Unbuffered, sendall-backed writer - what socketserver uses for wbufsize 0."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def writable(self) -> bool:
        return True

    def write(self, data):  # type: ignore[override]
        self._sock.sendall(data)
        with memoryview(data) as view:
            return view.nbytes

    def fileno(self) -> int:
        return self._sock.fileno()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RuTrackerProxy/1.0"

    mitm_host: str | None = None

    # ------------------------------------------------------------------ CONNECT
    def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        host, _, port_text = self.path.rpartition(":")
        try:
            port = int(port_text) if port_text else 443
        except ValueError:
            host, port = self.path, 443

        if config.is_mitm_host(host):
            self._intercept(host)
        else:
            self._tunnel(host, port)

    def _intercept(self, host: str) -> None:
        """Terminate the client's TLS with a cert minted for this host."""
        try:
            context = self.server.ca.context_for(host)
        except Exception as exc:  # noqa: BLE001 - without a cert there is nothing to serve
            log.error("cannot mint a certificate for %s: %s", host, exc)
            self.send_error(500, "certificate generation failed")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()

        try:
            tls = context.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log.warning("TLS handshake with %s failed: %s", host, exc)
            self.close_connection = True
            return

        log.debug("intercepting %s", host)
        self.connection = tls
        self.rfile = tls.makefile("rb", self.rbufsize)
        self.wfile = _SocketWriter(tls)
        self.mitm_host = host
        self.close_connection = False

    def _tunnel(self, host: str, port: int) -> None:
        """Blind TCP relay - this is how Prowlarr's own proxy health check gets out."""
        try:
            upstream = _open_socket(host, port)
        except OSError as exc:
            log.warning("CONNECT %s:%s failed: %s", host, port, exc)
            self.send_error(502, f"cannot connect to {host}:{port}")
            return

        log.debug("tunnelling %s:%s", host, port)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        try:
            _pump(self.connection, upstream)
        finally:
            upstream.close()
            self.close_connection = True

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
        if self.mitm_host:
            self._handle_site(method, self.path)
            return

        if self.path.startswith("/"):
            self._handle_local(method, self.path)
            return

        # Absolute-form plain http. Only the tracker is in scope; relaying anything
        # else would make this an open proxy.
        parts = urllib.parse.urlsplit(self.path)
        if config.is_mitm_host(parts.hostname or ""):
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
            self._handle_site(method, path)
            return
        self.send_error(403, "this proxy only relays RuTracker traffic")

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
                if not session.refresh_clearance(clearance_generation):
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

        if path == "/login" and method == "POST":
            self._finish_captcha(parts.query)
            return

        if method not in ("GET", "HEAD"):
            self.send_error(405, "unsupported method")
            return

        if path == "/healthz":
            self._send_json(200, {"ok": True})
        elif path == "/ca.crt":
            self._send_bytes(200, "application/x-pem-file", self.server.ca.ca_pem)
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
                        "add this as an Http indexer proxy in Prowlarr and tag the RuTracker "
                        "indexer with it; install /ca.crt in Prowlarr's trust store first"
                    ),
                    "note": "the credentials on the Prowlarr indexer are ignored; this proxy owns the session",
                    "mitm_hosts": config.MITM_HOSTS,
                    "endpoints": {
                        "/healthz": "liveness probe",
                        "/status": "active mirror, session age, last error",
                        "/ca.crt": "the CA to trust in Prowlarr",
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
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.content)

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


def _open_socket(host: str, port: int) -> socket.socket:
    """A plain socket, or one dialled through SOCKS5 when the host is tracker-adjacent."""
    if config.SOCKS5_URL and config.tunnel_via_socks(host):
        import socks  # PySocks, pulled in by requests[socks]

        parsed = urllib.parse.urlsplit(config.SOCKS5_URL)
        sock = socks.socksocket()
        sock.set_proxy(
            socks.SOCKS5,
            parsed.hostname,
            parsed.port or 1080,
            rdns=True,
            username=parsed.username,
            password=parsed.password,
        )
        sock.settimeout(config.HTTP_TIMEOUT)
        sock.connect((host, port))
        return sock
    return socket.create_connection((host, port), timeout=config.HTTP_TIMEOUT)


def _pump(client: socket.socket, upstream: socket.socket) -> None:
    while True:
        try:
            readable, _, errored = select.select([client, upstream], [], [client, upstream], 300)
        except (OSError, ValueError):
            return
        if errored or not readable:
            return
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                (upstream if source is client else client).sendall(data)
            except OSError:
                return


def _login_error(message: str) -> bytes:
    safe = message.replace("<", "&lt;").encode("utf-8", "replace")
    return (
        b"<!DOCTYPE html><html><body><h4 class=\"warnColor1 tCenter mrg_16\">"
        + safe
        + b"</h4></body></html>"
    )


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, ca, upstream, session, solver):
        self.ca = ca
        self.upstream = upstream
        self.session = session
        self.solver = solver
        super().__init__(address, handler)


def main() -> None:
    config.setup_logging()
    os.makedirs(config.STATE_DIR, exist_ok=True)

    ca = CertificateAuthority(config.CA_DIR)
    upstream = Upstream()
    solver = FlareSolverr()
    session = RuTrackerSession(upstream, solver)

    # Logging in can take a browser launch; do not hold up the listener for it.
    threading.Thread(target=_warm_up, args=(session,), daemon=True).start()

    server = ProxyServer((config.BIND, config.PORT), ProxyHandler, ca, upstream, session, solver)
    log.info("listening on %s:%s", config.BIND, config.PORT)
    log.info("intercepting %s, tunnelling everything else", ", ".join(config.MITM_HOSTS))
    log.info("mirrors: %s", ", ".join(config.MIRRORS))
    log.info("install %s in Prowlarr's trust store (also served at /ca.crt)", ca.cert_path)

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
