"""Offline checks for the parts that need no network: rewriting and detection."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("RUTRACKER_MIRRORS", "https://rutracker.org,https://rutracker.net")
os.environ.setdefault("SOCKS5_URL", "")

from proxy.app import _strip_cookie_domain  # noqa: E402
from proxy.flaresolverr import looks_like_challenge  # noqa: E402
from proxy.upstream import Upstream  # noqa: E402


class RewriteTest(unittest.TestCase):
    def test_foreign_mirror_becomes_canonical(self) -> None:
        up = Upstream()
        body = "<a href=\"https://rutracker.net/forum/viewtopic.php?t=1\">т</a>".encode("windows-1251")
        out = up.rewrite_bytes(body)
        self.assertNotIn(b"rutracker.net", out)
        self.assertIn(b"https://rutracker.org/forum/viewtopic.php?t=1", out)
        # windows-1251 bytes outside the hostname are untouched
        self.assertTrue(out.endswith("т</a>".encode("windows-1251")))

    def test_header_rewrite(self) -> None:
        self.assertEqual(Upstream().rewrite_text("https://rutracker.net/x"), "https://rutracker.org/x")


class ChallengeTest(unittest.TestCase):
    def test_cloudflare_interstitial(self) -> None:
        self.assertTrue(looks_like_challenge(403, [], b"<title>Just a moment...</title>"))

    def test_cf_mitigated_header(self) -> None:
        self.assertTrue(looks_like_challenge(200, [("cf-mitigated", "challenge")], b""))

    def test_ordinary_page(self) -> None:
        self.assertFalse(looks_like_challenge(200, [], b"<title>Just a moment</title>"))
        self.assertFalse(looks_like_challenge(404, [], b"not found"))


class CookieTest(unittest.TestCase):
    def test_domain_stripped(self) -> None:
        value = "bb_session=abc; Domain=.rutracker.org; Path=/; HttpOnly"
        self.assertEqual(_strip_cookie_domain(value), "bb_session=abc; Path=/; HttpOnly")


class CookieJarTest(unittest.TestCase):
    def test_set_cookie_does_not_shadow_explicit_cookies(self) -> None:
        from email.message import Message

        import requests
        from requests.cookies import MockRequest, MockResponse

        up = Upstream()
        headers = Message()
        headers["Set-Cookie"] = "cf_clearance=STALE; Domain=.rutracker.org; Path=/"
        prepared = requests.Request("GET", "https://rutracker.org/forum/index.php").prepare()
        up.session.cookies.extract_cookies(MockResponse(headers), MockRequest(prepared))
        self.assertEqual(len(up.session.cookies), 0)

        request = requests.Request(
            "GET", "https://rutracker.org/forum/tracker.php", cookies={"cf_clearance": "FRESH"}
        )
        self.assertEqual(up.session.prepare_request(request).headers["Cookie"], "cf_clearance=FRESH")


class StubbornChallengeTest(unittest.TestCase):
    """A clearance that does not help must not be re-fetched from the same browser."""

    def _session(self, solver):
        import tempfile

        from proxy import config
        from proxy.session import RuTrackerSession

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        original = config.STATE_PATH
        config.STATE_PATH = os.path.join(tmp.name, "session.json")
        self.addCleanup(setattr, config, "STATE_PATH", original)
        return RuTrackerSession(Upstream(), solver)

    def _solver(self):
        calls = []

        class Solver:
            def solve(self, url):
                calls.append("solve")
                return {"cf_clearance": f"C{len(calls)}"}, "UA"

            def destroy(self):
                calls.append("destroy")

        return Solver(), calls

    def test_first_challenge_reuses_browser_and_connections(self) -> None:
        solver, calls = self._solver()
        session = self._session(solver)
        before = session.upstream.session
        self.assertTrue(session.refresh_clearance(path="/forum/tracker.php"))
        self.assertEqual(calls, ["solve"])
        self.assertIs(session.upstream.session, before)

    def test_repeated_challenge_resets_browser_and_connections(self) -> None:
        solver, calls = self._solver()
        session = self._session(solver)
        before = session.upstream.session
        self.assertTrue(session.refresh_clearance(path="/forum/tracker.php", stubborn=True))
        self.assertEqual(calls, ["destroy", "solve"])
        self.assertIsNot(session.upstream.session, before)
        self.assertEqual(session.cf_cookies, {"cf_clearance": "C2"})
        # the new session keeps the jar policy that rejects Set-Cookie
        self.assertEqual(len(session.upstream.session.cookies), 0)
        self.assertEqual(session.upstream.session.cookies.get_policy().allowed_domains(), ())


ORG, NET = "https://rutracker.org", "https://rutracker.net"


def _mirror_of(url: str) -> str:
    return url[: url.index("/", len("https://"))]


class MirrorSwitchOnUnsolvedChallengeTest(unittest.TestCase):
    """A mirror whose challenge cannot be solved must not keep every search on 502."""

    CHALLENGE = b"<title>Just a moment...</title>"
    RESULTS = b"<html>results</html>"

    def setUp(self) -> None:
        import tempfile

        from proxy import config

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        original = config.STATE_PATH
        config.STATE_PATH = os.path.join(tmp.name, "session.json")
        self.addCleanup(setattr, config, "STATE_PATH", original)

    def _relay(self, solvable, fails=lambda mirror: None, error=None, up=None, stubborn_on=()):
        import types

        import requests

        from proxy.app import ProxyHandler
        from proxy.flaresolverr import ChallengeUnsolved
        from proxy.session import RuTrackerSession

        up = up or Upstream()
        cleared: set[str] = set()
        sent: list[str] = []
        solved: list[str] = []
        # Mirrors that still challenge once after their first clearance.
        stubborn_left = set(stubborn_on)
        # A mirror the stubborn re-solve can no longer pass.
        broken_after_first = set(stubborn_on)

        def send(method, url, headers, body, cookies):
            mirror = _mirror_of(url)
            sent.append(mirror)
            exc = fails(mirror)
            if exc:
                raise exc
            response = requests.Response()
            response.url = url
            response.headers["Content-Type"] = "text/html"
            if mirror in cleared and mirror in stubborn_left:
                stubborn_left.discard(mirror)
                response.status_code, response._content = 403, self.CHALLENGE
            elif mirror in cleared:
                response.status_code, response._content = 200, self.RESULTS
            else:
                response.status_code, response._content = 403, self.CHALLENGE
            return response

        up._send = send

        class Solver:
            def solve(self, url):
                mirror = _mirror_of(url)
                solved.append(mirror)
                if error:
                    raise error
                if mirror not in solvable or (mirror in broken_after_first and solved.count(mirror) > 1):
                    raise ChallengeUnsolved("Error: Error solving the challenge. Timeout after 60.0 seconds.")
                cleared.add(mirror)
                return {"cf_clearance": "C"}, "UA"

            def destroy(self):
                pass

        session = RuTrackerSession(up, Solver())
        session.bb_session = "S"
        handler = object.__new__(ProxyHandler)
        handler.server = types.SimpleNamespace(session=session, upstream=up)
        handler.headers = {}
        answers: list[tuple[int, bytes]] = []
        handler._send_bytes = lambda status, content_type, body: answers.append((status, body))
        handler._send_upstream = lambda response: answers.append((response.status, response.content))
        handler._relay("GET", "/forum/tracker.php?nm=x", None)
        return types.SimpleNamespace(up=up, answers=answers, sent=sent, solved=solved)

    def test_switches_to_the_mirror_that_can_be_solved(self) -> None:
        r = self._relay(solvable={NET})
        self.assertEqual(r.answers, [(200, self.RESULTS)])
        self.assertEqual(r.up.active, NET)
        self.assertEqual(r.sent, [ORG, NET, NET])
        self.assertEqual(r.solved, [ORG, NET])

    def test_gives_up_when_no_mirror_can_be_solved_and_does_not_wrap_back(self) -> None:
        r = self._relay(solvable=set())
        self.assertEqual(r.answers, [(502, b"a challenge could not be solved")])
        self.assertEqual(r.sent, [ORG, NET])
        # net was the last hope; org is still in its cooldown, so net stays
        self.assertEqual(r.up.active, NET)
        # the next request tries net only, instead of taking turns with org
        again = self._relay(solvable=set(), up=r.up)
        self.assertEqual(again.answers, [(502, b"a challenge could not be solved")])
        self.assertEqual(again.solved, [NET])
        self.assertEqual(again.up.active, NET)

    def test_solvable_mirror_stays_active(self) -> None:
        r = self._relay(solvable={ORG})
        self.assertEqual(r.answers, [(200, self.RESULTS)])
        self.assertEqual(r.up.active, ORG)

    def test_solves_the_mirror_that_served_the_challenge(self) -> None:
        import requests

        # org times out once (below the failover threshold), net serves the challenge
        timeouts = {ORG: 1}

        def fails(mirror):
            if timeouts.get(mirror):
                timeouts[mirror] -= 1
                return requests.ConnectTimeout("read timed out")
            return None

        r = self._relay(solvable={NET}, fails=fails)
        # net's challenge is solved on net, not on the active org
        self.assertEqual(r.solved[0], NET)
        self.assertEqual(r.answers, [(200, self.RESULTS)])

    def test_unsolvable_fallback_mirror_is_solved_once(self) -> None:
        import requests

        # org keeps timing out (below the threshold), net serves a challenge nobody can pass
        r = self._relay(solvable=set(), fails=lambda m: requests.ConnectTimeout("timed out") if m == ORG else None)
        self.assertEqual(r.solved, [NET])
        self.assertEqual(r.answers, [(502, b"a challenge could not be solved")])

    def test_switch_after_a_stubborn_retry_still_gets_an_attempt(self) -> None:
        # org: cleared, challenges again, stubborn re-solve fails -> net, which is solved
        r = self._relay(solvable={ORG, NET}, stubborn_on={ORG})
        self.assertEqual(r.solved, [ORG, ORG, NET])
        self.assertEqual(r.answers, [(200, self.RESULTS)])
        self.assertEqual(r.up.active, NET)

    def test_queued_caller_does_not_solve_a_demoted_mirror_again(self) -> None:
        from proxy.session import RuTrackerSession

        calls = []

        class Solver:
            def solve(self, url):
                calls.append(url)
                return {"cf_clearance": "C"}, "UA"

            def destroy(self):
                pass

        up = Upstream()
        session = RuTrackerSession(up, Solver())
        seen = up.demotions
        up.demote(ORG)  # another request gave up on org meanwhile
        won = session.refresh_clearance(
            session.clearance_generation, "/forum/tracker.php", mirror=ORG, demote=True, seen_demotions=seen
        )
        self.assertIsNone(won)
        self.assertEqual(calls, [])

    def test_flaresolverr_outage_keeps_the_mirror(self) -> None:
        import requests

        r = self._relay(solvable={ORG, NET}, error=requests.ConnectionError("connection refused"))
        self.assertEqual(r.answers, [(502, b"a challenge could not be solved")])
        self.assertEqual(r.up.active, ORG)


class DemoteTest(unittest.TestCase):
    def test_only_the_active_mirror_is_demoted(self) -> None:
        up = Upstream()
        up.demote(NET)
        self.assertEqual(up.active, ORG)
        up.demote(ORG)
        self.assertEqual(up.active, NET)

    def test_preferred_mirror_returns_after_the_cooldown(self) -> None:
        from proxy import config

        up = Upstream()
        up.demote(ORG)
        up._demoted_at -= config.MIRROR_RECHECK_SECONDS + 1
        self.assertEqual(up.active, ORG)


class FlareSolverrErrorTest(unittest.TestCase):
    def _post(self, status, body):
        import requests

        from proxy.flaresolverr import FlareSolverr

        solver = FlareSolverr()

        def post(url, json, timeout):
            response = requests.Response()
            response.status_code = status
            response._content = body
            return response

        solver._http.post = post
        return solver._post({"cmd": "request.get"})

    def test_challenge_timeout_is_unsolved(self) -> None:
        from proxy.flaresolverr import ChallengeUnsolved

        with self.assertRaises(ChallengeUnsolved):
            self._post(500, b'{"status": "error", "message": "Error: Error solving the challenge. Timeout after 60.0 seconds."}')

    def test_other_errors_are_not_unsolved(self) -> None:
        import requests

        with self.assertRaises(requests.HTTPError):
            self._post(500, b'{"status": "error", "message": "Error: This session does not exist."}')
        with self.assertRaises(requests.HTTPError):
            self._post(502, b"<html>bad gateway</html>")


if __name__ == "__main__":
    unittest.main()
