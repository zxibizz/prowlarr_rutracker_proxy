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


if __name__ == "__main__":
    unittest.main()


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
