"""The texts of the law are fetched over HTTPS only, redirects included.

Cellar answers https://publications.europa.eu/resource/celex/<celex> with a 303
to an http:// URL (recorded on 2026-10-11 in fixtures/cellar_redirect_32016R0679.json).
Followed as given, the act arrived in clear and the SHA-256 printed beside a
citation described bytes nothing had protected in transit. The same path over
https:// served the same document, byte for byte, so the hop is taken over HTTPS.

The responses below are Cellar's, replayed at the HTTP boundary: the recorded
303, and for the HTTPS hop the GDPR page already recorded in
fixtures/gdpr_it_excerpt.html. Any request over plain HTTP is answered 599 and
recorded, so the test sees it.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from mailradar.law_fetcher import GDPR, fetch_act_html, fetch_html

FIXTURES = Path(__file__).parent / "fixtures"
REDIRECT = json.loads((FIXTURES / "cellar_redirect_32016R0679.json").read_text(encoding="utf-8"))
PAGE = (FIXTURES / "gdpr_it_excerpt.html").read_text(encoding="utf-8")
HTTPS_TARGET = REDIRECT["headers"]["Location"].replace("http://", "https://", 1)


def _cellar(seen: list[str]) -> httpx.Client:
    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.scheme != "https":
            return httpx.Response(599)
        if str(request.url) == REDIRECT["request"]:
            return httpx.Response(REDIRECT["status"], headers=REDIRECT["headers"])
        if str(request.url) == HTTPS_TARGET:
            return httpx.Response(200, text=PAGE, headers={"Content-Type": REDIRECT["headers"]["Content-Type"]})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(answer))


def test_the_recorded_redirect_points_to_plain_http():
    """What the fix answers to, so that the test cannot pass for a fixture that
    no longer shows it."""
    assert REDIRECT["status"] == 303
    assert REDIRECT["headers"]["Location"].startswith("http://publications.europa.eu/")


def test_a_redirect_to_http_is_followed_over_https():
    seen: list[str] = []
    text = fetch_html(REDIRECT["request"], client=_cellar(seen))
    assert seen == [REDIRECT["request"], HTTPS_TARGET]
    assert text == PAGE


def test_no_request_of_an_act_goes_out_in_clear(monkeypatch):
    """Through the public entry point, with the headers Cellar negotiates on.
    conftest swaps fetch_html out so that no test reaches the network; this one
    puts the real function back, because the client it passes answers only from
    the recordings."""
    from mailradar import law_fetcher

    monkeypatch.setattr(law_fetcher, "fetch_html", fetch_html)
    seen: list[str] = []
    assert GDPR.celex == "32016R0679"
    assert fetch_act_html(GDPR, "IT", client=_cellar(seen)) == PAGE
    assert all(url.startswith("https://") for url in seen), seen
