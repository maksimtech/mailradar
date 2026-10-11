"""Tests for the EUR-Lex fetcher, on an excerpt of the real GDPR page."""
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from mailradar import law_fetcher
from mailradar.law_fetcher import (
    GDPR,
    LawFetchError,
    Provision,
    fetch_provisions,
    parse_articles,
)
from mailradar.law_fetcher import (
    fetch_html as real_fetch_html,
)

FIXTURES = Path(__file__).parent / "fixtures"
GDPR_PAGE = FIXTURES / "gdpr_it_excerpt.html"
NOW = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)

ARTICLES = ("32", "33")
POINT_REF, POINT_TEXT = ("32(1)(a)", "a) la pseudonimizzazione e la cifratura dei dati personali;")


@pytest.fixture(scope="module")
def page():
    return GDPR_PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def texts(page):
    return parse_articles(page, ARTICLES)


# ─── parse_articles ───────────────────────────────────────────────────────────

def test_point_text(texts):
    assert texts[POINT_REF] == POINT_TEXT


def test_every_article_has_paragraphs(texts):
    for article in ARTICLES:
        assert texts[f"{article}(1)"].startswith("1. ")
        assert texts[article].split("\n")[0] == texts[f"{article}(1)"]


def test_paragraph_includes_its_points(texts):
    paragraph = POINT_REF.rsplit("(", 1)[0]
    assert POINT_TEXT in texts[paragraph]


def test_article_text_leaves_out_number_and_title(texts):
    for article in ARTICLES:
        assert f"Articolo {article}" not in texts[article]


def test_whitespace_is_normalized(texts):
    for text in texts.values():
        assert "\xa0" not in text
        assert "  " not in text
        assert text == text.strip()


def test_only_requested_articles(page):
    first = ARTICLES[0]
    texts = parse_articles(page, (first,))
    assert all(ref == first or ref.startswith(f"{first}(") for ref in texts)


def test_missing_article_raises(page):
    with pytest.raises(LawFetchError, match="99"):
        parse_articles(page, (ARTICLES[0], "99"))


def test_page_without_articles_raises():
    # EUR-Lex answers some automated requests with a JavaScript challenge page
    with pytest.raises(LawFetchError):
        parse_articles("<html><body><script>challenge()</script></body></html>", ARTICLES)


# ─── fetch_html ───────────────────────────────────────────────────────────────

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_fetch_html_returns_page():
    client = _client(lambda request: httpx.Response(200, text="<html>ok</html>"))
    assert real_fetch_html("https://eur-lex.europa.eu/x", client=client) == "<html>ok</html>"


@pytest.mark.parametrize("status", [202, 404, 503])
def test_fetch_html_rejects_non_200(status):
    client = _client(lambda request: httpx.Response(status, text="challenge"))
    with pytest.raises(LawFetchError, match=str(status)):
        real_fetch_html("https://eur-lex.europa.eu/x", client=client)


def test_fetch_html_network_error():
    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    with pytest.raises(LawFetchError, match="offline"):
        real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))


def test_fetch_html_sends_user_agent():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers["user-agent"]
        return httpx.Response(200, text="ok")

    real_fetch_html("https://eur-lex.europa.eu/x", client=_client(handler))
    assert seen["ua"].startswith("MailRadar/")


# ─── fetch_provisions ─────────────────────────────────────────────────────────

def test_fetch_provisions(page, monkeypatch):
    urls = []

    def fake_fetch_html(url, **kwargs):
        urls.append(url)
        return page

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    provisions = fetch_provisions(GDPR, ARTICLES, now=NOW)

    assert urls == ["https://publications.europa.eu/resource/celex/32016R0679"]
    p = provisions[POINT_REF]
    assert isinstance(p, Provision)
    assert p.article == POINT_REF
    assert p.text == POINT_TEXT
    assert p.sha256 == hashlib.sha256(POINT_TEXT.encode("utf-8")).hexdigest()
    assert p.fetched_at == "2026-09-19T14:00:00Z"
    assert p.celex == "32016R0679"
    assert p.key == ("32016R0679", POINT_REF)


def test_provision_dict_round_trip():
    p = Provision.from_text("32(1)(a)", "a) testo;", "2026-09-19T14:00:00Z", "32016R0679")
    assert p.to_dict() == {
        "article": "32(1)(a)",
        "text": "a) testo;",
        "sha256": hashlib.sha256(b"a) testo;").hexdigest(),
        "fetched_at": "2026-09-19T14:00:00Z",
        "celex": "32016R0679",
    }
    assert Provision.from_dict(p.to_dict()) == p


# ─── where the text comes from ────────────────────────────────────────────────

def test_cellar_is_tried_first(monkeypatch):
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(GDPR, "IT")

    assert len(seen) == 1
    assert "publications.europa.eu" in seen[0]
    assert GDPR.celex in seen[0]


def test_the_web_interface_is_the_fallback(monkeypatch):
    """Kept, because a WAF rule can be relaxed again."""
    seen = []

    def fake(url, **kwargs):
        seen.append(url)
        if "publications.europa.eu" in url:
            raise LawFetchError("Cellar answered HTTP 500")
        return "<html>fallback</html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    assert law_fetcher.fetch_act_html(GDPR, "IT") == "<html>fallback</html>"

    assert len(seen) == 2
    assert "eur-lex.europa.eu" in seen[1]


def test_both_sources_failing_names_both(monkeypatch):
    """An error that says only "unreachable" costs a debugging session."""
    def fake(url, **kwargs):
        raise LawFetchError("HTTP 202" if "publications" in url else "HTTP 403")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    with pytest.raises(LawFetchError) as caught:
        law_fetcher.fetch_act_html(GDPR, "IT")

    assert "202" in str(caught.value)
    assert "403" in str(caught.value)


def test_the_language_reaches_cellar_as_a_three_letter_code(monkeypatch):
    """Cellar negotiates on Accept-Language and wants "ita", not "IT"."""
    seen = {}

    def fake(url, **kwargs):
        seen.update(kwargs.get("headers") or {})
        return "<html></html>"

    monkeypatch.setattr(law_fetcher, "fetch_html", fake)
    law_fetcher.fetch_act_html(GDPR, "IT")

    assert seen["Accept-Language"] == "ita"
    assert seen["Accept"] == law_fetcher.CELLAR_TYPE


def test_an_error_from_cellar_names_cellar():
    client = _client(lambda request: httpx.Response(503))
    with pytest.raises(LawFetchError, match="Cellar answered HTTP 503"):
        real_fetch_html("https://publications.europa.eu/resource/celex/x", client=client)


# ─── HTTPS→HTTP redirect upgrade ──────────────────────────────────────────────

# publications.europa.eu responds to the Cellar URL with 303 → http://; the
# content is identical at the https:// equivalent. fetch_html must upgrade.

# A resolved Cellar URL looks like this (measured 2026-10-11):
_CELLAR_HTTP = "http://publications.europa.eu/resource/cellar/resolved-content"
_CELLAR_HTTPS = "https://publications.europa.eu/resource/cellar/resolved-content"


def _cellar_redirect_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == "https://publications.europa.eu/resource/celex/32016R0679":
        # Real Cellar behaviour: 303 → http:// (scheme downgrade)
        return httpx.Response(303, headers={"Location": _CELLAR_HTTP})
    if url == _CELLAR_HTTP:
        # httpx follows the 303 and lands here: cleartext
        return httpx.Response(200, text="<html>http-content</html>")
    if url == _CELLAR_HTTPS:
        # Our fix re-requests with https://: TLS-verified content
        return httpx.Response(200, text="<html>https-content</html>")
    return httpx.Response(404)


def test_cellar_http_redirect_is_upgraded_to_https():
    """fetch_html must not accept content delivered over http://."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return _cellar_redirect_handler(request)

    client = _client(handler)
    result = real_fetch_html(
        "https://publications.europa.eu/resource/celex/32016R0679", client=client
    )

    # Content must come from the https:// re-request, not the http:// redirect target
    assert result == "<html>https-content</html>"
    # The last request the client made must be https://
    assert seen[-1] == _CELLAR_HTTPS
    # http:// was visited (httpx followed the 303), but we did not return that body
    assert _CELLAR_HTTP in seen


def test_non_https_origin_does_not_trigger_upgrade():
    """Redirect from http:// to http:// (e.g. Normattiva) is accepted as-is."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == "http://normattiva.it/x":
            return httpx.Response(301, headers={"Location": "http://normattiva.it/resolved"})
        return httpx.Response(200, text="<html>ok</html>")

    client = _client(handler)
    result = real_fetch_html("http://normattiva.it/x", client=client)

    assert result == "<html>ok</html>"
    # No https:// re-request: origin was already http
    assert len(seen) == 2  # original + redirect target


def test_https_to_https_redirect_is_not_re_requested():
    """A redirect that stays on https:// must not cause a double request."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url).endswith("/x"):
            return httpx.Response(301, headers={"Location": "https://eur-lex.europa.eu/y"})
        return httpx.Response(200, text="<html>ok</html>")

    client = _client(handler)
    result = real_fetch_html("https://eur-lex.europa.eu/x", client=client)

    assert result == "<html>ok</html>"
    assert seen == ["https://eur-lex.europa.eu/x", "https://eur-lex.europa.eu/y"]
