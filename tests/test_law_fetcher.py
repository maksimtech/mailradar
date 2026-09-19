"""Tests for the EUR-Lex fetcher, on an excerpt of the real GDPR page."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from mailradar import law_fetcher
from mailradar.law_fetcher import (
    GDPR,
    LawFetchError,
    Provision,
    fetch_html as real_fetch_html,
    fetch_provisions,
    parse_articles,
)

FIXTURES = Path(__file__).parent / "fixtures"
GDPR_PAGE = FIXTURES / "gdpr_it_excerpt.html"
NOW = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)

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
    return httpx.Client(transport=httpx.MockTransport(handler))


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

    assert urls == ["https://eur-lex.europa.eu/legal-content/IT/TXT/HTML/?uri=CELEX:32016R0679"]
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
        "sha256": hashlib.sha256("a) testo;".encode("utf-8")).hexdigest(),
        "fetched_at": "2026-09-19T14:00:00Z",
        "celex": "32016R0679",
    }
    assert Provision.from_dict(p.to_dict()) == p
