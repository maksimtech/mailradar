"""The law check end to end, over real sockets.

httpx talks to tests/replay.py's HTTPReplayProxy, which answers with the
responses in tests/fixtures/http/: Cellar's recorded 303 and the GDPR page the
other law tests use, and answers derived from them where a test needs the
service to misbehave. Each fixture says what was changed.

What these tests hold the check to: a citation is "verified" only when the
reference it cites was in the text downloaded now, from the host it was asked
of; anything else falls back to the cache, labelled as such, and the status
says which source was tried and why it was not used.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mailradar import law_fetcher
from mailradar.checker import DKIMResult, DMARCResult, DomainReport, GPGResult, MTASTSResult, SPFResult
from mailradar.law_cache import LawCache
from mailradar.law_checker import FINDING_ARTICLES, check
from mailradar.law_fetcher import GDPR
from tests.names import mentions

REAL_FETCH_HTML = law_fetcher.fetch_html
DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


@pytest.fixture
def real_fetch(monkeypatch):
    """conftest disables fetch_html so that no test reaches the network; here
    the proxy answers only from the recordings, so the real function goes back."""
    monkeypatch.setattr(law_fetcher, "fetch_html", REAL_FETCH_HTML)


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law-cache" / "law_cache.json")


def cleartext_testing() -> DomainReport:
    """MTA-STS in testing mode and nothing else: the one citation is GDPR art. 32(1)(a)."""
    return DomainReport(
        domain="example.com",
        dmarc=DMARCResult(present=True, policy="reject"),
        spf=SPFResult(present=True, all_mechanism="-all", permissive=False),
        dkim=DKIMResult(present=True, selector="default", key_bits=2048),
        mta_sts=MTASTSResult(present=True, mode="testing"),
        gpg=GPGResult(found=True),
    )


# ─── a cited reference must be in the text downloaded now ────────────────────


def test_the_report_cites_only_the_point():
    """What the tests below rely on."""
    assert FINDING_ARTICLES["cleartext_testing"] == ((GDPR, "32(1)(a)"),)


def test_a_point_missing_from_the_fresh_text_is_not_verified(real_fetch, http_replay, cache):
    """Cellar answered and article 32 parsed, but point a) was not in a table:
    the act used to be "verified against Cellar" beside "SHA256: not available"."""
    http_replay("cellar_32016R0679_it_point_a_untabled")
    law = check(cleartext_testing(), cache=cache, now=DAY1)

    [status] = law.acts
    assert status.source == "unavailable", status
    assert "32(1)(a)" in (status.error or "")
    assert law.citations[0].sha256 is None


def test_a_cached_point_is_not_served_as_verified(real_fetch, http_replay, cache):
    """The same, with the point cached by an earlier audit: its old SHA-256 and
    date came back under the "verified" label."""
    http_replay("cellar_32016R0679_it")
    first = check(cleartext_testing(), cache=cache, now=DAY1)
    assert [s.source for s in first.acts] == ["verified"]
    assert first.citations[0].sha256 is not None

    http_replay("cellar_32016R0679_it_point_a_untabled")
    law = check(cleartext_testing(), cache=cache, now=DAY2)

    [status] = law.acts
    assert status.source == "cache", status
    assert law.citations[0].sha256 == first.citations[0].sha256
    assert law.citations[0].version_date == "2026-09-19"


# ─── any failure to fetch is a LawFetchError, so the fallbacks apply ────────

CELLAR_GDPR = "https://publications.europa.eu/resource/celex/32016R0679"


def test_a_redirect_httpx_cannot_follow_is_a_fetch_error(real_fetch, http_replay):
    """http://xn--/DOC_1 makes httpx raise idna.core.IDNAError, which is no
    httpx.HTTPError: it went past both fallbacks and out of check()."""
    http_replay("cellar_redirect_32016R0679_bad_host")
    with pytest.raises(law_fetcher.LawFetchError, match="Cellar"):
        law_fetcher.fetch_html(CELLAR_GDPR)


def test_then_eur_lex_is_tried(real_fetch, http_replay, cache):
    http_replay("cellar_redirect_32016R0679_bad_host", "eurlex_32016R0679_it")
    law = check(cleartext_testing(), cache=cache, now=DAY1)

    assert [(s.source, s.origin) for s in law.acts] == [("verified", "EUR-Lex")]


def test_then_the_cache(real_fetch, http_replay, cache):
    http_replay("cellar_32016R0679_it")
    first = check(cleartext_testing(), cache=cache, now=DAY1)

    http_replay("cellar_redirect_32016R0679_bad_host", "eurlex_32016R0679_waf_202")
    law = check(cleartext_testing(), cache=cache, now=DAY2)

    assert [s.source for s in law.acts] == ["cache"]
    assert law.citations[0].sha256 == first.citations[0].sha256


# ─── redirects stay on the source's host ─────────────────────────────────────


def test_a_redirect_to_another_host_is_not_followed(real_fetch, http_replay):
    """The text example.org serves is not Cellar's, whatever Cellar's 303 says."""
    proxy = http_replay("cellar_redirect_32016R0679_other_host")
    with pytest.raises(law_fetcher.LawFetchError, match="example.org"):
        law_fetcher.fetch_html(CELLAR_GDPR)
    assert not any(mentions(request, "example.org") for request in proxy.requests), proxy.requests


def test_a_text_from_another_host_is_not_verified_against_cellar(real_fetch, http_replay, cache):
    http_replay("cellar_redirect_32016R0679_other_host", "eurlex_32016R0679_waf_202")
    law = check(cleartext_testing(), cache=cache, now=DAY1)

    assert [(s.source, s.origin) for s in law.acts] == [("unavailable", None)]


# ─── errors and statuses name the source that was tried ──────────────────────


def test_an_article_missing_from_normattiva_names_normattiva(real_fetch, http_replay):
    http_replay("normattiva_cdc_art99_another_page")
    with pytest.raises(law_fetcher.LawFetchError) as caught:
        law_fetcher.fetch_provisions_from(law_fetcher.CONSUMER_CODE, ("99",))

    assert "Normattiva" in str(caught.value)
    assert "EUR-Lex" not in str(caught.value)


def test_an_article_missing_from_cellar_names_cellar(real_fetch, http_replay):
    http_replay("cellar_32016R0679_it")
    with pytest.raises(law_fetcher.LawFetchError) as caught:
        law_fetcher.fetch_provisions_from(GDPR, ("99",))

    assert "Cellar" in str(caught.value)
    assert "EUR-Lex" not in str(caught.value)


def test_a_status_says_the_source_answered_without_the_text(real_fetch, http_replay, cache):
    """The CLI printed "EUR-Lex unreachable" for this: Cellar was reached, and
    only the reference cited was missing from its page."""
    http_replay("cellar_32016R0679_it")
    check(cleartext_testing(), cache=cache, now=DAY1)
    http_replay("cellar_32016R0679_it_point_a_untabled")
    [status] = check(cleartext_testing(), cache=cache, now=DAY2).acts

    assert (status.source, status.tried, status.failure) == ("cache", "Cellar", "not_in_text")
    assert status.reason == "Cellar answered without the text cited"


def test_a_status_names_both_sources_when_neither_answered(real_fetch, http_replay, cache):
    http_replay("cellar_redirect_32016R0679_other_host", "eurlex_32016R0679_waf_202")
    [status] = check(cleartext_testing(), cache=cache, now=DAY1).acts

    assert (status.source, status.tried, status.failure) == ("unavailable", "Cellar and EUR-Lex", "unreachable")
    assert status.reason == "Cellar and EUR-Lex unreachable"


def test_a_verified_status_has_no_reason(real_fetch, http_replay, cache):
    http_replay("cellar_32016R0679_it")
    [status] = check(cleartext_testing(), cache=cache, now=DAY1).acts

    assert (status.source, status.tried, status.failure, status.reason) == ("verified", None, None, None)
