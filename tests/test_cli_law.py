"""Tests for the law check that `mailradar check` and `mailradar report` run."""
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mailradar import law_fetcher
from mailradar.checker import (
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    SPFResult,
)
from mailradar.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "gdpr_it_excerpt.html"
NIS2_PAGE = FIXTURES / "nis2_it_excerpt.html"
ART_24_PAGE = FIXTURES / "normattiva_dlgs138_2024_art24_recorded.html"
runner = CliRunner()


def _report(weak=True):
    if weak:
        return DomainReport(domain="example.com", total_score=20, grade="CRITICAL")
    return DomainReport(
        domain="example.com",
        dmarc=DMARCResult(present=True, policy="reject"),
        spf=SPFResult(present=True, all_mechanism="-all"),
        dkim=DKIMResult(present=True, key_bits=2048),
        mta_sts=MTASTSResult(present=True, mode="enforce"),
        gpg=GPGResult(found=True),
        total_score=95,
        grade="EXCELLENT",
    )


def _sha(ref, page=FIXTURE):
    article = ref.split("(")[0]
    text = law_fetcher.parse_articles(page.read_text(encoding="utf-8"), (article,))[ref]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def eurlex(monkeypatch):
    calls = []

    def fake_fetch_html(url, **kwargs):
        calls.append(url)
        page = ART_24_PAGE if "normattiva.it" in url else NIS2_PAGE if "32022L2555" in url else FIXTURE
        return page.read_text(encoding="utf-8")

    monkeypatch.setattr(law_fetcher, "fetch_html", fake_fetch_html)
    return calls


def _check(report):
    with patch("mailradar.checker.domain_exists", return_value=True), \
            patch("mailradar.cli.analyze_domain", return_value=report):
        return runner.invoke(app, ["check", "example.com"])


def test_check_cites_article_32(eurlex):
    out = _check(_report())

    assert out.exit_code == 2, out.output   # grade CRITICAL, unchanged
    assert "Provisions applied" in out.output
    assert "DMARC missing" in out.output
    assert "Provision applied: GDPR art. 32\n" in out.output
    assert f"SHA256: {_sha('32')}" in out.output
    assert "Provision applied: GDPR art. 32(1)(a)" in out.output
    assert f"SHA256: {_sha('32(1)(a)')}" in out.output
    assert "Version of: " in out.output
    assert eurlex == [
        "https://publications.europa.eu/resource/celex/32016R0679",
        "https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2024-09-04;138~art24!vig=",
    ]


def test_check_cites_the_italian_nis2_decree_for_dmarc_and_mta_sts(eurlex):
    out = _check(_report())

    assert "Provision applied: D.Lgs. 138/2024 art. 24\n" in out.output
    assert f"SHA256: {_sha('24', ART_24_PAGE)}" in out.output
    flat = " ".join(out.output.split())   # Rich wraps the long URN at 80 columns
    assert ("D.Lgs. 138/2024: verified against Normattiva "
            "(URN urn:nir:stato:decreto.legislativo:2024-09-04;138)") in flat
    assert "GDPR: verified against Cellar (CELEX 32016R0679)" in out.output
    assert "EUR-Lex" not in out.output
    assert "essential and important entities" in out.output


def test_check_shows_evidence(eurlex):
    out = _check(_report())
    assert "no DMARC record" in out.output
    assert "MTA-STS missing" in out.output


def test_secure_domain_cites_nothing(eurlex):
    out = _check(_report(weak=False))

    assert out.exit_code == 0
    assert "Norma applicata" not in out.output
    assert eurlex == []


def test_check_offline_without_cache():
    # conftest makes every download fail
    out = _check(_report())

    assert "Provision applied: GDPR art. 32" in out.output
    assert "SHA256: not available" in out.output


def test_second_check_offline_uses_cache(eurlex, monkeypatch):
    _check(_report())

    def offline(url, **kwargs):
        raise law_fetcher.LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_html", offline)
    out = _check(_report())

    assert "cache" in out.output
    assert f"SHA256: {_sha('32')}" in out.output


def test_law_check_failure_does_not_change_exit_code(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("mailradar.law_checker.check", boom)
    out = _check(_report())

    assert out.exit_code == 2
    assert "unexpected" in out.output


def test_report_command_cites_too(eurlex):
    with patch("mailradar.checker.analyze_domain", return_value=_report()):
        out = runner.invoke(app, ["report", "example.com"])

    assert out.exit_code == 0, out.output
    assert f"SHA256: {_sha('32(1)(a)')}" in out.output
