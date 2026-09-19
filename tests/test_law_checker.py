"""Tests for mapping MailRadar findings to GDPR provisions."""
from datetime import datetime, timezone

import pytest

from mailradar import law_fetcher
from mailradar.checker import (
    DKIMResult, DMARCResult, DomainReport, GPGResult, MTASTSResult, SPFResult,
)
from mailradar.law_cache import LawCache
from mailradar.law_checker import (
    FINDING_ARTICLES,
    FINDING_TITLES,
    NIS2_SCOPE_NOTE,
    Citation,
    check,
    findings_of,
    format_citation,
    notes_of,
)
from mailradar.law_fetcher import GDPR, NIS2, LawFetchError, Provision

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)


def _report(**overrides):
    """A domain with nothing to report; overrides add the weaknesses."""
    parts = dict(
        dmarc=DMARCResult(present=True, policy="reject"),
        spf=SPFResult(present=True, all_mechanism="-all", permissive=False),
        dkim=DKIMResult(present=True, selector="default", key_bits=2048),
        mta_sts=MTASTSResult(present=True, mode="enforce"),
        gpg=GPGResult(found=True),
    )
    parts.update(overrides)
    return DomainReport(domain="example.com", **parts)


def _fake_fetch(suffix=""):
    calls = []

    def fake(act, articles, now=None, **kwargs):
        calls.append((act, articles))
        stamp = law_fetcher.utc_stamp(now)
        refs = {ref for pairs in FINDING_ARTICLES.values() for _, ref in pairs}
        return {
            ref: Provision.from_text(ref, f"testo di {ref}{suffix}", stamp, act.celex)
            for ref in refs if ref.split("(")[0] in articles
        }

    fake.calls = calls
    return fake


@pytest.fixture
def cache(tmp_path):
    return LawCache(tmp_path / "law_cache.json")


@pytest.fixture
def online(monkeypatch):
    fake = _fake_fetch()
    monkeypatch.setattr(law_fetcher, "fetch_provisions", fake)
    return fake.calls


# ─── mapping ──────────────────────────────────────────────────────────────────

def test_mapping():
    assert FINDING_ARTICLES == {
        "dmarc_missing": ((GDPR, "32"), (NIS2, "21")),
        "spf_dkim_weak": ((GDPR, "32"),),
        "cleartext": ((GDPR, "32(1)(a)"), (NIS2, "21")),
        "cleartext_testing": ((GDPR, "32(1)(a)"),),
        "gpg_missing": ((GDPR, "32"),),
    }
    assert set(FINDING_TITLES) == set(FINDING_ARTICLES)


def test_secure_domain_has_no_findings():
    assert findings_of(_report()) == {}


def test_dmarc_missing():
    assert findings_of(_report(dmarc=DMARCResult(present=False))) == {
        "dmarc_missing": ["nessun record DMARC"],
    }


def test_dmarc_policy_none_is_not_missing():
    assert findings_of(_report(dmarc=DMARCResult(present=True, policy="none"))) == {}


@pytest.mark.parametrize("spf, dkim, evidence", [
    (SPFResult(present=False), None, ["nessun record SPF"]),
    (SPFResult(present=True, all_mechanism="~all", permissive=True), None, ["SPF ~all"]),
    (None, DKIMResult(present=False), ["nessuna chiave DKIM con i selettori comuni"]),
    (None, DKIMResult(present=True, key_bits=1024), ["DKIM 1024 bit"]),
    (SPFResult(present=True, all_mechanism="+all", permissive=True),
     DKIMResult(present=True, key_bits=512), ["SPF +all", "DKIM 512 bit"]),
])
def test_spf_dkim_weak(spf, dkim, evidence):
    overrides = {k: v for k, v in (("spf", spf), ("dkim", dkim)) if v is not None}
    assert findings_of(_report(**overrides)) == {"spf_dkim_weak": evidence}


def test_cleartext_without_mta_sts():
    assert findings_of(_report(mta_sts=MTASTSResult(present=False))) == {
        "cleartext": ["MTA-STS assente: TLS non obbligatorio in ricezione"],
    }


def test_mta_sts_testing_is_cleartext_without_nis2():
    # NIS2 is cited for MTA-STS absent; testing mode only for GDPR art. 32(1)(a)
    found = findings_of(_report(mta_sts=MTASTSResult(present=True, mode="testing")))
    assert found == {"cleartext_testing": ["MTA-STS in modalità testing, non enforce"]}


@pytest.mark.parametrize("overrides", [
    dict(dmarc=DMARCResult(present=False)),
    dict(mta_sts=MTASTSResult(present=False)),
])
def test_nis2_scope_is_noted_when_nis2_is_cited(overrides):
    assert notes_of(_report(**overrides)) == [NIS2_SCOPE_NOTE]
    assert "soggetti essenziali e importanti" in NIS2_SCOPE_NOTE


@pytest.mark.parametrize("overrides", [
    {},
    dict(gpg=GPGResult(found=False)),
    dict(mta_sts=MTASTSResult(present=True, mode="testing")),
])
def test_no_nis2_note_without_nis2(overrides):
    assert notes_of(_report(**overrides)) == []


def test_gpg_missing():
    assert findings_of(_report(gpg=GPGResult(found=False))) == {
        "gpg_missing": ["nessuna chiave pubblica sui keyserver"],
    }


def test_findings_in_report_order():
    report = DomainReport(domain="example.com")   # every check failed
    assert list(findings_of(report)) == ["dmarc_missing", "spf_dkim_weak", "cleartext", "gpg_missing"]


# ─── check ────────────────────────────────────────────────────────────────────

def test_no_findings_no_download(cache, online):
    law = check(_report(), cache=cache, now=DAY1)
    assert law.citations == []
    assert online == []
    assert not cache.path.exists()


def test_all_findings_cite_gdpr_and_nis2(cache, online):
    law = check(DomainReport(domain="example.com"), cache=cache, now=DAY1)

    assert [(c.finding, c.law, c.article) for c in law.citations] == [
        ("dmarc_missing", "GDPR", "32"),
        ("dmarc_missing", "NIS2 dir. 2022/2555", "21"),
        ("spf_dkim_weak", "GDPR", "32"),
        ("cleartext", "GDPR", "32(1)(a)"),
        ("cleartext", "NIS2 dir. 2022/2555", "21"),
        ("gpg_missing", "GDPR", "32"),
    ]
    # Each act is downloaded once, for all the findings citing it
    assert online == [(GDPR, ("32",)), (NIS2, ("21",))]
    assert [s.source for s in law.acts] == ["verified", "verified"]
    assert law.notes == [NIS2_SCOPE_NOTE]
    assert law.citations[0].version_date == "2026-09-19"
    assert law.evidence["dmarc_missing"] == ["nessun record DMARC"]


def test_second_audit_same_text_keeps_version_date(cache, online):
    check(_report(gpg=GPGResult(found=False)), cache=cache, now=DAY1)
    law = check(_report(gpg=GPGResult(found=False)), cache=cache, now=DAY2)

    assert law.changed == {}
    assert law.citations[0].version_date == "2026-09-19"


def test_second_audit_changed_text(cache, monkeypatch):
    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch())
    first = check(_report(gpg=GPGResult(found=False)), cache=cache, now=DAY1)

    monkeypatch.setattr(law_fetcher, "fetch_provisions", _fake_fetch(" (rettificato)"))
    law = check(_report(gpg=GPGResult(found=False)), cache=cache, now=DAY2)

    assert law.changed == {"GDPR art. 32": first.citations[0].sha256}
    assert law.citations[0].sha256 != first.citations[0].sha256
    assert law.citations[0].version_date == "2026-10-01"


def test_offline_uses_cache(cache, online, monkeypatch):
    first = check(_report(dmarc=DMARCResult(present=False)), cache=cache, now=DAY1)

    def offline(*args, **kwargs):
        raise LawFetchError("offline")

    monkeypatch.setattr(law_fetcher, "fetch_provisions", offline)
    law = check(_report(dmarc=DMARCResult(present=False)), cache=cache, now=DAY2)

    assert [(s.source, s.error) for s in law.acts] == [("cache", "offline"), ("cache", "offline")]
    assert law.citations[0].sha256 == first.citations[0].sha256
    assert law.citations[0].version_date == "2026-09-19"


def test_offline_without_cache(cache):
    # conftest makes every download fail
    law = check(_report(dmarc=DMARCResult(present=False)), cache=cache, now=DAY1)

    assert [s.source for s in law.acts] == ["unavailable", "unavailable"]
    assert law.citations[0].sha256 is None


def test_default_cache_location(tmp_path, online):
    check(_report(gpg=GPGResult(found=False)), now=DAY1)
    assert (tmp_path / "mailradar-home" / "law_cache.json").is_file()


def test_format_citation():
    c = Citation("cleartext", "GDPR", "32(1)(a)", "ab" * 32, "2026-09-19")
    assert format_citation(c) == (
        "Norma applicata: GDPR art. 32(1)(a)\n"
        f"SHA256: {'ab' * 32}\n"
        "Versione del: 2026-09-19"
    )
