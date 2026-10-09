"""Tests for mapping MailRadar findings to GDPR provisions."""
from datetime import UTC, datetime

import pytest

from mailradar import law_fetcher
from mailradar.checker import (
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    SPFResult,
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

DAY1 = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


def _report(**overrides):
    """A domain with nothing to report; overrides add the weaknesses."""
    parts = {
        "dmarc": DMARCResult(present=True, policy="reject"),
        "spf": SPFResult(present=True, all_mechanism="-all", permissive=False),
        "dkim": DKIMResult(present=True, selector="default", key_bits=2048),
        "mta_sts": MTASTSResult(present=True, mode="enforce"),
        "gpg": GPGResult(found=True),
    }
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
        "dmarc_missing": ["no DMARC record"],
    }


def test_dmarc_policy_none_is_not_missing():
    assert findings_of(_report(dmarc=DMARCResult(present=True, policy="none"))) == {}


@pytest.mark.parametrize("spf, dkim, evidence", [
    (SPFResult(present=False), None, ["no SPF record"]),
    (SPFResult(present=True, all_mechanism="~all", permissive=True), None, ["SPF ~all"]),
    (None, DKIMResult(present=True, key_bits=1024), ["DKIM 1024 bit"]),
    (SPFResult(present=True, all_mechanism="+all", permissive=True),
     DKIMResult(present=True, key_bits=512), ["SPF +all", "DKIM 512 bit"]),
])
def test_spf_dkim_weak(spf, dkim, evidence):
    overrides = {k: v for k, v in (("spf", spf), ("dkim", dkim)) if v is not None}
    assert findings_of(_report(**overrides)) == {"spf_dkim_weak": evidence}


def test_spf_permerror_is_weak_spf():
    """Receivers apply no SPF to a record in permerror: cited as weak SPF, not passed over."""
    found = findings_of(_report(spf=SPFResult(present=True, permerror=True, raw="v=spf1 -all")))
    assert any("permerror" in w for w in found.get("spf_dkim_weak", []))


def test_unverified_dmarc_is_not_dmarc_missing():
    """A DMARC lookup that timed out says nothing either way: there is nothing to cite."""
    dmarc = DMARCResult(error="DNS lookup for _dmarc.example.com failed: Timeout")
    assert "dmarc_missing" not in findings_of(_report(dmarc=dmarc))


def test_ed25519_dkim_key_is_not_weak():
    """RFC 8463: 256 bits of Ed25519 are not a short RSA key (what check_dkim returns for one)."""
    dkim = DKIMResult(present=True, selector="default", key_type="ed25519", key_bits=256, score=15)
    weak = findings_of(_report(dkim=dkim)).get("spf_dkim_weak", [])
    assert not any("DKIM" in w for w in weak)


def test_cleartext_without_mta_sts():
    assert findings_of(_report(mta_sts=MTASTSResult(present=False))) == {
        "cleartext": ["MTA-STS missing: TLS not mandatory on delivery"],
    }


def test_mta_sts_testing_is_cleartext_without_nis2():
    # NIS2 is cited for MTA-STS absent; testing mode only for GDPR art. 32(1)(a)
    found = findings_of(_report(mta_sts=MTASTSResult(present=True, mode="testing")))
    assert found == {"cleartext_testing": ["MTA-STS in testing mode, not enforce"]}


@pytest.mark.parametrize("overrides", [
    {"dmarc": DMARCResult(present=False)},
    {"mta_sts": MTASTSResult(present=False)},
])
def test_nis2_scope_is_noted_when_nis2_is_cited(overrides):
    assert notes_of(_report(**overrides)) == [NIS2_SCOPE_NOTE]
    assert "essential and important entities" in NIS2_SCOPE_NOTE


@pytest.mark.parametrize("overrides", [
    {},
    {"gpg": GPGResult(found=False)},
    {"mta_sts": MTASTSResult(present=True, mode="testing")},
])
def test_no_nis2_note_without_nis2(overrides):
    assert notes_of(_report(**overrides)) == []


def test_gpg_missing():
    assert findings_of(_report(gpg=GPGResult(found=False))) == {
        "gpg_missing": ["no public key on the keyservers"],
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
    assert law.evidence["dmarc_missing"] == ["no DMARC record"]


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
        "Provision applied: GDPR art. 32(1)(a)\n"
        f"SHA256: {'ab' * 32}\n"
        "Version of: 2026-09-19"
    )


def test_gpg_not_verified_is_not_gpg_missing():
    """A keyserver that answered HTTP 429 proved nothing: GDPR art. 32 is not cited for a key that may exist."""
    unverified = GPGResult(found=False, error="keys.openpgp.org: HTTP 429")
    assert "gpg_missing" not in findings_of(_report(gpg=unverified))


def test_dkim_not_found_under_common_selectors_is_not_evidence(dns_replay):
    """amazon.it publishes none of the 33 common selectors and signs its mail under selectors of its own
    (recorded 2026-10-09): DNS cannot show DKIM absent, so there is no weakness to cite GDPR art. 32 for.
    Until 2026-10-09 the report to proton.me cited it for the same reason, over keys that exist."""
    from mailradar.checker import check_dkim
    dns_replay("amazon_it")
    assert findings_of(_report(dkim=check_dkim("amazon.it"))) == {}
