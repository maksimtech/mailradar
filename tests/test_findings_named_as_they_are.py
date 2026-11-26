"""
What the output calls a finding, once the bug-fix pass of 2026-11-17 changed
what the checks find. Each part was fixed in its own module; these are the
places where one module's new answer reached another module's old wording:

- a DKIM key that cannot be used (malformed, or only in testing mode) scores 0,
  and the table, the letter and the citations still described it by its length
  ("0-bit RSA", with a ✅, and "DKIM 0 bit" as an art. 32 weakness);
- a pass /0 range makes an SPF record with -all permissive, and the citation
  listed "SPF -all" as the weakness, which reads as the remedy;
- a law text that was reached but lacked the point cited was reported as
  "EUR-Lex unreachable", whichever source had been tried;
- a name DNS cannot hold was answered with "try again, or with another resolver".
"""
from __future__ import annotations

import re

import pytest
from rich.console import Console
from typer.testing import CliRunner

from mailradar import cli
from mailradar.checker import (
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    SPFResult,
)
from mailradar.law_checker import ActStatus, LawCheckResult, findings_of
from mailradar.law_fetcher import GDPR
from mailradar.reporter import generate_report

MALFORMED = DKIMResult(present=True, selector="s1", key_bits=0, key_type="rsa",
                       keys={"s1": "malformed RSA key"}, score=0,
                       issues=["DKIM key under s1 is malformed (no p= tag) — signatures cannot be verified"])
TESTING_ONLY = DKIMResult(present=True, selector="s1", key_bits=2048, key_type="rsa",
                          keys={"s1": "2048-bit RSA (testing, t=y)"}, score=0,
                          issues=["DKIM key under s1 is in testing mode (t=y)"])


def _report(**overrides) -> DomainReport:
    parts = {
        "dmarc": DMARCResult(present=True, policy="reject", score=50),
        "spf": SPFResult(present=True, all_mechanism="-all", score=20),
        "dkim": DKIMResult(present=True, selector="s1", key_bits=2048, keys={"s1": "2048-bit RSA"}, score=15),
        "mta_sts": MTASTSResult(present=True, mode="enforce", score=5),
        "gpg": GPGResult(found=True),
    }
    parts.update(overrides)
    return DomainReport(domain="example.com", total_score=70, grade="GOOD", **parts)


def _printed(report: DomainReport, monkeypatch) -> str:
    console = Console(width=200, force_terminal=False, color_system=None, emoji=False, highlight=False)
    monkeypatch.setattr(cli, "console", console)
    with console.capture() as capture:
        cli._print_report(report)
    return capture.get()


def _dkim_row(printed: str) -> str:
    return next(line for line in printed.splitlines() if line.startswith("│ DKIM"))


# ─── a DKIM key that cannot be used ──────────────────────────────────────────

def test_the_table_names_a_malformed_key_and_does_not_tick_it(monkeypatch):
    row = _dkim_row(_printed(_report(dkim=MALFORMED), monkeypatch))
    assert "malformed RSA key" in row
    assert "0-bit" not in row
    assert "✅" not in row


def test_the_table_names_a_key_that_only_tests(monkeypatch):
    row = _dkim_row(_printed(_report(dkim=TESTING_ONLY), monkeypatch))
    assert "testing, t=y" in row
    assert "✅" not in row


def test_the_letter_names_a_malformed_key():
    letter = generate_report(_report(dkim=MALFORMED), lang="en")
    assert "malformed RSA key" in letter
    assert "0-bit" not in letter


def test_an_unusable_key_is_a_weakness_by_what_it_is_not_its_length():
    weak = findings_of(_report(dkim=MALFORMED))["spf_dkim_weak"]
    assert weak == ["DKIM malformed RSA key"]
    assert findings_of(_report(dkim=TESTING_ONLY))["spf_dkim_weak"] == ["DKIM 2048-bit RSA (testing, t=y)"]


def test_a_short_key_is_still_a_weakness_by_its_length():
    short = DKIMResult(present=True, selector="s1", key_bits=1024, keys={"s1": "1024-bit RSA"}, score=10)
    assert findings_of(_report(dkim=short))["spf_dkim_weak"] == ["DKIM 1024 bit"]


# ─── an SPF record that -all does not close ──────────────────────────────────

def test_a_permissive_record_with_minus_all_is_not_cited_as_minus_all():
    """A pass ip4:0.0.0.0/0 before -all authorises every address: the weakness is
    that, and "SPF -all" would read as the remedy."""
    spf = SPFResult(present=True, all_mechanism="-all", permissive=True, score=0,
                    issues=["SPF ip4:0.0.0.0/0 authorises every address — the same as +all"])
    weak = findings_of(_report(spf=spf))["spf_dkim_weak"]
    assert weak == ["SPF authorises every address before -all"]


def test_a_softfail_is_still_cited_by_its_all():
    """Where DMARC does not enforce: under p=reject it is not a weakness (#141)."""
    spf = SPFResult(present=True, all_mechanism="~all", permissive=True, score=10)
    dmarc = DMARCResult(present=True, policy="none", score=10)
    assert findings_of(_report(spf=spf, dmarc=dmarc))["spf_dkim_weak"] == ["SPF ~all"]


# ─── ~all under an enforcing DMARC policy (mailradar#141) ────────────────────

SOFTFAIL = SPFResult(present=True, all_mechanism="~all", permissive=True, score=10,
                     issues=["SPF uses ~all (softfail) — consider -all (hardfail)"])


def test_softfail_under_reject_is_not_a_gdpr_art_32_weakness():
    """With p=reject on every message, DMARC decides what happens to a failing
    message, not the SPF qualifier, and RFC 7489 §10.1 warns that -all can make
    a receiver reject at SPF time, before DMARC sees a DKIM signature that would
    have passed: ~all there is a choice, not a gap in security of processing."""
    report = _report(spf=SOFTFAIL, dmarc=DMARCResult(present=True, policy="reject", pct=100, score=50))
    assert "spf_dkim_weak" not in findings_of(report)


def test_softfail_under_reject_keeps_its_score_until_january():
    """The rule of 2026-11-22: on 7 December the false statement goes, the
    score stays; scoring ~all like -all is #154."""
    report = _report(spf=SOFTFAIL, dmarc=DMARCResult(present=True, policy="reject", pct=100, score=50))
    assert report.spf.score == 10
    assert "consider -all" in report.spf.issues[0]


@pytest.mark.parametrize("dmarc", [
    DMARCResult(present=True, policy="none", score=10),
    DMARCResult(present=True, policy="quarantine", score=40),
    DMARCResult(present=True, policy="reject", pct=50, score=50),
    DMARCResult(present=False),
])
def test_softfail_where_dmarc_does_not_reject_every_message_is_still_cited(dmarc):
    assert findings_of(_report(spf=SOFTFAIL, dmarc=dmarc))["spf_dkim_weak"] == ["SPF ~all"]


@pytest.mark.parametrize("spf, dkim, title", [
    (SOFTFAIL, None, "SPF weak"),
    (None, DKIMResult(present=True, selector="s1", key_bits=1024, key_type="rsa",
                      keys={"s1": "1024-bit RSA"}, score=5), "DKIM weak"),
    (SOFTFAIL, DKIMResult(present=True, selector="s1", key_bits=1024, key_type="rsa",
                          keys={"s1": "1024-bit RSA"}, score=5), "SPF/DKIM weak"),
])
def test_the_heading_names_only_what_is_weak(spf, dkim, title):
    """yubico.com, with a 2048-bit DKIM key, was headed "SPF/DKIM weak"."""
    from mailradar.law_checker import finding_title

    overrides = {"dmarc": DMARCResult(present=True, policy="none", score=10)}
    if spf:
        overrides["spf"] = spf
    if dkim:
        overrides["dkim"] = dkim
    found = findings_of(_report(**overrides))
    assert finding_title("spf_dkim_weak", found["spf_dkim_weak"]) == title


def test_a_record_with_no_all_of_its_own_is_cited_in_english():
    spf = SPFResult(present=True, all_mechanism="", permissive=True, score=0)
    assert findings_of(_report(spf=spf))["spf_dkim_weak"] == ["SPF without an all that applies"]


# ─── a law text that was not verified ────────────────────────────────────────

def _law_output(status: ActStatus) -> str:
    console = Console(width=300, force_terminal=False, color_system=None, emoji=False, highlight=False)
    law = LawCheckResult(citations=[], acts=[status], notes=["n"])
    with console.capture() as capture:
        cli._print_law_check(law, out=console)
    return capture.get()


def test_a_source_that_answered_without_the_point_is_not_called_unreachable():
    out = _law_output(ActStatus(act=GDPR, source="cache", tried="Cellar", failure="not_in_text"))
    assert "Cellar answered without the text cited" in out
    assert "unreachable" not in out


def test_both_sources_unreachable_with_nothing_cached_say_which():
    out = _law_output(ActStatus(act=GDPR, source="unavailable", tried="Cellar and EUR-Lex", failure="unreachable"))
    assert "Cellar and EUR-Lex unreachable and nothing cached" in out


# ─── a name DNS cannot hold ──────────────────────────────────────────────────

def test_an_invalid_name_is_not_answered_with_try_another_resolver():
    result = CliRunner().invoke(cli.app, ["check", "a" * 64 + ".com"], env={"COLUMNS": "300"})
    flat = re.sub(r"\s+", " ", result.output)
    assert "not a valid domain name" in flat
    assert "resolver" not in flat
    assert result.exit_code == 64


def test_the_italian_letter_says_it_in_italian():
    letter = generate_report(_report(dkim=MALFORMED), lang="it")
    assert "chiave RSA malformata" in letter
    assert "malformed RSA key" not in letter


def test_the_letter_says_a_key_only_tests():
    assert "(testing, t=y)" in generate_report(_report(dkim=TESTING_ONLY), lang="en")
    assert "(in modalità test, t=y)" in generate_report(_report(dkim=TESTING_ONLY), lang="it")


def test_softfail_with_an_open_range_is_still_a_weakness_under_reject():
    """`ip4:0.0.0.0/0` passes every address whatever the qualifier of `all`."""
    spf = SPFResult(present=True, all_mechanism="~all", permissive=True, score=0,
                    issues=["SPF uses ~all (softfail) — consider -all (hardfail)",
                            "SPF ip4:0.0.0.0/0 passes every IPv4 address, as +all does — "
                            "any server can send as this domain!"])
    report = _report(spf=spf, dmarc=DMARCResult(present=True, policy="reject", pct=100, score=50))
    assert "spf_dkim_weak" in findings_of(report)
