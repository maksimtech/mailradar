"""
The results table and the lists under it: what each cell claims.

Reports are built from the result dataclasses, as the checks return them.
"""
from __future__ import annotations

import re

import pytest
from rich.console import Console

from mailradar import cli
from mailradar.checker import (
    MAX_SCORES,
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    SPFResult,
)


def _lines(report: DomainReport, monkeypatch, color: bool = False) -> list[str]:
    """What _print_report prints for `report`, line by line; with ANSI colours when `color`."""
    console = Console(width=200, force_terminal=color, color_system="standard" if color else None,
                      emoji=False, highlight=False)
    monkeypatch.setattr(cli, "console", console)
    with console.capture() as capture:
        cli._print_report(report)
    return capture.get().splitlines()


def _row(lines: list[str], check: str) -> str:
    """The row of `check`, as printed (colours kept); found by its text without them."""
    return next(line for line in lines if re.sub(r"\x1b\[[0-9;]*m", "", line).startswith(f"│ {check}"))


def _score(row: str) -> str:
    """The last cell of a table row."""
    return row.rstrip().rstrip("│").rsplit("│", 1)[1].strip()


# ─── An unverified check has no score ────────────────────────────────────────

def test_a_check_dns_did_not_answer_shows_no_score(monkeypatch):
    """The Score column said 0 for a lookup that timed out: "not measured" is not zero."""
    report = DomainReport(domain="example.com", total_score=None, grade="N/A")
    report.dmarc = DMARCResult(error="DNS lookup for _dmarc.example.com failed: Timeout")
    assert _score(_row(_lines(report, monkeypatch), "DMARC")) == "—"


def test_a_keyserver_that_did_not_answer_shows_no_score(monkeypatch):
    report = DomainReport(domain="example.com", gpg=GPGResult(error="keys.openpgp.org: HTTP 429"))
    assert _score(_row(_lines(report, monkeypatch), "GPG")) == "—"


def test_a_check_that_answered_shows_its_score(monkeypatch):
    report = DomainReport(domain="example.com", spf=SPFResult(present=True, raw="v=spf1 -all", score=20))
    assert _score(_row(_lines(report, monkeypatch), "SPF")) == "20"


# ─── Each score coloured on its own scale ────────────────────────────────────

RED, BRIGHT_GREEN = "\x1b[31m", "\x1b[92m"


@pytest.mark.parametrize("check,result", [
    ("SPF", SPFResult(present=True, raw="v=spf1 -all", all_mechanism="-all", score=MAX_SCORES["spf"])),
    ("DKIM", DKIMResult(present=True, selector="s", key_bits=2048, score=MAX_SCORES["dkim"])),
    ("GPG", GPGResult(found=True, verified=True, uid="security@example.com", score=MAX_SCORES["gpg"])),
])
def test_a_full_score_is_green_whatever_the_check_s_maximum(monkeypatch, check, result):
    """Scores were coloured on the 0-100 scale of the total: SPF's full 20 came out red."""
    report = DomainReport(domain="example.com")
    setattr(report, {"SPF": "spf", "DKIM": "dkim", "GPG": "gpg"}[check], result)
    row = _row(_lines(report, monkeypatch, color=True), check)
    score_cell = row.rsplit("│", 2)[1]
    assert BRIGHT_GREEN in score_cell, repr(score_cell)
    assert RED not in score_cell


def test_score_cell_colour_is_the_fraction_of_the_check_s_maximum():
    assert cli._check_score_cell("dkim", DKIMResult(present=True, score=10)).style == "yellow"   # 10 of 15
    assert cli._check_score_cell("dmarc", DMARCResult(present=True, score=50)).style == "bright_green"


# ─── SPF notes ───────────────────────────────────────────────────────────────

NOTE = "SPF ip4:192.0.2.98/27 is written from an address inside the range — it authorises all of 192.0.2.96/27"


def test_spf_notes_are_printed_apart_from_the_issues(monkeypatch):
    report = DomainReport(domain="example.com",
                          spf=SPFResult(present=True, raw="v=spf1 ip4:192.0.2.98/27 -all", score=20, notes=[NOTE]))
    out = "\n".join(_lines(report, monkeypatch))
    assert "Issues found" not in out
    assert "Notes" in out
    assert NOTE in out


def test_spf_notes_are_shown_not_obeyed(monkeypatch):
    report = DomainReport(domain="example.com", spf=SPFResult(present=True, notes=["range \x1b[2J here"]))
    out = "\n".join(_lines(report, monkeypatch))
    assert "\x1b" not in out
    assert r"range \x1b[2J here" in out
