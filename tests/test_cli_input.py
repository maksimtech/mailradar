"""
What the commands accept as input, and the exit codes they answer with.

DNS and HTTP are replayed from recordings (tests/replay.py); nothing reaches
the network.
"""
from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from mailradar.cli import app
from tests.names import mentions

ENV = {"COLUMNS": "300"}


def _flat(output: str) -> str:
    """The words of `output`, without Rich's colours: on GitHub Actions Rich colours
    Typer's usage panel, and an option name arrives split between escapes."""
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


# ─── Exit code 64 for usage errors ───────────────────────────────────────────

@pytest.mark.parametrize("args", [
    [],                                      # no command
    ["no-such-command"],
    ["check"],                               # missing argument
    ["check", "example.com", "--no-such-option"],
    ["report", "example.com", "--lang"],     # option without its value
])
def test_a_usage_error_is_not_mistaken_for_a_critical_grade(args):
    """Click exits 2 on a usage error, and 2 is also `check`'s grade CRITICAL: a script could not tell
    "the domain is critical" from "the command line was wrong". 64 is EX_USAGE (sysexits.h)."""
    result = CliRunner().invoke(app, args, env=ENV)
    assert result.exit_code == 64, result.output


# ─── report, send and batch check the name first ─────────────────────────────

NXDOMAIN = "mailradar-nxdomain-test.example.co.uk"   # NXDOMAIN in dept_example_co_uk_exists.json (derived)


def test_report_does_not_grade_a_domain_that_does_not_exist(dns_replay):
    """`report no-such-domain.example` wrote a letter grading it CRITICAL."""
    dns_replay("dept_example_co_uk_exists")
    result = CliRunner().invoke(app, ["report", NXDOMAIN], env=ENV)
    assert result.exit_code == 1, result.output
    assert "not found in DNS" in result.output
    assert "Generating email report" not in result.output


def test_send_does_not_write_to_a_domain_that_does_not_exist(dns_replay, smtp_server, trusted_ca, monkeypatch):
    """...and `send` would have mailed security@ that name."""
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_ca.path))
    server = smtp_server("tls", trusted_ca.server_context("127.0.0.1"))
    dns_replay("dept_example_co_uk_exists")
    result = CliRunner().invoke(app, [
        "send", NXDOMAIN, "--smtp-host", "127.0.0.1", "--smtp-port", str(server.port), "--smtp-user", "a@b.c",
        "--smtp-pass", "x", "--from", "a@b.c", "--name", "N", "--role", "R", "--org", "O"], env=ENV)
    assert result.exit_code == 1, result.output
    assert "not found in DNS" in result.output
    assert server.connections == 0


def test_send_without_an_answer_from_dns_does_not_go_on(dns_replay):
    dns_replay("dept_example_co_uk_exists", silent=["dept.example.co.uk A"])
    result = CliRunner().invoke(app, ["send", "dept.example.co.uk"], env=ENV)
    assert result.exit_code == 1, result.output
    assert "could not be checked" in result.output
    assert "Analyzing" not in result.output


def test_batch_reports_a_domain_that_does_not_exist_as_failed(dns_replay, http_replay, tmp_path):
    dns_replay("startpage_com", "startpage_com_dkim_selectors", "startpage_com_exists", "dept_example_co_uk_exists")
    http_replay("startpage_com", "startpage_com_keyservers_index")
    domains = tmp_path / "domains.txt"
    domains.write_text(f"{NXDOMAIN}\nstartpage.com\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["batch", str(domains)], env=ENV)
    out = _flat(result.output)
    assert f"{NXDOMAIN}: not found in DNS" in out
    assert f"Failed (1): {NXDOMAIN}" in out
    # Not analysed, so not in the summary as a score
    summary = [line.split() for line in result.output.splitlines() if line.split()[:1] == [NXDOMAIN]]
    assert summary == []


@pytest.mark.parametrize("command", ["check", "report", "send", "discover"])
@pytest.mark.parametrize("given,hint", [
    ("https://example.com/", "example.com"),
    ("http://www.example.com", "www.example.com"),
    ("security@example.com", "example.com"),
])
def test_a_url_or_an_address_is_not_taken_for_a_domain(dns_replay, command, given, hint):
    """`report https://example.com/` raised an uncaught OSError at --save; an address went to DNS as a name."""
    server = dns_replay()
    result = CliRunner().invoke(app, [command, given], env=ENV)
    assert result.exit_code == 64, result.output
    assert hint in result.output
    assert server.queries == []


def test_batch_skips_a_url_and_says_what_to_write(dns_replay, tmp_path):
    server = dns_replay()
    domains = tmp_path / "domains.txt"
    domains.write_text("https://example.com/\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["batch", str(domains)], env=ENV)
    out = _flat(result.output)
    assert "Failed (1)" in out
    assert mentions(out, "example.com")
    assert server.queries == []


# ─── report --save ───────────────────────────────────────────────────────────

SAVED_NAME = re.compile(r"mailradar_[a-z0-9.-]+_\d{8}_(it|en)\.txt")


@pytest.mark.parametrize("name", ["x/../../../evil.com", r"x\..\..\evil.com", "example.com:x", "Example.COM."])
def test_the_saved_file_stays_in_the_current_directory_under_a_plain_name(tmp_path, monkeypatch, name):
    """The name came from the raw argument: `x/../../../evil.com` climbed out of the directory, and on
    NTFS `example.com:x` wrote to an alternate data stream of a file named mailradar_example.com."""
    from mailradar.reporter import save_report
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    path = save_report("letter", name, "en")

    assert SAVED_NAME.fullmatch(path.name), path.name
    assert path.resolve().parent == work.resolve()
    assert [p.name for p in tmp_path.rglob("*") if p.is_file()] == [path.name]
    assert path.read_text(encoding="utf-8") == "letter"


def _example_com(dns_replay, http_replay):
    dns_replay("example_com", "example_com_dkim_more_selectors")
    http_replay("example_com", "keyservers_example_com")


def test_report_saves_under_the_analysed_name(dns_replay, http_replay, tmp_path, monkeypatch):
    _example_com(dns_replay, http_replay)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["report", "Example.COM.", "--save", "--lang", "en"], env=ENV)

    assert result.exit_code == 0, result.output
    [saved] = list(tmp_path.iterdir())
    assert saved.name.startswith("mailradar_example.com_") and saved.name.endswith("_en.txt")


def test_a_file_that_cannot_be_written_is_a_message_not_a_traceback(dns_replay, http_replay, tmp_path, monkeypatch):
    _example_com(dns_replay, http_replay)
    monkeypatch.chdir(tmp_path)
    from datetime import date
    # A directory where the file should go: the write fails whatever the platform
    (tmp_path / f"mailradar_example.com_{date.today():%Y%m%d}_en.txt").mkdir()

    result = CliRunner().invoke(app, ["report", "example.com", "--save", "--lang", "en"], env=ENV)

    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert "not saved" in _flat(result.output)


# ─── batch's exit code ───────────────────────────────────────────────────────

def _graded(grade: str):
    from mailradar.checker import DomainReport
    score = {"EXCELLENT": 95, "GOOD": 80, "MODERATE": 60, "POOR": 30, "CRITICAL": 10, "N/A": None}[grade]
    return DomainReport(domain="x.example", total_score=score, grade=grade)


@pytest.mark.parametrize("grades,code", [
    (["EXCELLENT", "GOOD"], 0),
    (["GOOD", "MODERATE"], 1),
    (["POOR", "CRITICAL", "GOOD"], 2),
    (["CRITICAL", "N/A"], 3),
])
def test_batch_exits_with_the_worst_code_check_would_give(tmp_path, grades, code):
    """batch exited 0 whatever it found. Each domain now counts as `check` would exit for it, and the batch
    exits with the highest of those codes. The analysis is a report built by hand: what is under test is
    the arithmetic of the exit code."""
    from unittest.mock import patch
    domains = tmp_path / "domains.txt"
    domains.write_text("".join(f"d{i}.example\n" for i in range(len(grades))), encoding="utf-8")
    with patch("mailradar.checker.domain_exists", return_value=True), \
            patch("mailradar.cli.analyze_domain", side_effect=[_graded(g) for g in grades]):
        result = CliRunner().invoke(app, ["batch", str(domains)], env=ENV)
    assert result.exit_code == code, result.output


def test_batch_with_a_domain_that_failed_does_not_exit_0(dns_replay, http_replay, tmp_path):
    dns_replay("dept_example_co_uk_exists")
    domains = tmp_path / "domains.txt"
    domains.write_text(f"{NXDOMAIN}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["batch", str(domains)], env=ENV)
    assert result.exit_code == 1, result.output


# ─── --lang ──────────────────────────────────────────────────────────────────

def test_lang_is_case_insensitive_and_all_of_one_language(dns_replay, http_replay, tmp_path, monkeypatch):
    """On Windows `--lang IT` found report_IT.j2 (NTFS ignores case) while the code compared `lang == "it"`:
    an Italian letter with English lines in it, saved as _IT.txt."""
    _example_com(dns_replay, http_replay)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["report", "example.com", "--lang", "IT", "--save"], env=ENV)

    assert result.exit_code == 0, result.output
    assert "Gentile responsabile" in result.output
    # example.com revokes its DKIM keys (recorded): the letter says so in Italian, not in English
    assert "Chiave revocata (p= vuoto)" in result.output
    assert "Key revoked (empty p=)" not in result.output
    [saved] = list(tmp_path.iterdir())
    assert saved.name.endswith("_it.txt")


@pytest.mark.parametrize("command", ["report", "send"])
def test_a_language_without_a_letter_is_refused(dns_replay, tmp_path, monkeypatch, command):
    """`--lang de` gave an English letter, saved as _de.txt."""
    server = dns_replay()
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, [command, "example.com", "--lang", "de"], env=ENV)

    assert result.exit_code == 64, result.output
    assert "it" in result.output and "en" in result.output
    assert server.queries == []
    assert list(tmp_path.iterdir()) == []
