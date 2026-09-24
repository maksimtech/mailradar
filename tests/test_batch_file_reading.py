"""How `mailradar batch` reads the file it is given.

CookieRadar's `batch` already answers all four of these questions, and the
command here is the same command against a different kind of target — but it
opens the file with a bare `open(file)`, which means:

- the locale decides the encoding, so a UTF-8 list of domains is misread on a
  Windows console and read correctly on Linux CI: the worst kind of difference,
  because the suite is green where nobody is standing;
- a byte order mark, which is what Notepad writes by default, becomes part of
  the first domain, and that domain then fails to resolve;
- an OSError that is not FileNotFoundError — a directory, a permission — is not
  caught at all, so the user gets a traceback instead of a message.

An internationalised domain is the ordinary case here, not an exotic one:
`müller.de` and `società.it` are both real and both registrable.

Found on 2026-09-24 while making the Windows suites runnable: the same family
as the cp1252 crash already in the backlog, on the input side this time.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mailradar.cli import app

runner = CliRunner()


def _batch(path):
    """Analysis is mocked: these tests are about reading, and nothing else.

    Patched at `mailradar.cli.analyze_domain`, not at `mailradar.checker`: the
    CLI imports the name into its own module at import time, so patching the
    definition leaves the CLI holding the original — and the suite then makes
    real DNS queries and hangs.
    """
    from mailradar.checker import DomainReport

    def analysed(domain, *args, **kwargs):
        report = DomainReport(domain=domain)
        report.total_score = 100
        report.grade = "EXCELLENT"
        return report

    with patch("mailradar.cli.analyze_domain", side_effect=analysed):
        return runner.invoke(app, ["batch", str(path)])


def test_a_utf8_list_is_read_as_utf8_whatever_the_console_says(tmp_path):
    """Asserting on the domain, not on the count.

    Read through cp1252 the count is still right, and "società.it" comes back
    as "societÃ .it" — a domain that will not resolve, queried as though it had
    been the one asked for.
    """
    listing = tmp_path / "domains.txt"
    listing.write_text("società.it\nmüller.de\n", encoding="utf-8")

    result = _batch(listing)

    assert "società.it" in result.output, result.output
    assert "müller.de" in result.output, result.output


def test_a_byte_order_mark_is_not_part_of_the_first_domain(tmp_path):
    """Notepad writes a BOM by default; it must not be pasted onto a domain.

    The mark is U+FEFF when decoded as UTF-8 and "ï»¿" when decoded as cp1252,
    so both spellings are refused: either one means the first domain is wrong.
    """
    listing = tmp_path / "domains.txt"
    listing.write_text("first.example\nsecond.example\n", encoding="utf-8-sig")

    result = _batch(listing)

    assert "﻿" not in result.output
    assert "ï»¿" not in result.output
    assert "first.example" in result.output, result.output


def test_a_file_that_is_not_utf8_is_refused_with_a_message(tmp_path):
    """Not a traceback: the user is told which file and why."""
    listing = tmp_path / "domains.txt"
    listing.write_bytes("società.it\n".encode("latin-1"))

    result = _batch(listing)

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "domains.txt" in result.output


def test_a_directory_instead_of_a_file_is_refused_with_a_message(tmp_path):
    """The mistake is easy to make with tab completion, and it used to raise."""
    result = _batch(tmp_path)

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_a_missing_file_still_says_so(tmp_path):
    """The one case that was already handled; it must survive the others."""
    result = _batch(tmp_path / "nope.txt")

    assert result.exit_code != 0
    assert "nope.txt" in result.output


@pytest.mark.parametrize("line", ["# commented", "  # indented", "", "   "])
def test_comments_and_blank_lines_are_still_skipped(tmp_path, line):
    listing = tmp_path / "domains.txt"
    listing.write_text(f"{line}\nreal.example\n", encoding="utf-8")

    result = _batch(listing)

    assert "commented" not in result.output, result.output
    assert "indented" not in result.output, result.output
    assert "real.example" in result.output, result.output
