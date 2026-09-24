"""Output must survive a console that is not UTF-8.

On Windows the console code page is cp1252 unless something changes it, and
Python encodes its output with it. The CLI help string carries an emoji, so
`--help` — a command that does nothing — ended in:

    UnicodeEncodeError: 'charmap' codec can't encode character '\\U0001f4e1'

The command was not failing; printing its output was. Every entry point was
affected, so nothing could run without PYTHONIOENCODING=utf-8 set by hand.
"""

from __future__ import annotations

import io
import sys

import pytest

from mailradar import cli

# One of each: the emoji that broke it, an en dash, and an accented letter that
# cp1252 does have — the last must survive the fix too.
AWKWARD = "\U0001f4e1 — città"


def cp1252_stream() -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


def test_a_cp1252_stream_cannot_print_the_help_text():
    """The bug itself, pinned so the fix is measured against it."""
    stream = cp1252_stream()
    with pytest.raises(UnicodeEncodeError):
        stream.write(AWKWARD)
        stream.flush()


def test_stdout_and_stderr_are_switched_to_utf8(monkeypatch):
    out, err = cp1252_stream(), cp1252_stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    cli.enable_utf8_output()

    assert sys.stdout.encoding.lower().replace("-", "") == "utf8"
    assert sys.stderr.encoding.lower().replace("-", "") == "utf8"


def test_the_awkward_characters_then_go_through(monkeypatch):
    out = cp1252_stream()
    monkeypatch.setattr(sys, "stdout", out)

    cli.enable_utf8_output()
    sys.stdout.write(AWKWARD)
    sys.stdout.flush()

    written = sys.stdout.buffer.getvalue().decode("utf-8")
    assert written == AWKWARD


def test_a_stream_that_cannot_be_reconfigured_is_left_alone(monkeypatch):
    """pytest's capture, a pipe wrapper, anything not a TextIOWrapper.

    Replacing the stream would swallow whatever is capturing it, and raising
    would take down a program that has not printed anything yet. Neither is
    worth it for a cosmetic setting, so the helper gives up quietly.
    """
    class Plain:
        encoding = "cp1252"

        def write(self, text):
            return len(text)

    monkeypatch.setattr(sys, "stdout", Plain())
    cli.enable_utf8_output()          # must not raise
    assert sys.stdout.encoding == "cp1252"


def test_a_stream_already_in_utf8_is_not_disturbed(monkeypatch):
    original = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", original)

    cli.enable_utf8_output()

    assert sys.stdout is original


def test_it_runs_at_import_so_nothing_prints_before_it():
    """Calling it from main() would be too late: Typer builds its help text,
    and Rich decides how to encode, while the module is being imported."""
    source = cli.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()

    call = text.index("enable_utf8_output()")
    app = text.index("app = typer.Typer(")
    assert call < app, "the call must come before the Typer app is built"
