"""
MailRadar — the spinner must leave nothing in Rich's buffer.

While `console.status()` runs, Rich replaces `sys.stdout` and `sys.stderr` with a
`FileProxy` that holds text until it meets a newline. `Live` puts the original
streams back **without flushing that buffer**: a partial line written by a library
stays there, and is printed only when the interpreter finalises the object, at a
point where importing is no longer possible:

    Exception ignored while finalizing file <rich.file_proxy.FileProxy object …>
    ImportError: sys.meta_path is None, Python is likely shutting down

A successful command therefore ends in a traceback, and whoever is watching has
no way of knowing the result was valid. Observed on APKRadar with rich 15.0.0 and
Python 3.14.7; here the spinners wrap the DNS interrogations, the crt.sh lookup
and the sending of letters, that is third party code writing to the streams.

The test runs in a subprocess because finalisation is the thing being measured,
and inside pytest's own process it would never happen. It needs a `Console` that
believes it is a terminal: Rich installs the proxy only in that case, which is why
the defect cannot be seen through a pipe.
"""
import subprocess
import sys

import pytest

_SHUTDOWN_SCRIPT = """
import sys
from unittest.mock import patch

import typer
from rich.console import Console

import mailradar.checker as checker
import mailradar.cli as cli


def fake_domain_exists(domain):
    # A library holding a reference to sys.stdout keeps Rich's FileProxy alive
    # past the end of the spinner, with the partial line still inside it.
    global held_stdout
    held_stdout = sys.stdout
    sys.stdout.write("partial-line-without-newline")
    return False


with patch.object(checker, "domain_exists", fake_domain_exists), \\
     patch.object(checker, "find_domain_variants", lambda domain: []), \\
     patch.object(cli, "console", Console(force_terminal=True, width=250)):
    try:
        cli.app(["check", "esempio.invalid"], standalone_mode=False)
    except typer.Exit:
        pass
"""


def test_check_leaves_nothing_in_the_proxy_buffer():
    proc = subprocess.run(
        [sys.executable, "-c", _SHUTDOWN_SCRIPT],
        capture_output=True, text=True, timeout=120,
        encoding="utf-8", errors="replace",
    )

    assert proc.returncode == 0, proc.stderr
    assert "sys.meta_path is None" not in proc.stderr
    assert "Exception ignored" not in proc.stderr
    # And the partial line must not be lost: flushing the buffer means printing
    # it, not discarding it. A fix that threw it away would pass the two checks
    # above and hide a library's output.
    assert "partial-line-without-newline" in proc.stdout


def test_the_console_is_flushed_even_when_the_body_raises(monkeypatch):
    """The path the docstring of `_status` claims to cover and did not.

    `console.file.flush()` sat after the `with console.status(...)` block rather
    than in a `finally`, so an exception leaving the body skipped it — and that is
    the path where a library's partial line matters most, because it is the run
    that is about to print a traceback. SonarCloud's python:S9152 found it
    ("Cleanup after this yield may be skipped on early exit"); no test did,
    because every test exercised the success path.

    `console.status` is replaced with a no-op for the duration, and that is the
    whole point of the test rather than a convenience. The first version of it did
    not do this, and passed against the broken code: Rich's own `Live.stop()`
    writes to the console on its way out, which flushes `console.file` as a side
    effect, so the recorder saw a flush that `_status` never performed. A test that
    cannot fail is worse than no test, and only replacing the spinner leaves this
    module's own flush as the only thing that could have done it.
    """
    from contextlib import contextmanager

    from rich.console import Console

    from mailradar import cli

    flushed: list[str] = []

    class Recorder:
        def flush(self):
            flushed.append("console.file")

        def write(self, *_a, **_k):
            return 0

        def isatty(self):
            return False

    @contextmanager
    def no_spinner(_message):
        yield

    # A console of its own, put in place of the module's. Reading
    # `cli.console.file` and assigning it back looks like a restore and is not:
    # Rich's `file` is a property that falls back to `sys.stdout` when nothing was
    # set, so writing the current value into it pins that stream for good. Every
    # later test rendering through this console then wrote to the terminal instead
    # of to the CliRunner's buffer — measured on 2026-09-30, where
    # tests/test_hash_is_verifiable.py failed on an empty `result.output` because
    # it happened to run after this file.
    console = Console(file=Recorder())
    console.status = no_spinner
    monkeypatch.setattr(cli, "console", console)

    with pytest.raises(RuntimeError, match="collector died"), cli._status("working..."):
        raise RuntimeError("collector died")

    assert flushed == ["console.file"], (
        "the console was not flushed on the way out of an exception"
    )
