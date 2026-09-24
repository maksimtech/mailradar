"""What the report says when a law could not be verified.

A missing SHA-256 is not a defect in the hashing: it is the honest consequence
of having no verified text to hash. Printing one anyway would assert a
verification that never happened.

But the reader has to be able to reach that conclusion from the report alone.
Before this, the warning said only "text not verifiable" at the top, while
"SHA256: not available" appeared further down against each citation, and
nothing connected the two — so a missing hash read as a bug in the tool.

Verified on 2026-09-24 against a real cache: every one of the 56 cached
provisions had a hash, and every cited reference was produced by the parser.
The gap was never in the computation.
"""

from __future__ import annotations

from rich.console import Console

from mailradar.cli import _print_law_check
from mailradar.law_checker import ActStatus, Citation, LawCheckResult
from mailradar.law_fetcher import GDPR


def render(law) -> str:
    """The panel as the terminal would show it, wide enough not to wrap."""
    console = Console(width=200, no_color=True, force_terminal=False)
    with console.capture() as captured:
        _print_law_check(law, out=console)
    return captured.get()


def law(source: str, *, sha256: str | None) -> LawCheckResult:
    return LawCheckResult(
        citations=[Citation(finding="cleartext", law=GDPR.name, article="32(1)",
                            sha256=sha256, version_date="2026-09-24" if sha256 else None)],
        acts=[ActStatus(GDPR, source, None if source == "verified" else "EUR-Lex 202")],
    )


HASH = "a" * 64


# ── the state that loses the hash ───────────────────────────────────────────


def test_the_warning_itself_says_the_citations_will_have_no_hash():
    """The sentence that was missing, and the reason this file exists.

    Asserted on the warning line, not on the whole report: "SHA256" appears in
    every citation anyway, so a whole-report assertion would pass without the
    two facts ever being joined — which was the state being corrected.
    """
    out = render(law("unavailable", sha256=None))
    warning = next(line for line in out.splitlines() if "not verifiable" in line)

    assert "SHA" in warning, warning


def test_the_unverifiable_state_still_names_the_act_and_its_source():
    """The new clause must not crowd out what the line already said."""
    out = render(law("unavailable", sha256=None))
    warning = next(line for line in out.splitlines() if "not verifiable" in line)

    assert GDPR.name in warning, warning
    assert GDPR.source in warning, warning


# ── the two states that keep it ─────────────────────────────────────────────


def test_a_verified_act_does_not_mention_a_missing_hash():
    """Nothing is missing there, and saying so would only worry the reader."""
    out = render(law("verified", sha256=HASH))

    assert "verified" in out
    assert "not verifiable" not in out


def test_an_act_read_from_the_cache_still_has_its_hash():
    """The source being down does not cost the hash — only having no copy does."""
    out = render(law("cache", sha256=HASH))

    assert "cache" in out
    assert "not verifiable" not in out, out

