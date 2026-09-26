"""How this Radar is numbered, and when it is allowed to move.

Five tools ship together and they are numbered the way Apple numbers a suite:
iOS 26, macOS 26, watchOS 26 share the generation and nothing else. The year is
the generation; the number after it belongs to this Radar alone and counts its
own releases. Two Radar being at 2026.10 and 2026.33 in the same week is the
scheme working, not a drift.

The rule that matters most is the one that is easiest to break by being tidy:
**a Radar that has not changed does not get a version.** Apple does not ship
watchOS 26.1 to keep iOS 26.1 company. On 2026-09-26 this project nearly
published five versions of which one — mailradar — was byte-identical to what
was already public, for no reason beyond making the numbers line up. The last
test here is that mistake, written down.

The month left the version when the scheme changed. It used to sit in the
second segment, which is why the numbering could not simply continue: under
PEP 440, `2026.4` is *lower* than `2026.9.3`, so the two Radar whose count was
below ten started again at ten rather than going backwards on PyPI.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from mailradar import __version__ as VERSION

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = "mailradar"
CHANGELOG = ROOT / "CHANGELOG.md"

# The generation, this Radar's count, and optionally a fix on top of it:
# 2026.40, then 2026.40.1 for something urgent, then 2026.41 for the next
# ordinary release. iOS 26 -> 26.1 -> 26.1.1, with the year in front.
GENERATION_FORM = re.compile(r"^\d{4}\.[1-9]\d*(\.[1-9]\d*)?$")

# The one version that moved without the code moving, named so that it is an
# exception and not a hole.
#
# On 2026-09-26 the five Radar were put on a common baseline. They had drifted
# to .32, .12, .11, .6 and .3 of the same generation, which made the shared part
# of the number mean nothing; the highest count was taken, rounded up for
# headroom, and everybody started again from there. A Radar with nothing changed
# took the number too, once, on purpose — that is what a baseline is.
#
# It is a settling year. From 2027 the count moves because something moved.
BASELINE = "2026.40"


def normalised(version: str) -> tuple[int, ...]:
    """PEP 440 drops leading zeros, so 2026.09.4 and 2026.9.4 are one version.
    Tags carry a `v` in four of the five repositories and not in the fifth."""
    return tuple(int(part) for part in version.lstrip("v").split(".") if part.isdigit())


def git(*args: str) -> str | None:
    """Output, or None when git cannot answer — a shallow CI checkout has no
    tags, and a test that fails for that reason tests the checkout."""
    try:
        done = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True,
            # Not the locale encoding: a tag or a path may carry any alphabet,
            # and on Windows text=True alone decodes with cp1252.
            encoding="utf-8", errors="replace", timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def last_tag() -> str | None:
    described = git("describe", "--tags", "--abbrev=0")
    return described.strip() if described and described.strip() else None


def test_the_version_carries_the_generation_and_nothing_else():
    """A version being prepared uses the year form. One that has not moved
    since the scheme changed is allowed to keep its old number — the form is
    required of the next release, not retroactively of history."""
    if GENERATION_FORM.match(VERSION):
        return

    tag = last_tag()
    if tag is None:
        pytest.skip("no tags reachable: nothing to compare the version against")
    assert normalised(VERSION) == normalised(tag), (
        f"{VERSION} is ahead of {tag} and is not in the year generation form"
    )


def test_the_generation_is_a_year():
    generation = VERSION.split(".")[0]

    assert len(generation) == 4 and generation.isdigit()
    assert 2020 <= int(generation) <= 2100


def test_the_changelog_describes_the_version_that_is_here():
    """A version with no entry is a release nobody can read."""
    if last_tag() and normalised(VERSION) == normalised(last_tag()):
        pytest.skip("nothing pending: the entry was written when it shipped")

    assert f"[{VERSION}]" in CHANGELOG.read_text(encoding="utf-8"), (
        f"CHANGELOG.md has no section for {VERSION}"
    )


def test_a_version_ahead_of_the_last_tag_means_this_package_changed():
    """The rule the suite nearly broke.

    A number that moved while the code did not is a release that fixes nothing,
    and it costs more than it looks: whoever reads the changelog goes hunting
    for a change that is not there, and whoever is chasing a bug upgrades and
    finds the same bug.
    """
    tag = last_tag()
    if tag is None:
        pytest.skip("no tags reachable: nothing to compare the version against")
    if normalised(VERSION) == normalised(tag):
        return

    changed = git("diff", "--name-only", f"{tag}..HEAD", "--", PACKAGE_DIR)
    if changed is None:
        pytest.skip(f"git cannot diff {tag}..HEAD in this checkout")

    assert changed.strip() or VERSION == BASELINE, (
        f"{VERSION} is ahead of {tag} and nothing under {PACKAGE_DIR} changed "
        "between them: a Radar that has not changed does not get a version"
    )


def test_a_fix_on_top_of_a_baseline_never_starts_at_zero():
    """PEP 440 strips a trailing zero, so 2026.40.0 *is* 2026.40 — the same
    version under a different spelling, which PyPI would refuse as a duplicate
    and which would read as a release to everybody else. Counting from one is
    not a convention here, it is the only thing that works."""
    parts = VERSION.split(".")
    if len(parts) < 3:
        return

    assert int(parts[2]) >= 1, f"{VERSION} spells a fix that is not a fix"
