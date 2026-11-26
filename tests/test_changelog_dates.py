"""The CHANGELOG says a review happened only once it has.

The Security entries end with the date an accepted finding is looked at again,
and in November they wrote it in the past: "Reviewed on 2026-12-15 with the other
OpenSSL entries", "The entries are reviewed on 2026-12-08". A reader takes it as
done. It was a deadline: the same date as `review_by` in
SECURITY-EXCEPTIONS.toml, which the Security Posture gate enforces
(maksimtech/apkradar#130).

The wording mirrors the field: "Review by DATE" before the review, "Reviewed on
DATE: outcome; next review by DATE" after it. This file holds three things:

- in `[Unreleased]`, no "reviewed on" a date after today;
- in a released section, no "reviewed on" a date after that release;
- in `[Unreleased]`, a Security entry that names a CVE accepted in
  SECURITY-EXCEPTIONS.toml and gives a "review by" date gives that CVE's
  `review_by`.

Released sections are not held to the third rule: a `review_by` may move after a
review, and what a release said on its day stays what it said.

Whitespace, line breaks included, is folded before matching: five of the 34
phrases found on 2026-11-22 were wrapped across two lines. `today` is a
parameter; the tests of the logic pass fixed dates, and the check against the
real clock can only turn from red to green as days pass.
"""
from __future__ import annotations

import re
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
EXCEPTIONS = ROOT / "SECURITY-EXCEPTIONS.toml"

SECTION = re.compile(
    r"^## \[(?P<name>[^\]]+)\](?:[ \t]*[-—–][ \t]*(?P<released>\d{4}-\d{2}-\d{2}))?[^\n]*$", re.M
)
REVIEWED_ON = re.compile(r"\b[Rr]eviewed\s+on\s+(\d{4}-\d{2}-\d{2})")
REVIEW_BY = re.compile(r"\b[Rr]eview\s+by\s+(\d{4}-\d{2}-\d{2})")
CVE = re.compile(r"\bCVE-\d{4}-\d+\b")


def _fold(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def sections(text: str):
    """(name, release date or None, body) for every `## [...]` section."""
    heads = list(SECTION.finditer(text))
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        released = head["released"]
        yield head["name"], date.fromisoformat(released) if released else None, text[head.end():end]


def premature_reviews(text: str, today: date) -> list[str]:
    """Every "reviewed on DATE" whose DATE had not come when its section was written."""
    found = []
    for name, released, body in sections(text):
        limit = today if name == "Unreleased" else released
        if limit is None:
            continue
        flat = _fold(body)
        for match in REVIEWED_ON.finditer(flat):
            when = date.fromisoformat(match[1])
            if when > limit:
                context = flat[max(0, match.start() - 60):match.end()]
                found.append(f"[{name}] …{context}: write 'Review by {match[1]}'")
    return found


def _bullets(body: str):
    """The top-level `- ` entries of a section, each with its continuation lines."""
    for chunk in re.split(r"\n(?=- )", "\n" + body):
        if chunk.startswith("- "):
            yield chunk


def review_by_mismatches(text: str, review_by: dict[str, date]) -> list[str]:
    """Unreleased entries whose "review by" date is none of the dates of the CVEs they name."""
    found = []
    for name, _, body in sections(text):
        if name != "Unreleased":
            continue
        for bullet in _bullets(body):
            flat = _fold(bullet)
            named = {cve: review_by[cve] for cve in CVE.findall(flat) if cve in review_by}
            if not named:
                continue
            for match in REVIEW_BY.finditer(flat):
                given = date.fromisoformat(match[1])
                if given not in named.values():
                    expected = ", ".join(f"{cve} {d.isoformat()}" for cve, d in sorted(named.items()))
                    found.append(f"'Review by {match[1]}' in an entry naming {expected} (SECURITY-EXCEPTIONS.toml)")
    return found


def _exceptions() -> dict[str, date]:
    data = tomllib.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    dates = {}
    for entry in data.get("exception", []):
        value = entry["review_by"]
        dates[entry["id"]] = value if isinstance(value, date) else date.fromisoformat(str(value))
    return dates


# ─── the logic, on fixed dates ──────────────────────────────────────────────

SAMPLE = """# Changelog

## [Unreleased]

### Security

- **CVE-2026-1 is accepted.** Not reachable. Reviewed on
  2026-12-15 with the other entries.
- **CVE-2026-2 was looked at.** Reviewed on 2026-11-01: still no fix; next review by 2026-12-15.

## [2026.49] - 2026-11-18

### Security

- **CVE-2026-3 is accepted.** The entries are reviewed on 2026-12-08 and dropped when fixed.
- The paragraph, last reviewed on 2026-09-12, is gone.
"""


def test_a_future_review_in_unreleased_is_found_even_when_wrapped():
    found = premature_reviews(SAMPLE, today=date(2026, 11, 26))
    assert len(found) == 2, found
    assert "[Unreleased]" in found[0] and "Review by 2026-12-15" in found[0]


def test_a_review_that_has_happened_is_not_flagged():
    """Past 2026-12-15 the Unreleased line is no longer early, and the review of
    2026-11-01 never was. The released section's stays wrong whatever today is."""
    found = premature_reviews(SAMPLE, today=date(2026, 12, 20))
    assert len(found) == 1 and "[2026.49]" in found[0], found


def test_a_released_section_is_held_to_its_own_release_date():
    found = premature_reviews(SAMPLE, today=date(2030, 1, 1))
    assert found == [found[0]]
    assert "[2026.49]" in found[0] and "2026-12-08" in found[0]


def test_review_by_must_be_the_date_of_a_cve_the_entry_names():
    text = SAMPLE.replace("Reviewed on\n  2026-12-15", "Review by\n  2026-12-15")
    assert review_by_mismatches(text, {"CVE-2026-1": date(2026, 12, 15)}) == []
    wrong = review_by_mismatches(text, {"CVE-2026-1": date(2026, 12, 8)})
    assert len(wrong) == 1 and "CVE-2026-1 2026-12-08" in wrong[0]


def test_an_entry_naming_no_accepted_cve_is_not_checked():
    assert review_by_mismatches(SAMPLE, {"CVE-2099-9": date(2026, 12, 15)}) == []


# ─── this repository ────────────────────────────────────────────────────────

def test_the_changelog_claims_no_review_before_it_happened():
    found = premature_reviews(CHANGELOG.read_text(encoding="utf-8"), today=date.today())
    assert found == [], "\n".join(found)


def test_every_review_by_in_unreleased_is_the_exceptions_date():
    found = review_by_mismatches(CHANGELOG.read_text(encoding="utf-8"), _exceptions())
    assert found == [], "\n".join(found)
