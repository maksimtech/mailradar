"""EPSS where CVE ids already exist: the gate's own alerts.

Point four of the FIRST work was "EPSS in the other Radar", and this is one of them, and EPSS is indexed by
CVE. Measured on 2026-10-02, exeradar carries no CVE ids at all and apkradar,
mailradar and cookieradar one incidental mention each — so there was nothing for it
to attach to, and inventing a CVE surface to justify a forecast would be the wrong
way round.

There is one surface that already exists, in all five, and we have spent two days
feeding it: `SECURITY-EXCEPTIONS.toml` and the code-scanning alerts it answers.
Docker Scout names its alerts by CVE, so the gate is holding CVE ids already —
`CVE-2026-95619`, `CVE-2026-102010`, `CVE-2026-85091` — with a written reason and a
review date against each.

A forecast is what those records were missing. "No fix available in any suite" is
an acceptance whose cost depends entirely on whether anybody is likely to use the
flaw: zlib's CVE-2026-85091 accepted until December is comfortable at an EPSS of
0.1% and is something else at 40%. The number does not decide; it is what a person
reads before renewing a review date.

Three rules the tests hold:

**The forecast never changes the verdict.** The gate fails on a blocking alert
with no entry and on an entry past its date, and on nothing else. An unreachable
EPSS, a CVE FIRST does not score, a 90% probability on an accepted finding: none of
them turns a pass into a failure. The gate is about the record.

**Only ids that are CVE ids are looked up.** `SNYK-DEBIAN13-GCC14-20386241` is not
a CVE and is not sent to FIRST as one, even though its description names a CVE —
reading the id is reading what the scanner said, and parsing prose is guessing.

**An absent score is absent.** FIRST not scoring a CVE and FIRST being unreachable
are different silences, and neither is a zero: 0.0 is a real reading at the floor
of the scale, where tens of thousands of CVEs sit.
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import security_exceptions as gate  # noqa: E402

TODAY = dt.date(2026, 10, 2)


def alert(number, rule, tool="Docker Scout", severity="high"):
    return {
        "number": number,
        "rule": {"id": rule, "security_severity_level": severity},
        "tool": {"name": tool},
        "most_recent_instance": {"location": {"path": "Dockerfile"}},
    }


def entry(identifier, *, source="Docker Scout", review_by="2026-12-31"):
    return gate.Exception_(
        id=identifier,
        where="the base image",
        why="no fix in any suite",
        review_by=review_by,
        source=source,
    )


# ── which ids are CVE ids ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "identifier, expected",
    [
        ("CVE-2026-95619", "CVE-2026-95619"),
        ("CVE-1999-0001", "CVE-1999-0001"),
        ("CVE-2026-102010", "CVE-2026-102010"),          # five digits, which exist
        ("cve-2026-95619", "CVE-2026-95619"),            # upper-cased, as FIRST wants it
        ("SNYK-DEBIAN13-GCC14-20386241", None),
        ("GHSA-6v7p-g79w-8964", None),
        ("py/incomplete-url-substring-sanitization", None),
        ("", None),
        (None, None),
    ],
)
def test_only_a_cve_id_is_treated_as_one(identifier, expected):
    assert gate.cve_id(identifier) == expected


def test_a_snyk_id_is_not_resolved_through_its_description():
    """SNYK-DEBIAN13-GCC14-20386241 *is* CVE-2026-95619, and the description says
    so in prose. Reading the id is reading what the scanner stated; reading the
    description is guessing, and a wrong CVE would attach a forecast to the wrong
    flaw."""
    assert gate.cve_id("SNYK-DEBIAN13-GCC14-20386241") is None


# ── the forecast on the alerts ──────────────────────────────────────────────


def test_the_cves_to_ask_about_come_from_the_alerts_and_the_record():
    """Both, because they answer different questions: an unexplained alert needs a
    forecast to be triaged, and an accepted one needs it to be re-read."""
    alerts = [alert(1, "CVE-2026-95619"), alert(2, "SNYK-DEBIAN13-GCC14-20386241", tool="Snyk Container")]
    exceptions = [entry("CVE-2026-85091")]

    assert gate.cves_of(alerts, exceptions) == ["CVE-2026-85091", "CVE-2026-95619"]


def test_a_cve_is_asked_about_once_however_often_it_appears():
    alerts = [alert(1, "CVE-2026-95619"), alert(2, "CVE-2026-95619", tool="Snyk Container")]

    assert gate.cves_of(alerts, [entry("CVE-2026-95619")]) == ["CVE-2026-95619"]


def test_the_forecast_is_printed_against_the_alert_it_belongs_to(capsys):
    verdict = gate.review([alert(1, "CVE-2026-95619")], [], today=TODAY)

    gate.report(verdict, forecasts={"CVE-2026-95619": (0.42, 0.97)})
    printed = capsys.readouterr().out

    assert "CVE-2026-95619" in printed
    assert "42" in printed          # 42%, not 0.42
    assert "97" in printed          # the percentile, which is what makes 42% large


def test_an_accepted_finding_carries_its_forecast_too(capsys):
    """The number a review date is renewed against."""
    verdict = gate.review([alert(1, "CVE-2026-85091")], [entry("CVE-2026-85091")], today=TODAY)

    gate.report(verdict, forecasts={"CVE-2026-85091": (0.001, 0.12)},
                accepted=["CVE-2026-85091"])
    printed = capsys.readouterr().out

    assert "CVE-2026-85091" in printed
    assert "0.1%" in printed          # 0.001 is a tenth of a percent
    assert "renewing a review date" in printed


def test_a_cve_first_does_not_score_is_said_to_be_unscored_and_not_zero(capsys):
    verdict = gate.review([alert(1, "CVE-2026-95619")], [], today=TODAY)

    gate.report(verdict, forecasts={"CVE-2026-95619": None})
    printed = capsys.readouterr().out

    assert "CVE-2026-95619" in printed
    assert "0.0%" not in printed
    assert "not scored" in printed.lower() or "no epss" in printed.lower()


def test_no_forecasts_at_all_prints_the_report_it_always_printed(capsys):
    """FIRST unreachable, or the lookup switched off: the gate still says
    everything it said before, and says nothing about probabilities."""
    verdict = gate.review([alert(1, "CVE-2026-95619")], [], today=TODAY)

    gate.report(verdict, forecasts={})
    printed = capsys.readouterr().out

    assert "CVE-2026-95619" in printed
    assert "%" not in printed
    assert "epss" not in printed.lower()


# ── the verdict is untouched ────────────────────────────────────────────────


def test_a_high_forecast_does_not_fail_a_recorded_finding():
    """The gate fails on an unexplained alert and on an overdue entry. A 90%
    probability on something accepted with a reason is not a third failure mode —
    it is a reason to re-read the entry, and a build that failed on it would be
    failing on FIRST's model rather than on this repository."""
    verdict = gate.review([alert(1, "CVE-2026-85091")], [entry("CVE-2026-85091")], today=TODAY)

    assert verdict.ok
    assert gate.exit_code(verdict, forecasts={"CVE-2026-85091": (0.9, 0.99)}) == 0


def test_an_unexplained_alert_still_fails_whatever_its_forecast():
    verdict = gate.review([alert(1, "CVE-2026-95619")], [], today=TODAY)

    assert not verdict.ok
    assert gate.exit_code(verdict, forecasts={"CVE-2026-95619": (0.0001, 0.01)}) == 1


def test_an_overdue_entry_still_fails_even_at_a_tiny_forecast():
    verdict = gate.review(
        [alert(1, "CVE-2026-85091")],
        [entry("CVE-2026-85091", review_by="2026-01-01")],
        today=TODAY,
    )

    assert not verdict.ok
    assert gate.exit_code(verdict, forecasts={"CVE-2026-85091": (0.0, 0.0)}) == 1
