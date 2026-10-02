"""The gate that refuses: open findings must be fixed, or explained and dated.

On 2026-09-28 every workflow of this repository was green while SonarCloud's
quality gate was red and thirteen high-severity alerts were open in code
scanning. Nothing was broken. `snyk.yml` carries `continue-on-error` so a pull
request is not blocked by findings that were already there, and Sonar evaluates
its gate after the job has finished succeeding. The pipeline reported and never
refused.

The rule here is the one that can be defended:

    block on everything we can fix; never block on an upstream flaw with no fix
    available — but require a dated, written reason for each one.

It is stricter than "hold the release until upstream fixes it", not laxer.
`CVE-2026-85091` in Debian's zlib is marked *not fixed* by Debian itself: waiting
for it means never shipping our own fixes again, while a tool whose whole thesis
is that unpatched software is the risk stops patching itself. And an unexplained
finding that nobody has to justify is exactly how thirteen of them came to be
open without anyone deciding anything.

Read as a library by the tests, run as a script by
`.github/workflows/security-posture.yml`:

    gh api repos/OWNER/REPO/code-scanning/alerts?state=open > alerts.json
    python tools/security_exceptions.py alerts.json
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import sys
import tomllib
from dataclasses import dataclass, field

# Only these refuse a build. The ten `note` findings of 2026-09-28 were all false
# positives — a path traversal whose taint source is the operator's own
# environment variable, a test harness, a rule about Python versions this project
# does not support — and demanding a written exception for each would fill the
# record with noise and teach its reader to skim.
BLOCKING = frozenset({"high", "critical"})

REQUIRED_FIELDS = ("id", "where", "why", "review_by")

DEFAULT_FILE = "SECURITY-EXCEPTIONS.toml"


@dataclass(frozen=True)
class Exception_:
    """One accepted finding. `why` and `review_by` are what make it an exception
    rather than a silencer."""

    id: str
    where: str
    why: str
    review_by: str
    source: str | None = None
    # A rule id alone is too wide for a rule that can fire anywhere: an entry for
    # `py/clear-text-logging-sensitive-data` would excuse the next real one in
    # another file. `path` narrows an entry to the file it was written about, and
    # is left out for a CVE, where the location is the image and not a line.
    path: str | None = None

    def covers(self, alert: dict) -> bool:
        if _rule_of(alert) != self.id:
            return False
        if self.source is not None and self.source != _tool_of(alert):
            return False
        return self.path is None or self.path == _path_of(alert)

    def overdue(self, today: dt.date) -> bool:
        # Inclusive: reviewed today is reviewed.
        return dt.date.fromisoformat(self.review_by) < today


@dataclass(frozen=True)
class Verdict:
    unexplained: list[dict] = field(default_factory=list)
    expired: list[Exception_] = field(default_factory=list)
    unused: list[Exception_] = field(default_factory=list)
    # Reported and not counted: the finding is not open any more, but GitHub still
    # has it, so the entry describes something real that a scanner stopped
    # mentioning. See `review` for why that is not the same as a stale record.
    settled: list[Exception_] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.unexplained or self.expired or self.unused)

    def describe(self) -> str:
        """For whoever has to act. The exit code is for the machine."""
        lines: list[str] = []
        if self.settled:
            # First, because it is the one part that asks for judgement rather
            # than a fix, and last place is where a passing build's output is not
            # read.
            lines.append(f"{len(self.settled)} exception(s) whose finding is not "
                         f"reported any more:")
            lines += [f"  {e.id}  ({e.where})" for e in self.settled]
            lines.append("  GitHub still has the alert, closed, so this is not a "
                         "stale record — a scanner stopped mentioning it. Docker "
                         "Scout has done this and changed its mind back. Delete "
                         "the entry once the absence holds, not on the first "
                         "quiet run.")
        if self.ok:
            lines.append("ok: every blocking alert is explained and every "
                         "exception is in date")
            return "\n".join(lines)

        if self.unexplained:
            lines.append(f"{len(self.unexplained)} blocking alert(s) with no exception:")
            lines += [
                f"  #{a.get('number')}  {_severity_of(a)}  {_tool_of(a)}  {_rule_of(a)}"
                f"  {_where_of(a)}"
                for a in self.unexplained
            ]
            lines.append("  Fix them, or add an entry to " + DEFAULT_FILE
                         + " saying why they are acceptable and when that is reviewed.")
        if self.expired:
            lines.append(f"{len(self.expired)} exception(s) past their review date:")
            lines += [f"  {e.id}  review_by {e.review_by}  ({e.where})" for e in self.expired]
            lines.append("  Re-read the reason and either move the date or delete the entry.")
        if self.unused:
            lines.append(f"{len(self.unused)} exception(s) matching nothing any more:")
            lines += [f"  {e.id}  ({e.where})" for e in self.unused]
            lines.append("  The finding is gone; delete the entry so the record still "
                         "describes the product.")
        return "\n".join(lines)


def _rule_of(alert: dict) -> str:
    return str((alert.get("rule") or {}).get("id") or "")


def _tool_of(alert: dict) -> str:
    return str((alert.get("tool") or {}).get("name") or "")


def _severity_of(alert: dict) -> str:
    rule = alert.get("rule") or {}
    return str(rule.get("security_severity_level") or rule.get("severity") or "").lower()


def _path_of(alert: dict) -> str:
    return str(((alert.get("most_recent_instance") or {}).get("location") or {}).get("path") or "")


def _where_of(alert: dict) -> str:
    location = ((alert.get("most_recent_instance") or {}).get("location") or {})
    path = location.get("path")
    return f"{path}:{location.get('start_line')}" if path else ""


def blocking(alerts: list[dict]) -> list[dict]:
    return [a for a in alerts if _severity_of(a) in BLOCKING]


def load_exceptions(path: str | pathlib.Path) -> list[Exception_]:
    """The record, or an empty list when a repository has never needed one.

    Every field is required. `why` because an exception without a reason is a
    silencer, `review_by` because one without a date never comes back, and
    `where` because the next reader has to find the thing being excused.
    """
    target = pathlib.Path(path)
    if not target.is_file():
        return []
    data = tomllib.loads(target.read_text(encoding="utf-8"))

    entries: list[Exception_] = []
    for raw in data.get("exception", []):
        for name in REQUIRED_FIELDS:
            if not str(raw.get(name) or "").strip():
                raise ValueError(f"{target.name}: an entry is missing {name!r}: {raw!r}")
        try:
            dt.date.fromisoformat(str(raw["review_by"]))
        except ValueError as exc:
            raise ValueError(
                f"{target.name}: review_by must be YYYY-MM-DD, not {raw['review_by']!r}"
            ) from exc
        entries.append(Exception_(
            id=str(raw["id"]),
            where=str(raw["where"]),
            why=str(raw["why"]),
            review_by=str(raw["review_by"]),
            source=(str(raw["source"]) if str(raw.get("source") or "").strip() else None),
            path=(str(raw["path"]) if str(raw.get("path") or "").strip() else None),
        ))
    return entries


def review(alerts: list[dict], exceptions: list[Exception_], *,
           today: dt.date | None = None,
           closed: list[dict] | None = None) -> Verdict:
    """The three ways this can fail, reported together rather than one at a time.

    An alert that is explained by an overdue exception appears under `expired`
    and not under `unexplained`: both facts are true, and hiding the second
    behind the first is how an exception becomes permanent.

    `unused` is only reported for a scanner that said something. An empty list of
    alerts is not a clean product — it is also what a scan that failed to upload
    produces — and calling every exception stale there would fail the build for
    the one reason that is not the product's fault.

    `closed` is the same distinction one step further in. An entry that matches no
    open alert but matches a closed one is `settled`, which is reported and does
    not fail: the finding was there and a scanner stopped mentioning it. Measured
    on 2026-09-29, Docker Scout dropped CVE-2026-82560 from exeradar while
    patchradar and mailradar held it both open and closed, having already lost and
    regained it the day before. Failing on the first quiet run means one commit to
    delete the entry and another to put it back, and a rule that demands
    alternating commits gets ignored. An entry matching nothing in either state is
    still `unused`, which is the drift the rule was written for.
    """
    today = today or dt.date.today()
    closed = closed or []
    interesting = blocking(alerts)
    tools_that_spoke = {_tool_of(a) for a in alerts}

    unexplained = [a for a in interesting
                   if not any(entry.covers(a) for entry in exceptions)]
    expired = [entry for entry in exceptions if entry.overdue(today)]

    orphaned = [
        entry for entry in exceptions
        if not any(entry.covers(a) for a in alerts)
        and (entry.source in tools_that_spoke if entry.source else bool(alerts))
    ]
    # `covers` is reused unchanged, so a closed alert has to match the entry's
    # source as well as its rule: Scout going quiet says nothing about whether
    # Snyk still reports the same CVE, and the two disagree about these packages
    # routinely.
    settled = [entry for entry in orphaned
               if any(entry.covers(a) for a in closed)]
    unused = [entry for entry in orphaned if entry not in settled]
    return Verdict(unexplained=unexplained, expired=expired, unused=unused,
                   settled=settled)


# ─── EPSS, from FIRST, on the CVEs this record already holds ──────────────────
#
# Point four of the FIRST work was "EPSS in the other Radar", and EPSS is indexed
# by CVE. Measured on 2026-10-02: exeradar carries no CVE ids at all, and the other
# three one incidental mention each — so there was nothing to attach a forecast to,
# and building a CVE surface to justify one would have been the wrong way round.
#
# This record is the surface that already exists, in all five. Docker Scout names
# its alerts by CVE, so the gate holds CVE ids with a written reason and a review
# date against each — and the one thing those records lacked was a forecast. "No
# fix in any suite" accepted until December is comfortable at an EPSS of 0.1% and
# is something else at 40%. The number decides nothing; it is what a person reads
# before renewing a date.
#
# It is printed and never counted. The gate fails on an unexplained alert and on an
# overdue entry, and a build that failed on FIRST's model would be failing on
# somebody else's weather forecast.
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_TIMEOUT = 10.0
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def cve_id(identifier: str | None) -> str | None:
    """`identifier` as a CVE id, or None if it is not one.

    Scanner ids are not CVEs — SNYK-DEBIAN13-GCC14-20386241 *is* CVE-2026-95619,
    and its description says so in prose, but reading the id is reading what the
    scanner stated while reading the description is guessing. A forecast attached
    to the wrong flaw is worse than none.
    """
    if not isinstance(identifier, str):
        return None
    text = identifier.strip().upper()
    return text if _CVE_ID.match(text) else None


def cves_of(alerts: list[dict], exceptions: list[Exception_]) -> list[str]:
    """Every CVE the gate is about to mention, sorted, without repeats.

    Both sides on purpose: an unexplained alert needs a forecast to be triaged,
    and an accepted one needs it to be re-read.
    """
    found = {cve_id(_rule_of(a)) for a in alerts}
    found |= {cve_id(entry.id) for entry in exceptions}
    return sorted(c for c in found if c)


def forecasts_for(cves: list[str], *, url: str = EPSS_URL) -> dict[str, tuple[float, float] | None]:
    """{cve: (score, percentile)}, None for a CVE FIRST does not score.

    Returns {} on any failure, which is how this stays out of the verdict: no
    network in CI, a 503 from FIRST, a changed payload — the gate prints what it
    always printed and says nothing about probabilities. urllib rather than httpx
    because this script runs on a bare checkout in a workflow that installs
    nothing.

    A CVE FIRST does not score maps to None and never to 0.0: the floor of the
    scale is a real reading that tens of thousands of CVEs sit on.
    """
    if not cves:
        return {}
    import urllib.error
    import urllib.parse
    import urllib.request

    found: dict[str, tuple[float, float] | None] = dict.fromkeys(cves)
    query = urllib.parse.urlencode({"cve": ",".join(cves), "limit": len(cves)})
    request = urllib.request.Request(
        f"{url}?{query}", headers={"User-Agent": "patchradar-security-posture"}
    )
    try:
        with urllib.request.urlopen(request, timeout=EPSS_TIMEOUT) as response:
            if response.status != 200:
                return {}
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return {}

    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = cve_id(row.get("cve"))
        if name is None or name not in found:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if 0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0:
            found[name] = (score, percentile)
    return found


def _forecast_phrase(forecast: tuple[float, float] | None) -> str:
    """One parenthesis for a reader, or the absence said out loud.

    ">99.9%" rather than "100.0%" at the top of the scale, and a floored
    percentile: the top 1% is p99 and there is no p100 to be in.
    """
    if forecast is None:
        return " (EPSS: not scored by FIRST)"
    score, percentile = forecast
    shown = ">99.9%" if score > 0.9995 else f"{score * 100:.1f}%"
    if score < 0.001:
        shown = f"{score * 100:.2f}%"
    return f" (EPSS {shown}, p{int(percentile * 100)})"


def annotate(text: str, forecasts: dict[str, tuple[float, float] | None]) -> str:
    """The report with a forecast added to every line that names a CVE it has.

    Done on the rendered text rather than inside `describe` so that the verdict's
    own wording stays the one thing it was before: this adds a clause to a line and
    cannot change what the line says.
    """
    if not forecasts:
        return text
    lines = []
    for line in text.splitlines():
        for name, forecast in forecasts.items():
            if name in line.upper():
                line = f"{line}{_forecast_phrase(forecast)}"
                break
        lines.append(line)
    return "\n".join(lines)


def accepted_block(
    accepted: list[str], forecasts: dict[str, tuple[float, float] | None]
) -> str:
    """The forecast on each CVE this record accepts, worst first.

    A passing verdict is one line, "ok", so without this the number that matters
    most has nowhere to appear: the one on a flaw accepted until December. It is
    printed on a passing run on purpose — this is where a person decides whether to
    renew a date, and the decision is not prompted by anything else.

    Worst first because that is the order a reader needs; unscored last, because
    "FIRST does not score it" is not a low probability.
    """
    rows = [(name, forecasts[name]) for name in accepted if name in forecasts]
    if not rows:
        return ""
    rows.sort(key=lambda row: (row[1] is None, -(row[1][0] if row[1] else 0.0), row[0]))
    lines = [f"{len(rows)} accepted finding(s), with FIRST's forecast:"]
    lines += [f"  {name}  {_forecast_phrase(forecast).strip()}" for name, forecast in rows]
    lines.append("  A forecast changes no verdict here. It is what to read before "
                 "renewing a review date.")
    return "\n".join(lines)


def report(
    verdict: Verdict,
    forecasts: dict[str, tuple[float, float] | None] | None = None,
    accepted: list[str] | None = None,
) -> None:
    """Print the verdict, with the forecasts where they belong."""
    forecasts = forecasts or {}
    print(annotate(verdict.describe(), forecasts))
    block = accepted_block(accepted or [], forecasts)
    if block:
        print()
        print(block)


def exit_code(verdict: Verdict, forecasts: dict[str, tuple[float, float] | None] | None = None) -> int:
    """1 when the record is wrong, 0 otherwise — and never anything else.

    `forecasts` is accepted and ignored, which is the point: the signature says
    the forecast was available and did not enter the decision.
    """
    return 0 if verdict.ok else 1


def _read_alerts(path: str) -> list[dict]:
    alerts = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(alerts, list):
        raise ValueError(f"{path}: expected the list the code-scanning API returns")
    return alerts


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <open-alerts.json> [closed-alerts.json] "
              f"[{DEFAULT_FILE}]", file=sys.stderr)
        return 2
    try:
        alerts = _read_alerts(argv[1])
        # Optional, and optional on purpose: a run that cannot read the closed
        # alerts still checks everything else, and falls back to the stricter
        # reading of `unused` rather than to no check at all.
        closed = _read_alerts(argv[2]) if len(argv) > 2 and argv[2].endswith(".json") else []
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    record = next((a for a in argv[2:] if not a.endswith(".json")), DEFAULT_FILE)

    exceptions = load_exceptions(record)
    verdict = review(alerts, exceptions, closed=closed)
    print(f"{len(alerts)} open alert(s), {len(blocking(alerts))} of them blocking"
          f"{f', {len(closed)} closed' if closed else ''}\n")
    # Asked after the verdict is decided, so that nothing about the forecast can
    # reach it. An unreachable FIRST gives {} and the report is the one this
    # script printed before EPSS existed.
    forecasts = forecasts_for(cves_of(alerts, exceptions))
    report(verdict, forecasts, accepted=cves_of([], exceptions))
    return exit_code(verdict)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
