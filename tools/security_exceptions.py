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

    @property
    def ok(self) -> bool:
        return not (self.unexplained or self.expired or self.unused)

    def describe(self) -> str:
        """For whoever has to act. The exit code is for the machine."""
        if self.ok:
            return "ok: every blocking alert is explained and every exception is in date"

        lines: list[str] = []
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
           today: dt.date | None = None) -> Verdict:
    """The three ways this can fail, reported together rather than one at a time.

    An alert that is explained by an overdue exception appears under `expired`
    and not under `unexplained`: both facts are true, and hiding the second
    behind the first is how an exception becomes permanent.

    `unused` is only reported for a scanner that said something. An empty list of
    alerts is not a clean product — it is also what a scan that failed to upload
    produces — and calling every exception stale there would fail the build for
    the one reason that is not the product's fault.
    """
    today = today or dt.date.today()
    interesting = blocking(alerts)
    tools_that_spoke = {_tool_of(a) for a in alerts}

    unexplained = [a for a in interesting
                   if not any(entry.covers(a) for entry in exceptions)]
    expired = [entry for entry in exceptions if entry.overdue(today)]
    unused = [
        entry for entry in exceptions
        if not any(entry.covers(a) for a in alerts)
        and (entry.source in tools_that_spoke if entry.source else bool(alerts))
    ]
    return Verdict(unexplained=unexplained, expired=expired, unused=unused)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <alerts.json> [{DEFAULT_FILE}]", file=sys.stderr)
        return 2
    alerts = json.loads(pathlib.Path(argv[1]).read_text(encoding="utf-8"))
    if not isinstance(alerts, list):
        print(f"{argv[1]}: expected the list the code-scanning API returns", file=sys.stderr)
        return 2
    record = argv[2] if len(argv) > 2 else DEFAULT_FILE

    verdict = review(alerts, load_exceptions(record))
    print(f"{len(alerts)} open alert(s), {len(blocking(alerts))} of them blocking\n")
    print(verdict.describe())
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
