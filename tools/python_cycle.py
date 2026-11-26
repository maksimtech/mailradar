"""Python's release cycle as data, and the Pythons a Radar should promise from it (#129).

    python tools/python_cycle.py            # print what the copy expects today, and the next due event
    python tools/python_cycle.py --refresh  # read the cycle again from peps.python.org into the copy

The copy, tools/python_release_cycle.json, holds `release-cycle.json` as it was
read, with the day and the URL. Tests read the copy and never the network; only
`--refresh` asks it.

Everything below takes `today` as a parameter: the tests pass fixed dates, and
only tests/test_python_cycle.py's check of the repository uses the real one.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

SOURCE = "https://peps.python.org/api/release-cycle.json"
COPY = Path(__file__).resolve().parent / "python_release_cycle.json"
MARGIN = timedelta(days=14)


@dataclass(frozen=True)
class Expected:
    """What a Radar should promise on a day: stable matrix and classifiers, `-dev` row, requires-python."""
    stable: list[str]
    dev: str
    minimum: str


@dataclass(frozen=True)
class Event:
    when: date
    version: str
    kind: str  # "first release" or "end of life"

    def __str__(self) -> str:
        return f"{self.version} {self.kind} on {self.when.isoformat()}"


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _day(text: str) -> date:
    """A date of the cycle: `2027-10-06`, or a month (`2027-10`) counting from its first day."""
    return date.fromisoformat(text if text.count("-") == 2 else f"{text}-01")


def read_raw(path: Path = COPY) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_cycle(path: Path = COPY) -> dict[str, dict]:
    """Python 3 versions of the copy, by version, with `first_release` and `end_of_life` as dates."""
    releases = read_raw(path)["releases"]
    return {
        version: {"first_release": _day(entry["first_release"]), "end_of_life": _day(entry["end_of_life"])}
        for version, entry in releases.items()
        if version.startswith("3.")
    }


def events(cycle: dict[str, dict]) -> list[Event]:
    found = [Event(entry["first_release"], version, "first release") for version, entry in cycle.items()]
    found += [Event(entry["end_of_life"], version, "end of life") for version, entry in cycle.items()]
    return sorted(found, key=lambda e: (e.when, _key(e.version)))


def _state(cycle: dict[str, dict], happened) -> Expected:
    """The promise once every event for which `happened(event)` is true has been followed."""
    stable = sorted(
        (version for version in cycle
         if happened(Event(cycle[version]["first_release"], version, "first release"))
         and not happened(Event(cycle[version]["end_of_life"], version, "end of life"))),
        key=_key,
    )
    major, minor = _key(stable[-1])
    return Expected(stable=stable, dev=f"{major}.{minor + 1}-dev", minimum=stable[0])


def expected_pythons(cycle: dict[str, dict], today: date) -> Expected:
    """Released by `today` and not past end of life; the dev row is the minor after the newest."""
    return _state(cycle, lambda event: event.when <= today)


def patch_tuesday(year: int, month: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(1 - first.weekday()) % 7 + 7)


def due(event_day: date) -> date:
    """14 days after the event, moved to the Monday after when that falls in a
    Patch Tuesday week (Monday to Friday around the second Tuesday)."""
    day = event_day + MARGIN
    tuesday = patch_tuesday(day.year, day.month)
    if tuesday - timedelta(days=1) <= day <= tuesday + timedelta(days=3):
        return tuesday + timedelta(days=6)
    return day


def accepted(cycle: dict[str, dict], today: date) -> list[Expected]:
    """The states a repository may be in on `today`: with every due event followed,
    and, for events that happened but are not due yet, followed or not."""
    strict = _state(cycle, lambda event: due(event.when) <= today)
    early = _state(cycle, lambda event: event.when <= today)
    return [strict] if strict == early else [strict, early]


def next_due(cycle: dict[str, dict], today: date) -> tuple[date, str]:
    """The next event whose due day is after `today`, as (due day, description)."""
    upcoming = sorted((due(event.when), event) for event in events(cycle) if due(event.when) > today)
    when, event = upcoming[0]
    return when, str(event)


def explain(cycle: dict[str, dict], today: date, *, stable: list[str], dev: str, minimum: str) -> str:
    """Why the repository's Pythons are not among those accepted on `today`, and what to change."""
    lines = [f"The Pythons of this Radar do not follow Python's release cycle on {today.isoformat()}:"]
    for event in events(cycle):
        if due(event.when) > today:
            continue
        if event.kind == "first release" and event.version not in stable and _key(event.version) > _key(stable[-1]):
            lines.append(f"- {event} (release-cycle.json), due {due(event.when).isoformat()}: add {event.version} "
                         f"to the stable matrix and the classifiers, and move the -dev row on")
        if event.kind == "end of life" and event.version in stable:
            lines.append(f"- {event} (release-cycle.json), due {due(event.when).isoformat()}: take "
                         f"{event.version} out of the matrix and the classifiers, and raise requires-python")
    want = accepted(cycle, today)[0]
    lines.append(f"Expected: stable {want.stable}, dev row {want.dev}, requires-python >={want.minimum}.")
    lines.append(f"Found: stable {stable}, dev row {dev}, requires-python >={minimum}.")
    lines.append("Change .github/workflows/tests.yml, the classifiers and requires-python in pyproject.toml, "
                 "and the ruleset's required Tests rows with it.")
    return "\n".join(lines)


def end_of_life(cycle: dict[str, dict], version: str) -> date:
    return cycle[version]["end_of_life"]


def refresh(path: Path = COPY, today: date | None = None) -> None:
    """Read the cycle again from peps.python.org and write the copy, with the day and the source."""
    import httpx

    response = httpx.get(SOURCE, timeout=30)
    response.raise_for_status()
    releases = response.json()
    data = {"source": SOURCE, "read_on": (today or date.today()).isoformat(), "releases": releases}
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh", action="store_true", help="read the cycle again from peps.python.org")
    args = parser.parse_args(argv)
    if args.refresh:
        refresh()
        print(f"{COPY.name} read from {SOURCE} on {date.today().isoformat()}")
    cycle = load_cycle()
    today = date.today()
    want = expected_pythons(cycle, today)
    print(f"On {today.isoformat()}: stable {want.stable}, dev row {want.dev}, requires-python >={want.minimum}")
    when, what = next_due(cycle, today)
    print(f"Next due: {what}, due {when.isoformat()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
