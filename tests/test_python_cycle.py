"""The Pythons this Radar promises follow Python's own release cycle, read as data (maksimtech/apkradar#129).

The stable matrix, the `-dev` row, the classifiers, `requires-python` and the
image's Python were typed by hand, and the tests checked them against each
other, not against Python's cycle: when a version went final or reached end of
life nothing turned red, and a promise could go stale silently.

Python publishes the cycle as data (https://peps.python.org/api/release-cycle.json).
A copy lives in tools/python_release_cycle.json with the day it was read, and
`python tools/python_cycle.py --refresh` renews it. Nothing here asks the network.

- The logic, `expected_pythons(cycle, today)`, takes `today` as a parameter, and
  its tests pass fixed dates: they never expire.
- One check uses the real date, on purpose, as the `review_by` of
  SECURITY-EXCEPTIONS.toml does: the repository against the cycle. An event (a
  first release, an end of life) is due 14 days after it happens, moved to the
  Monday after when that falls in the week of a Patch Tuesday. Before it is due
  either state is accepted; after, only the new one. The failure names the
  event, the day it became due, and what to change. October 2027 brings both at
  once: 3.16 final (due 2027-10-20) and 3.11's end of life (due 2027-10-18).

Dates are the JSON's: for 3.16.0 it gives 2027-10-06, while PEP 826's schedule
says Tuesday 2027-10-05 (maksimtech/apkradar#129). The margin absorbs the day.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("python_cycle", ROOT / "tools" / "python_cycle.py")
python_cycle = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = python_cycle
_spec.loader.exec_module(python_cycle)

CYCLE = python_cycle.load_cycle()
due = python_cycle.due
expected_pythons = python_cycle.expected_pythons


# ─── the logic, on fixed dates ──────────────────────────────────────────────

def test_on_2026_11_22_the_cycle_gives_3_11_to_3_15_and_3_16_dev():
    expected = expected_pythons(CYCLE, date(2026, 11, 22))
    assert expected.stable == ["3.11", "3.12", "3.13", "3.14", "3.15"]
    assert expected.dev == "3.16-dev"
    assert expected.minimum == "3.11"


def test_on_3_16_s_release_day_it_is_stable_and_3_17_is_the_dev_row():
    """The dev row is the minor after the newest released one, not the version
    the snapshot calls `feature`: the copy read today does not know 3.17."""
    expected = expected_pythons(CYCLE, date(2027, 10, 6))
    assert expected.stable[-1] == "3.16"
    assert expected.dev == "3.17-dev"


def test_after_3_11_s_end_of_life_3_12_is_the_minimum():
    """An end of life given as a month (`2027-10`) counts from its first day."""
    assert "3.11" in expected_pythons(CYCLE, date(2027, 9, 30)).stable
    expected = expected_pythons(CYCLE, date(2027, 10, 1))
    assert "3.11" not in expected.stable
    assert expected.minimum == "3.12"


def test_patch_tuesday_is_the_second_tuesday():
    assert python_cycle.patch_tuesday(2027, 10) == date(2027, 10, 12)
    assert python_cycle.patch_tuesday(2026, 12) == date(2026, 12, 8)


@pytest.mark.parametrize("event, expected", [
    (date(2027, 10, 6), date(2027, 10, 20)),   # 3.16 final: +14 days, outside the Patch Tuesday week
    (date(2027, 10, 1), date(2027, 10, 18)),   # 3.11 end of life: +14 = Fri 15, in the week of the 12th → Mon 18
    (date(2026, 11, 26), date(2026, 12, 14)),  # +14 = Thu 10 Dec, in the week of Tue 8 Dec → Mon 14
])
def test_an_event_is_due_14_days_later_out_of_a_patch_tuesday_week(event, expected):
    assert due(event) == expected


def test_before_an_event_is_due_both_states_are_accepted():
    """On 2027-10-10, 3.16 is out but not yet due: the matrix may have it or not."""
    accepted = python_cycle.accepted(CYCLE, date(2027, 10, 10))
    assert {e.stable[-1] for e in accepted} == {"3.15", "3.16"}


def test_once_due_only_the_new_state_is_accepted():
    accepted = python_cycle.accepted(CYCLE, date(2027, 10, 21))
    assert [(e.stable[0], e.stable[-1], e.dev) for e in accepted] == [("3.12", "3.16", "3.17-dev")]


def test_the_failure_names_the_event_the_day_it_became_due_and_what_to_change():
    message = python_cycle.explain(CYCLE, date(2027, 10, 21), stable=["3.11", "3.12", "3.13", "3.14", "3.15"],
                                   dev="3.16-dev", minimum="3.11")
    assert "3.11 end of life" in message and "2027-10-18" in message
    assert "3.16 first release" in message and "2027-10-20" in message
    assert "tests.yml" in message and "pyproject.toml" in message


def test_the_next_due_event_is_named_in_advance():
    when, what = python_cycle.next_due(CYCLE, date(2026, 11, 26))
    assert when == date(2027, 10, 18) and "3.11" in what and "end of life" in what


# ─── this repository against the cycle, on the real date ────────────────────

def _repository_pythons() -> tuple[list[str], str, str]:
    """(stable matrix, -dev row, requires-python minimum) as this repository has them."""
    path = next(p for p in (ROOT / ".github" / "workflows" / n for n in ("tests.yml", "test.yml")) if p.is_file())
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    matrix = workflow["jobs"]["test"]["strategy"]["matrix"]
    stable = [str(v) for v in matrix["python-version"]]
    dev = [row["python-version"] for row in matrix.get("include", []) if row.get("experimental") is True]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    minimum = re.fullmatch(r">=\s*(\d+\.\d+)", project["requires-python"])
    assert minimum, f"requires-python is {project['requires-python']!r}, not '>=X.Y'"
    classified = sorted(
        (c.rsplit("::", 1)[1].strip() for c in project["classifiers"]
         if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)),
        key=lambda v: tuple(map(int, v.split("."))),
    )
    assert classified == stable, f"the classifiers say {classified}, the matrix runs {stable}"
    return stable, ",".join(dev), minimum[1]


def test_the_matrix_follows_python_s_release_cycle():
    """Deliberately on the real date: red once an event is due and not followed.
    The classifiers must say what the matrix runs."""
    today = date.today()
    stable, dev, minimum = _repository_pythons()
    accepted = python_cycle.accepted(CYCLE, today)
    assert any((stable, dev, minimum) == (e.stable, e.dev, e.minimum) for e in accepted), (
        python_cycle.explain(CYCLE, today, stable=stable, dev=dev, minimum=minimum)
    )


def test_the_image_python_is_still_supported():
    """Which supported version the image runs is the maintainer's decision
    (tests/test_docker_python.py); that it is still supported is checked here,
    with the same margin after its end of life."""
    image = re.search(r"^FROM python:(\d+\.\d+)-", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.M)[1]
    end = python_cycle.end_of_life(CYCLE, image)
    assert date.today() < due(end), (
        f"the image runs Python {image}, past its end of life on {end.isoformat()} "
        f"(due {due(end).isoformat()}): move the Dockerfile and tests/test_docker_python.py on"
    )


def test_the_copy_says_when_it_was_read_and_from_where():
    data = python_cycle.read_raw()
    assert data["source"] == "https://peps.python.org/api/release-cycle.json"
    assert date.fromisoformat(data["read_on"]) <= date.today()
    assert "3.16" in data["releases"]
