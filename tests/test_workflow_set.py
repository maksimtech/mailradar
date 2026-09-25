"""Which workflows this Radar has, and why the rest are not here.

The five Radar had drifted apart without anyone deciding it — on 2026-09-26
exeradar carried eight workflows of fifteen and cookieradar all of them, and the
absences turned out to be nobody's choice rather than anybody's judgement. The
missing ones were ported; this is what keeps them from drifting again.

The core set is required everywhere. Everything else follows from what the
repository actually contains: a Dockerfile, a Docker smoke test, benchmarks —
because a workflow that measures nothing still reports success, which is the
failure mode this project spends most of its tests on.

`KNOWN_GAPS` holds what is still missing and the reason. A gap that is not listed
fails the test; a listed one stays visible until somebody closes it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# Required of every Radar, whatever it does.
CORE = {
    "quality",      # ruff and mypy
    "sonarcloud",   # quality gate and coverage
    "snyk",         # dependencies
    "codeql",       # code scanning
    "bandit",       # Python security lint
    "trivy",        # filesystem CVEs
    "licenses",     # no GPL/AGPL/LGPL creeping in
    "mutation",     # do the tests actually test
    "publish",      # PyPI
    "release",      # GitHub release from a tag
}

# Required only of a Radar that has what they need.
CAPABILITY = {
    "docker-build-check": lambda: (ROOT / "Dockerfile").is_file()
    and (ROOT / "tests" / "docker" / "smoke.py").is_file(),
    "docker": lambda: (ROOT / "Dockerfile").is_file(),
    "docker-scout": lambda: (ROOT / "Dockerfile").is_file(),
    "codspeed": lambda: (ROOT / "tests" / "benchmarks").is_dir()
    or (ROOT / "benchmarks").is_dir(),
}

KNOWN_GAPS = {
}


def present(name: str) -> bool:
    return (WORKFLOWS / f"{name}.yml").is_file()


@pytest.mark.parametrize("name", sorted(CORE))
def test_the_core_workflow_is_here(name):
    assert present(name), f"{name}.yml is missing from a Radar that must have it"


def test_the_test_suite_has_a_workflow():
    """tests.yml in three of them and test.yml in two: the name is not the point,
    running the suite is."""
    assert present("tests") or present("test")


@pytest.mark.parametrize("name", sorted(CAPABILITY))
def test_a_workflow_this_repository_can_support_is_here(name):
    if not CAPABILITY[name]():
        pytest.skip(f"{name} needs something this repository does not have")
    if name in KNOWN_GAPS:
        pytest.xfail(f"{name} is a known gap — see KNOWN_GAPS")
    assert present(name)


def test_every_known_gap_is_still_a_gap():
    """A note that outlives the thing it describes is worse than no note: it
    teaches the reader that the list is stale."""
    for name in KNOWN_GAPS:
        assert not present(name), (
            f"{name}.yml exists now — remove it from KNOWN_GAPS"
        )


def test_no_workflow_is_here_without_being_accounted_for():
    """Anything not in CORE, CAPABILITY or this list is a workflow nobody
    described. Naming them is how the set stays a decision."""
    extra = {
        "docker-publish", "dependabot", "stale", "labeler",
    }
    known = CORE | set(CAPABILITY) | extra | {"tests", "test"}

    found = {path.stem for path in WORKFLOWS.glob("*.yml")}
    assert found <= known, f"undescribed workflows: {sorted(found - known)}"
