"""Every workflow that runs pytest installs the dependencies the project declares.

The rule exists because breaking it is invisible until a dependency is added.
sonarcloud.yml installed `pip install -e .` plus a hand-written list of pytest
plugins rather than the declared extra, so it had a different set of packages
from tests.yml — and on 2026-09-24, adding hypothesis broke the SonarCloud run
with `ModuleNotFoundError: No module named 'hypothesis'` while the test workflow
stayed green.

A list written by hand cannot stay in step with pyproject.toml. The extra can.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# How this project declares its test dependencies.
DECLARED_INSTALL = 'pip install -e ".[dev]"'

# Plugins that belong to one workflow and are not project dependencies.
WORKFLOW_ONLY = {"pytest-codspeed"}

# pip flags whose next token is a value rather than a package.
FLAGS_TAKING_A_VALUE = {
    "--only-binary", "--no-binary", "--index-url", "--extra-index-url",
    "--find-links", "--constraint", "-c", "--requirement", "-r", "--target", "-t",
}


def _run_scripts(path: pathlib.Path) -> list[str]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    scripts = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps", []):
            if isinstance(step.get("run"), str):
                scripts.append(step["run"])
    return scripts


def _workflows_running_pytest() -> list[pathlib.Path]:
    return [
        path for path in sorted(WORKFLOWS.glob("*.yml"))
        if any(re.search(r"\bpytest\b", script) for script in _run_scripts(path))
    ]


def _named_packages(line: str) -> set[str]:
    """The distributions a pip line installs by name.

    Three things are not names, and all three were mistaken for one on the first
    attempt: the editable target itself (`-e ".[dev]"`, whose quoting hides the
    dot), the value of a flag such as `--only-binary :all:`, and any flag.
    """
    line = line.split("#", 1)[0].strip()
    if not line.startswith("pip install"):
        return set()

    names: set[str] = set()
    skip_next = False
    for token in line.removeprefix("pip install").split():
        if skip_next:
            skip_next = False
            continue
        if token in ("-e", "--editable"):
            skip_next = True                      # the target, not a package
            continue
        if token.startswith("-"):
            skip_next = token in FLAGS_TAKING_A_VALUE
            continue
        name = re.split(r"[<>=!~\[]", token.strip("\"'"), maxsplit=1)[0]
        if name and name not in WORKFLOW_ONLY:
            names.add(name)
    return names


@pytest.mark.parametrize("path", _workflows_running_pytest(), ids=lambda p: p.name)
def test_a_workflow_that_runs_pytest_installs_the_declared_extra(path):
    scripts = "\n".join(_run_scripts(path))
    assert DECLARED_INSTALL in scripts, (
        f"{path.name} runs pytest but does not install {DECLARED_INSTALL}"
    )


@pytest.mark.parametrize("path", _workflows_running_pytest(), ids=lambda p: p.name)
def test_no_workflow_installs_test_packages_by_hand(path):
    """A package named on a pip line is a package pyproject.toml does not control."""
    stray: set[str] = set()
    for script in _run_scripts(path):
        for line in script.splitlines():
            stray |= _named_packages(line)
    assert not stray, f"{path.name} installs {sorted(stray)} outside pyproject.toml"


def test_the_detector_tells_a_name_from_a_flag_or_a_target():
    """Otherwise a green run would mean only that the detector is broken."""
    assert _named_packages('pip install -e ".[dev]"') == set()
    assert _named_packages("pip install -e .") == set()
    assert _named_packages("pip install pytest-codspeed --only-binary :all:") == set()
    assert _named_packages("pip install pytest pytest-cov") == {"pytest", "pytest-cov"}
    assert _named_packages('pip install "ruff>=0.16"') == {"ruff"}
    assert _named_packages("python -m pip install --upgrade pip") == set()


def test_the_rule_looks_at_something():
    """A check that matched no workflow would pass for the wrong reason."""
    assert _workflows_running_pytest(), "no workflow runs pytest?"
