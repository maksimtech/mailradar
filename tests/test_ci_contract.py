"""The Tests workflow never ran the tests.

Checked on 2026-09-25: `.github/workflows/test.yml` is called Tests, publishes the
check name the branch ruleset requires, and its only step runs

    mailradar --help
    mailradar check maksimtech.com
    mailradar discover maksimtech.com --no-gpg

There are 368 tests in this repository and the workflow invoked none of them. The
suite could not fail the build, and `pip install -e .` without the dev extra meant
pytest was not even installed to run it with. PatchRadar had the same defect and
fixed it; this is the same guard, here.

Two of those three commands also query a real domain over the network from a
GitHub runner, so the one check that did exist depended on DNS and on somebody
else's mail server being up.

The second half is the coverage upload, which has three silent failure modes: no
XML is produced, the file produced is not the file uploaded, or the step is
guarded to a Python version the matrix does not contain. `fail_ci_if_error: false`
means none of them reddens the build — they just leave Codecov with nothing,
which reads as absent coverage rather than as a broken upload.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    return TEST_WORKFLOW.read_text(encoding="utf-8")


# ── the suite has to run ────────────────────────────────────────────────────


def test_the_workflow_invokes_pytest(workflow):
    assert re.search(r"\bpytest\b", workflow), (
        "the Tests workflow never invokes pytest — 368 tests cannot fail the build"
    )


def test_the_workflow_runs_the_tests_directory(workflow):
    assert re.search(r"pytest[^\n]*\btests/", workflow)


def test_the_workflow_installs_what_the_suite_needs(workflow):
    """`pip install -e .` alone does not bring pytest, so the step above would
    fail on a missing command rather than on a failing test."""
    assert re.search(r"pip install[^\n]*\[dev\]", workflow), (
        "the dev extra is not installed, so pytest is not there to run"
    )


def test_no_step_queries_the_network_for_a_smoke_test(workflow):
    """`mailradar check maksimtech.com` and `discover` reach DNS and a mail server
    from the runner. A suite of 368 tests does not need a live domain to say
    whether this code works, and a check that depends on one is a check that goes
    red for reasons that have nothing to do with the commit."""
    for command in ("mailradar check ", "mailradar discover "):
        assert command not in workflow, f"{command.strip()} runs against a live domain"


def test_the_cli_is_still_exercised(workflow):
    """--help costs nothing, needs no network, and catches an import error or a
    broken entry point — which the suite, importing modules directly, does not."""
    assert "mailradar --help" in workflow


# ── the coverage upload ─────────────────────────────────────────────────────


def test_the_suite_writes_a_coverage_report(workflow):
    assert "--cov-report=xml" in workflow, "no XML is produced, so nothing can be uploaded"


def test_the_file_uploaded_is_the_file_written(workflow):
    """A path typo here reads as zero coverage, not as a broken upload."""
    written = re.search(r"--cov-report=xml(?::(\S+))?", workflow)
    assert written, "no XML report is written"
    produced = written.group(1) or "coverage.xml"

    uploaded = re.search(r"^\s*files?:\s*(\S+)", workflow, re.MULTILINE)
    assert uploaded, "the upload step names no file"
    assert uploaded.group(1) == produced


def test_the_upload_runs_once_on_a_version_the_matrix_has(workflow):
    """Guarded to one entry, so one measurement is not uploaded four times — and
    that entry has to exist, or the step never runs at all."""
    import yaml

    parsed = yaml.safe_load(workflow)
    versions = {
        str(version)
        for job in parsed["jobs"].values()
        for version in (job.get("strategy", {}).get("matrix", {}).get("python-version") or [])
    }

    guard = re.search(r"matrix\.python-version\s*==\s*'([^']+)'", workflow)
    assert guard, "the upload is not guarded to a single matrix entry"
    assert guard.group(1) in versions, (
        f"the upload is pinned to Python {guard.group(1)}, absent from {sorted(versions)}"
    )


def test_the_upload_is_given_a_token(workflow):
    """Codecov wants one even for a public repository; without it the upload is
    rejected — silently, like everything else here."""
    assert "CODECOV_TOKEN" in workflow


def test_the_actions_are_pinned_by_sha(workflow):
    """This repository pins its actions to a full commit, and a new step should
    not be the one exception."""
    for uses in re.findall(r"uses:\s*(\S+)", workflow):
        assert re.search(r"@[0-9a-f]{40}$", uses), f"{uses} is not pinned to a commit"


def test_the_benchmarks_are_not_run_without_their_plugin(workflow):
    """tests/benchmarks imports pytest-codspeed, which the dev extra does not
    declare: running them here would replace a check that tested nothing with one
    that fails every time. codspeed.yml runs them with what they need.

    Stated as the invariant rather than as the command, so it still holds if the
    plugin is added to the extra one day.
    """
    import tomllib

    benchmarks = ROOT / "tests" / "benchmarks"
    if not benchmarks.is_dir():
        pytest.skip("no benchmarks in this repository")

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = declared.get("project", {}).get("optional-dependencies", {})
    plugin_declared = any(
        "pytest-codspeed" in package
        for packages in extras.values()
        for package in packages
    )

    assert plugin_declared or "--ignore=tests/benchmarks" in workflow, (
        "the suite runs tests/benchmarks and pytest-codspeed is not declared"
    )
