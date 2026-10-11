"""What Security Posture reads on a pull request, and when it reads it.

On 2026-10-11 the gate was found to judge every pull request by the state of
main. Measured on mailradar #39: the step that waits for the scanners finished
in two seconds, because it compared the runs' head commit with GITHUB_SHA, which
on a pull request is the merge commit and matches no run; and the alerts were
listed without a `ref`, which is main's. A finding a pull request introduced
reached main before the gate could see it.

Measured the same day on one recent pull request of each of the six Radar, with
the real tool: the open alerts of `refs/pull/N/merge` (CodeQL reports there only
what the change introduces) checked against the closed alerts of both that ref
and main gave the same verdict as main in all six. The closed alerts of main are
needed: an exception whose finding went quiet is "settled" because main still
holds the closed alert, and a pull request ref, which has no history, would call
it unused and fail every pull request.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
POSTURE = WORKFLOWS / "security-posture.yml"


def _steps() -> dict[str, dict]:
    workflow = yaml.safe_load(POSTURE.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    return {step.get("name", ""): step for step in job["steps"]}


@pytest.fixture(scope="module")
def wait() -> dict:
    return _steps()["Wait for this commit's analyses"]


@pytest.fixture(scope="module")
def collect() -> dict:
    return _steps()["Collect the open alerts"]


def test_the_wait_looks_for_the_runs_of_the_commit_under_review(wait):
    """On a pull request the scanners' runs carry the head of the branch, not the
    merge commit GITHUB_SHA names."""
    assert wait["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert 'os.environ["HEAD_SHA"]' in wait["run"]
    assert 'os.environ["GITHUB_SHA"]' not in wait["run"]


def test_the_wait_knows_every_workflow_that_uploads_alerts(wait):
    """A scanner left off the list is not waited for, and its alerts are read
    before it has uploaded them. Bandit was off the list until 2026-10-11."""
    uploaders = set(wait["env"]["UPLOADERS"].split(","))
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "upload-sarif" in text or "codeql-action/analyze" in text:
            name = yaml.safe_load(text)["name"]
            assert name in uploaders, f"{path.name} ({name}) uploads alerts and is not waited for"


def test_the_open_alerts_are_those_of_the_ref_under_review(collect):
    """github.ref is refs/pull/N/merge on a pull request and refs/heads/main on a
    push, a schedule or a dispatch: the same call serves both."""
    assert collect["env"]["ALERT_REF"] == "${{ github.ref }}"
    assert "alerts?state=open&per_page=100&ref=${ALERT_REF}" in collect["run"]


def test_the_closed_alerts_come_from_the_ref_and_from_main(collect):
    """main's closed alerts keep a quiet finding "settled" on a pull request,
    where the ref has no history of its own."""
    run = collect["run"]
    assert "alerts?state=closed&per_page=100&ref=${ALERT_REF}" in run
    assert "alerts?state=closed&per_page=100&ref=refs/heads/main" in run
    assert "closed.json" in run
