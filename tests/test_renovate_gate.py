"""A Renovate pull request merges only when Renovate's own checks are green.

This is apkradar's gate (alignment to apkradar, step 4), for the reason it was
made there. On 2026-11-19 apkradar#81 locked a release seven days old under
another title.
Renovate said so: its `renovate/artifacts` status failed. But GitHub's
auto-merge waits only for the required checks, and that status is not one, so
the pull request was merged. Making `renovate/artifacts` required is not
possible: pull requests that are not Renovate's never get it and would wait
forever. `platformAutomerge: false` is not either: Renovate then merges only
with every check green, and the 3.16-dev row is red by choice.

So a required job, "Renovate gate", reads the statuses Renovate set on the head
commit of the pull request: on a `renovate/` branch every `renovate/*` status
has to be green; any other pull request passes at once.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("renovate_gate", ROOT / "tools" / "renovate_gate.py")
renovate_gate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = renovate_gate
_spec.loader.exec_module(renovate_gate)

WORKFLOW = ROOT / ".github" / "workflows" / "renovate-gate.yml"
RENOVATE = ROOT / ".github" / "renovate.json"
# Renovate's own default for `branchPrefix` (lib/config/options/index.ts)
RENOVATE_DEFAULT_BRANCH_PREFIX = "renovate/"


def status(context, state, description=""):
    return {"context": context, "state": state, "description": description}


class TestVerdict:
    def test_a_pull_request_that_is_not_renovate_s_passes(self):
        ok, why = renovate_gate.verdict("fix/something", [status("renovate/artifacts", "failure")])
        assert ok, why

    def test_81_is_refused(self):
        """#81's head: stability-days green, artifacts failed."""
        statuses = [status("renovate/stability-days", "success", "Updates have met minimum release age requirement"),
                    status("renovate/artifacts", "failure", "Artifact file update failure")]
        ok, why = renovate_gate.verdict("renovate/pytest-asyncio-1.x-lockfile", statuses)
        assert not ok
        assert "renovate/artifacts" in why and "Artifact file update failure" in why

    def test_a_release_younger_than_its_wait_is_refused(self):
        ok, _ = renovate_gate.verdict("renovate/ruff-0.x-lockfile", [status("renovate/stability-days", "pending")])
        assert not ok

    def test_all_green_passes(self):
        statuses = [status("renovate/stability-days", "success"), status("renovate/artifacts", "success")]
        ok, why = renovate_gate.verdict("renovate/mypy-2.x-lockfile", statuses)
        assert ok, why

    def test_no_renovate_status_passes(self):
        """An update with no wait (a pinDigest, a security fix) may get no Renovate status at all."""
        ok, why = renovate_gate.verdict("renovate/pin-dependencies", [])
        assert ok, why

    def test_statuses_of_other_tools_are_not_this_gate_s_business(self):
        ok, why = renovate_gate.verdict("renovate/mypy-2.x-lockfile", [status("codecov/patch", "failure")])
        assert ok, why


class TestWorkflow:
    def workflow(self):
        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_it_runs_on_every_pull_request_to_main(self):
        triggers = self.workflow()[True]  # YAML 1.1 reads the key `on` as True
        assert triggers["pull_request"]["branches"] == ["main"]
        assert "paths" not in triggers["pull_request"], "a required check that does not run blocks the PR"

    def test_the_job_is_named_as_the_ruleset_requires_it(self):
        [job] = self.workflow()["jobs"].values()
        assert job["name"] == "Renovate gate"

    def test_it_reads_the_head_commit_of_the_pull_request(self):
        """github.sha is the merge commit GitHub makes for the run: Renovate set nothing on it."""
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "github.event.pull_request.head.sha" in text
        assert "github.head_ref" in text

    def test_it_can_only_read(self):
        assert self.workflow()["permissions"] == {"contents": "read", "statuses": "read"}


class TestBranchPrefix:
    """The gate knows a Renovate pull request by its branch name (apkradar#114). If
    Renovate's `branchPrefix` changed and the gate's did not, every Renovate pull request
    would look like somebody else's and pass at once: the gap of apkradar#83 back, with
    every check green."""

    def test_the_gate_and_renovate_agree_on_the_branch_prefix(self):
        config = json.loads(RENOVATE.read_text(encoding="utf-8"))
        prefixes = {config.get("branchPrefix", RENOVATE_DEFAULT_BRANCH_PREFIX)}
        prefixes |= {rule["branchPrefix"] for rule in config.get("packageRules", []) if "branchPrefix" in rule}
        assert prefixes == {renovate_gate.BRANCH_PREFIX}, prefixes

    def test_the_constant_is_the_one_the_verdict_uses(self):
        red = [status("renovate/artifacts", "failure")]
        ok, _ = renovate_gate.verdict(renovate_gate.BRANCH_PREFIX + "mypy-2.x-lockfile", red)
        assert not ok
        ok, _ = renovate_gate.verdict("not-" + renovate_gate.BRANCH_PREFIX + "mypy-2.x-lockfile", red)
        assert ok
