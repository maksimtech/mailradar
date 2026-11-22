"""Every job runs on the same runner image, named, never `ubuntu-latest`.

The jobs moved to ubuntu-26.04 on 2026-10-02, except CodSpeed's: CodSpeedHQ/action
v5 failed there with "Unsupported system". CodSpeed added Ubuntu 26.04 in runner
and action v5.5.0 (2026-10-14), and the last job followed on 2026-11-22, as in
apkradar, whose tests/test_runners.py this is.

`ubuntu-latest` is not used anywhere: it moves to a new image on GitHub's
schedule, and a job that breaks then breaks on main at a moment nobody picked.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
IMAGE = "ubuntu-26.04"


def jobs():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (workflow.get("jobs") or {}).items():
            yield f"{path.name}:{name}", job.get("runs-on")


def test_there_are_jobs_to_look_at():
    assert len(list(jobs())) > 10


def test_every_job_runs_on_the_same_named_image():
    elsewhere = {job: runner for job, runner in jobs() if runner != IMAGE}
    assert elsewhere == {}, f"jobs not on {IMAGE}: {elsewhere}"
