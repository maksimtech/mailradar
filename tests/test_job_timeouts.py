"""Every job says how long it may run, so a hung job cannot hold a pull request for six hours.

Without `timeout-minutes` a job runs for GitHub's default of 360 minutes. When it is a
required check the pull request waits that long, and so would an auto-merge
(maksimtech/apkradar#113).

The limits are about three times the longest run of the job in its last 40 runs
(2026-11-20), and never under ten minutes: a short job is mostly installs and image pulls,
which are slow on a bad day without being stuck.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
GITHUB_DEFAULT = 360


def jobs():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (workflow.get("jobs") or {}).items():
            yield f"{path.name}:{name}", job


def test_there_are_jobs_to_look_at():
    assert len(list(jobs())) > 10


def test_every_job_declares_a_timeout_below_the_default():
    wrong = {name: job.get("timeout-minutes") for name, job in jobs()
             if not (isinstance(job.get("timeout-minutes"), int) and 0 < job["timeout-minutes"] < GITHUB_DEFAULT)}
    assert wrong == {}, f"jobs without a timeout under {GITHUB_DEFAULT} minutes: {wrong}"


def test_security_posture_outlives_its_own_wait():
    # The gate waits for the scanners up to a deadline of its own and then says they did not
    # finish. A job timeout shorter than that would kill it first, with no such message.
    job = dict(jobs())["security-posture.yml:posture"]
    script = "\n".join(step.get("run", "") for step in job["steps"])
    wait = int(re.search(r"deadline=\$\(\( SECONDS \+ (\d+) \)\)", script).group(1))
    assert job["timeout-minutes"] * 60 >= wait + 5 * 60
