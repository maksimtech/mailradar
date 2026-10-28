"""Docker Scout's CVE scan decides the job; its base-image recommendations only advise.

docker-scout.yml ran `command: cves,recommendations` in one step. From
2026-10-24 every run failed: the CVEs were scanned and printed, then the
scout CLI crashed in the recommendations part (`panic: runtime error: invalid
memory address or nil pointer dereference`, in
internal/format/recommendations/markdown.go) on the images built on
python:3.12-slim-trixie, with scout-action 1.27 and 1.28 alike. The job went
red and GitHub mailed a failure for every push to main, while the scan that
matters had worked.

So the scan is a step of its own that writes the SARIF and fails the job if
it fails, and the recommendations are a second step that may fail without
failing the job: a crash in advice must not read as a failed scan, and must
not hide one either.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _scout_steps(name: str) -> list[dict]:
    doc = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    steps = [step for job in doc["jobs"].values() for step in job.get("steps", [])]
    return [s for s in steps if str(s.get("uses", "")).startswith("docker/scout-action@")]


def _commands(step: dict) -> set[str]:
    return {c.strip() for c in str(step.get("with", {}).get("command", "")).split(",")}


def test_the_cve_scan_and_the_recommendations_are_separate_steps():
    for step in _scout_steps("docker-scout.yml"):
        assert _commands(step) != {"cves", "recommendations"}, f"{step.get('name')} runs both in one step"


def test_the_cve_scan_writes_the_sarif_and_can_fail_the_job():
    scans = [s for s in _scout_steps("docker-scout.yml") if "cves" in _commands(s)]
    assert len(scans) == 1
    assert scans[0]["with"].get("sarif-file")
    assert not scans[0].get("continue-on-error")


def test_the_recommendations_cannot_fail_the_job():
    advice = [s for s in _scout_steps("docker-scout.yml") if "recommendations" in _commands(s)]
    assert len(advice) == 1, "the recommendations are still worth having"
    assert advice[0].get("continue-on-error") is True
    assert not advice[0].get("with", {}).get("sarif-file"), "only the scan feeds the Security tab"


def test_the_image_workflow_scan_still_fails_on_its_own():
    """docker.yml scans with `cves` alone and was never affected; it stays so."""
    for step in _scout_steps("docker.yml"):
        assert _commands(step) == {"cves"}
        assert not step.get("continue-on-error")
