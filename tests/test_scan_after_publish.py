"""Docker Scout reads the image as soon as it is published, and the Security Posture gate reads that scan.

Docker Scout scans maksimtech/mailradar:latest from Docker Hub. It ran on a push to main, on a schedule and by
hand, never after a new image was pushed: on 2026-10-24, after the certifi release, every Radar's gate stayed red
on the published image's old certifi until Docker Scout was dispatched by hand, image by image, and the gate run
again. Now the scan follows the workflow that pushes the image, and the gate follows the scan.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
# The workflows that push maksimtech/mailradar to Docker Hub
IMAGE_WORKFLOWS = ["Build and Push Docker Image"]


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def triggers(workflow: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as the boolean True
    return workflow.get("on", workflow.get(True)) or {}


def names_of_workflows() -> set[str]:
    return {load(path.name).get("name") for path in WORKFLOWS.glob("*.yml")}


@pytest.fixture(scope="module")
def scout() -> dict:
    return load("docker-scout.yml")


@pytest.fixture(scope="module")
def posture() -> dict:
    return load("security-posture.yml")


def test_the_scan_follows_the_workflow_that_pushes_the_image(scout):
    run = triggers(scout).get("workflow_run")
    assert run, "docker-scout.yml has no workflow_run trigger"
    assert sorted(run["workflows"]) == sorted(IMAGE_WORKFLOWS)
    assert run["types"] == ["completed"]


def test_the_workflows_it_follows_exist():
    """workflow_run matches by name: a misspelt one would make the trigger silently never fire."""
    assert set(IMAGE_WORKFLOWS) <= names_of_workflows()


def test_a_failed_push_triggers_no_scan(scout):
    """Nothing new is on Docker Hub when the image workflow failed: scanning would re-read the old image."""
    for job in scout["jobs"].values():
        condition = " ".join(str(job.get("if", "")).split())
        assert "github.event.workflow_run.conclusion == 'success'" in condition
        assert "github.event_name != 'workflow_run'" in condition


def test_the_gate_follows_the_scan(posture):
    run = triggers(posture).get("workflow_run")
    assert run, "security-posture.yml has no workflow_run trigger"
    assert run["workflows"] == ["Docker Scout CVE Scan"]
    assert run["types"] == ["completed"]
    assert "Docker Scout CVE Scan" in names_of_workflows()


def test_the_scan_still_runs_by_hand_and_on_its_schedule(scout):
    on = triggers(scout)
    assert "workflow_dispatch" in on and "schedule" in on


def test_the_customer_document_says_when_the_image_is_scanned():
    """docs/nis2-compliance.md is held to what the repository does: the row for Docker Scout names the build."""
    doc = (WORKFLOWS.parent.parent / "docs" / "nis2-compliance.md").read_text(encoding="utf-8")
    row = next(line for line in doc.splitlines() if line.startswith("| `Docker Scout` |"))
    assert "ogni build dell'immagine" in row
