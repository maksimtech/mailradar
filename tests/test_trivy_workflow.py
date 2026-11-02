"""What trivy.yml scans: the repository's files, and the image a pull request builds.

Until 2026-11-02 the image a pull request builds was scanned by Snyk Container
alone — Trivy read the files and Docker Scout reads `latest` only once it has been
published. snyk.yml was retired (tests/test_workflow_set.py, RETIRED), and its one
part that worked moved here. These tests hold the two lessons that part had
already paid for: a fixed image name, and a category of its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TRIVY = ROOT / ".github" / "workflows" / "trivy.yml"


def workflow() -> dict:
    return yaml.safe_load(TRIVY.read_text(encoding="utf-8"))


def triggers() -> dict:
    loaded = workflow()
    # PyYAML reads the bare key `on` as the boolean True.
    return loaded.get(True, loaded.get("on"))


def job_scanning(scan_type: str) -> dict:
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if "trivy-action" in step.get("uses", "") and step["with"].get("scan-type") == scan_type:
                return job
    raise AssertionError(f"no job in trivy.yml runs a Trivy {scan_type} scan")


def step_using(job: dict, fragment: str) -> dict:
    return next(step for step in job["steps"] if fragment in step.get("uses", ""))


@pytest.fixture(scope="module")
def image_job() -> dict:
    return job_scanning("image")


def test_the_image_is_scanned_on_every_pull_request():
    assert "pull_request" in triggers()
    assert "push" in triggers()


def test_the_image_scanned_is_the_one_this_dockerfile_builds(image_job):
    """Not `latest` from Docker Hub — that is Docker Scout's, and it describes the
    last release, not the change under review."""
    build = next(step for step in image_job["steps"] if "docker build" in str(step.get("run", "")))
    tag = build["run"].split("-t", 1)[1].split()[0].strip("\"'")
    scan = step_using(image_job, "trivy-action")

    assert scan["with"]["image-ref"] == tag
    assert "Dockerfile" in build["if"], "a Radar without a Dockerfile has no image to build"
    assert f"steps.{build['id']}.outcome == 'success'" in scan["if"], "the scan runs without an image"


def test_the_image_name_does_not_change_from_one_commit_to_the_next(image_job):
    """Snyk Container wrote the image reference into the SARIF's automation id, and
    tagged with the commit it minted one code-scanning configuration per run:
    apkradar reached 32 and its pull requests could no longer be told which alerts
    they introduced. A name that never changes cannot do that."""
    scan = step_using(image_job, "trivy-action")["with"]
    assert "${{" not in scan["image-ref"]


def test_the_image_findings_have_a_category_of_their_own(image_job):
    """Written down rather than derived from the job's name, which is the default:
    a renamed job would start a new configuration and leave the old one's alerts
    open with nothing to close them. And not the files' category, or each upload
    would close the other's findings."""
    upload = step_using(image_job, "upload-sarif")
    files_upload = step_using(job_scanning("fs"), "upload-sarif")

    assert upload["with"].get("category")
    assert upload["with"].get("category") != files_upload.get("with", {}).get("category")
    assert upload["with"]["sarif_file"] == step_using(image_job, "trivy-action")["with"]["output"]


def test_the_findings_are_uploaded_even_when_the_scan_step_fails(image_job):
    upload = step_using(image_job, "upload-sarif")
    assert upload["if"].startswith("always()")
    assert "hashFiles(" in upload["if"]


def test_only_high_and_critical_reach_code_scanning(image_job):
    """By default trivy-action writes every severity into a SARIF whatever
    `severity` says. Snyk counted 107 low findings in the base image on
    2026-11-02; as alerts they would bury the few the gate is about, and the gate
    blocks on high and critical only."""
    scan = step_using(image_job, "trivy-action")["with"]
    assert scan["severity"] == "CRITICAL,HIGH"
    assert str(scan["limit-severities-for-sarif"]).lower() == "true"


def test_both_scans_run_the_same_pinned_trivy(image_job):
    image = step_using(image_job, "trivy-action")["uses"]
    files = step_using(job_scanning("fs"), "trivy-action")["uses"]
    assert image == files
    assert len(image.split("@", 1)[1].split()[0]) == 40, "not pinned to a commit"


def test_the_log_names_the_package_of_each_image_finding(image_job):
    """An image alert in code scanning reads "library/trivy-scan:1" and nothing
    about the package; on 2026-11-02 that left 45 alerts nobody could act on
    without the SARIF. The listing reads the SARIF the scan wrote, and runs when
    the scan step failed too."""
    listing = next(step for step in image_job["steps"] if step.get("name") == "List the image findings")
    output = step_using(image_job, "trivy-action")["with"]["output"]
    assert output in listing["run"]
    assert listing["if"].startswith("always()")
