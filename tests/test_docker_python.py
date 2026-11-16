"""The image runs a Python that still gets bug fixes, and the release SBOM of the
Python environment is resolved by that same interpreter.

Until 2026-11-16 the image was built on python:3.12-slim-trixie. 3.12 has had
security fixes only since April 2025, and 3.13 joined it in October 2026; 3.14
gets bug fixes until October 2027 and security fixes until October 2030
(peps.python.org release cycle). 3.15, out since 2026-10-09, is too new for the
wheels an image needs. exeradar and patchradar were already built on 3.14, and
cookieradar moved on 2026-11-13; this test is the same in every Radar.

sbom.yml describes the Python environment of a release with the interpreter it
sets up. On another minor version pip can resolve other wheels and markers, and
the two SBOMs attached to the release would describe two different resolutions.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
SBOM = ROOT / ".github" / "workflows" / "sbom.yml"


def image_python() -> str:
    match = re.search(r"^FROM python:(\d+\.\d+)-slim-trixie\b", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert match, "the Dockerfile is not built FROM python:<version>-slim-trixie"
    return match.group(1)


def sbom_python() -> str:
    workflow = yaml.safe_load(SBOM.read_text(encoding="utf-8"))
    versions = [
        str(step["with"]["python-version"])
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "actions/setup-python" in str(step.get("uses", ""))
    ]
    assert len(versions) == 1, f"sbom.yml sets up Python {versions}"
    return versions[0]


def test_the_image_runs_python_3_14():
    assert image_python() == "3.14"


def test_the_python_sbom_is_resolved_by_the_image_interpreter():
    assert sbom_python() == image_python(), (
        f"sbom.yml resolves the environment with Python {sbom_python()}, the image runs {image_python()}"
    )
