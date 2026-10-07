"""What pyproject.toml tells PyPI about the project.

Nothing in the build reads these fields, so nothing fails when they are wrong:
the Changelog link answered 404 for as long as it was there, and the classifiers
stopped at 3.13 while the suite already ran on 3.14.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_the_changelog_url_is_not_a_404():
    """https://github.com/<org>/<repo>/CHANGELOG.md is a 404: /blob/main/ was missing."""
    url = _project()["urls"]["Changelog"]
    assert url == "https://github.com/maksimtech/mailradar/blob/main/CHANGELOG.md"


def test_python_314_is_among_the_classifiers():
    """The suite runs on 3.14, and the other four Radar declare it."""
    assert "Programming Language :: Python :: 3.14" in _project()["classifiers"]
