"""uv.lock and requirements-ci.txt pin the same packages to the same versions.

The two files lock the runtime dependencies twice: uv.lock is the list
docs/nis2-compliance.md shows a customer, requirements-ci.txt the hash-locked
one pip-compile writes. Dependabot's pip ecosystem bumps only the second, so
from 2026-09-14 to 2026-11-16 seven packages drifted apart one pull request at a
time (anyio, certifi, cryptography, idna, markupsafe, pycparser, typer), and
nothing noticed: `uv lock --check` compares uv.lock with pyproject.toml, not
with the other file.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()       # PEP 503


def _uv_lock() -> dict[str, str]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {
        _normalized(package["name"]): package["version"]
        for package in lock["package"]
        if "version" in package                       # the project itself has none
    }


def _requirements_ci() -> dict[str, str]:
    text = (ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    return {
        _normalized(name): version
        for name, version in re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", text, re.MULTILINE)
    }


REQUIREMENTS = _requirements_ci()
LOCKED = _uv_lock()


def test_requirements_ci_pins_something():
    """A parser that finds nothing would make the comparison below pass on nothing."""
    assert len(REQUIREMENTS) >= 10
    assert set(REQUIREMENTS) & set(LOCKED)


@pytest.mark.parametrize("name", sorted(set(REQUIREMENTS) & set(LOCKED)))
def test_both_files_pin_the_same_version(name):
    assert LOCKED[name] == REQUIREMENTS[name], (
        f"{name}: uv.lock has {LOCKED[name]}, requirements-ci.txt has {REQUIREMENTS[name]}"
    )
