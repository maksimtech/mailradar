"""The files the build is told to include have to be there.

apkradar lost its LICENSE out of the working tree on 2026-10-04 and the loss reached
`main`: pyproject names the file, so `python -m build` failed with `License file does not
exist: LICENSE`, and the PyPI publish and the image went with it. cookieradar lost its own
a few hours later, during a run of the suite. Nothing in either suite noticed, because
nothing in either suite looked.

What removes them is not known. These cases do not explain it; they stop it reaching a
commit, which is the part that can be fixed without knowing.

The expectation is read out of the declarations rather than written here as "LICENSE",
because the five Radar do not declare it the same way: patchradar states its licence as
text and only its Dockerfile names the file, the other four name it in pyproject, and of
those apkradar and mailradar do not copy it into the image. One of the two cases below
covers each repository, and three are covered by both.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
DOCKERFILE = ROOT / "Dockerfile"


def _licence_file_named_by_pyproject() -> str | None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    declared = project.get("license")
    if isinstance(declared, dict):
        return declared.get("file")
    return None


def _copy_sources() -> list[str]:
    """The source paths of every COPY, which is what the build will go looking for.

    Lines with `--from=` copy out of another stage rather than out of this tree, and a
    source with a glob in it is not a path to check, so both are left out.
    """
    sources: list[str] = []
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("COPY ") or "--from=" in stripped:
            continue
        parts = stripped.split()[1:]
        sources.extend(p for p in parts[:-1] if "*" not in p and not p.startswith("--"))
    return sources


def test_the_licence_file_pyproject_names_is_there():
    named = _licence_file_named_by_pyproject()
    if named is None:
        pytest.skip("this project states its licence as text, not as a file")

    path = ROOT / named
    assert path.is_file(), (
        f"pyproject names {named} and it is not there — `python -m build` fails on this, "
        f"and so does everything downstream of it"
    )
    assert path.read_text(encoding="utf-8").strip(), f"{named} is empty"


def test_every_path_the_image_copies_is_there():
    """A COPY of something absent fails the build, and the image build is the slowest
    place to find that out."""
    missing = [source for source in _copy_sources() if not (ROOT / source).exists()]

    assert not missing, f"the Dockerfile copies paths that are not there: {missing}"


# What mutmut puts in mutants/ besides `source_paths` and `also_copy`, of its own accord.
_MUTMUT_COPIES_ANYWAY = {"tests", "test", "setup.cfg", "pyproject.toml", "uv.lock"}


def test_the_mutation_run_copies_what_these_tests_read():
    """mutmut runs the suite inside mutants/, a copy of the tree that holds only what
    it is told to hold. The two cases above read the root: the licence file and every
    COPY source. Without them there the Saturday run stopped in its stats phase, before
    a single mutant was tried, on 2026-10-10 and 2026-10-17 — LICENSE was not listed."""
    mutmut = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"]["mutmut"]
    copied = set(mutmut.get("source_paths", [])) | set(mutmut.get("also_copy", [])) | _MUTMUT_COPIES_ANYWAY
    named = _licence_file_named_by_pyproject()
    read = ["Dockerfile", *_copy_sources(), *([named] if named else [])]

    missing = sorted({Path(p).parts[0] for p in read if Path(p).parts} - copied)

    assert not missing, f"read by these tests and left out of the mutation run: {missing}"
