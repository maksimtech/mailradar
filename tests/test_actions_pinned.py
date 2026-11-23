"""Every action every workflow uses is pinned to a commit, with its version beside it.

tests/test_ci_contract.py held test.yml to this and said "this repository pins
its actions to a full commit" — true of four workflows out of sixteen. The
others named moving tags: `actions/setup-python@v7`, `actions/checkout@v7`,
`docker/build-push-action@v7`, and in publish.yml, the job that holds the PyPI
OIDC token, `pypa/gh-action-pypi-publish@release/v1`, a branch. Whoever moves a
tag changes the code these jobs run without a pull request here: on 2026-10-28
`setup-python@v7` already ran 7.1.0, released six days earlier, which no change
in this repository had approved.

A full commit hash cannot be moved. The `# vX.Y.Z` after it says which release
it is, for a reader and for Dependabot, which updates both together. The
version is a full one since 2026-11-23: the pattern let `# v7.1` through, a
line of releases rather than the one pinned (alignment to apkradar, step 3).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.y*ml"))
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.M)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
# Major, minor and patch: `# v7` and `# v7.1` name lines of releases, not the one pinned
VERSION = re.compile(r"#\s*v?\d+\.\d+\.\d+\b")


def _uses(path: Path) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in USES.finditer(path.read_text(encoding="utf-8"))]


def test_there_are_workflows_to_check():
    assert len(WORKFLOWS) >= 10


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    loose = [ref for ref, _ in _uses(path) if not ref.startswith(("./", "docker://")) and not PINNED.match(ref)]
    assert loose == [], f"{path.name}: not pinned to a full commit: {loose}"


@pytest.mark.parametrize("comment,says_the_release", [
    ("# v7.0.1", True),
    ("# v1.14.3", True),
    ("# 2.1.0", True),
    ("# v7", False),          # a major is a moving tag, not a release
    ("# v7.1", False),        # nor is a minor: which patch?
    ("# release/v1", False),  # a branch
    ("", False),
])
def test_the_version_comment_names_a_full_release(comment, says_the_release):
    """The rule the Radars share is a commit plus its full version (alignment to
    apkradar, step 3): `vX.Y` names a line of releases, not the one pinned."""
    assert bool(VERSION.search(comment)) is says_the_release


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_pin_says_which_release_it_is(path):
    bare = [ref for ref, rest in _uses(path) if PINNED.match(ref) and not VERSION.search(rest)]
    assert bare == [], f"{path.name}: pinned without a '# vX.Y.Z' comment: {bare}"
