"""Every file at the root that a test reads is one mutmut copies.

mutmut runs the suite from `mutants/`, a copy of the project holding only the
mutated `source_paths`, what it copies of its own accord (`tests/`, `test/`,
`setup.cfg`, `pyproject.toml`, the lock files, `test*.py`) and `also_copy`. A test
that reads anything else from the root finds nothing there, and the Saturday run
dies before trying a mutant. It happened on 2026-10-03, 2026-10-10 and 2026-10-17,
and again on 2026-11-21: tests/test_lock_agreement.py had started reading
requirements-ci.txt four days earlier.

This reads the tests for the root they join a name to (`ROOT / "name"`,
`parents[1] / "name"`, `parent.parent / "name"`) and holds every such name that
exists here to the copy, so the gap shows on the pull request instead of on the
next Saturday. Names that do not exist are left alone: a test checking that
something is absent finds it absent in `mutants/` too.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

# mutmut 3.8 `configuration.py`: what it adds to `also_copy` itself.
MUTMUT_COPIES = {"tests", "test", "setup.cfg", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock"}

JOINED_TO_ROOT = re.compile(r'(?:\bROOT|parents\[1\]|parent\.parent)\s*/\s*"([^"/\\]+)"')


def copied() -> set[str]:
    mutmut = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]
    first = {Path(p).parts[0] for p in mutmut["source_paths"] + mutmut.get("also_copy", [])}
    return first | MUTMUT_COPIES | {p.name for p in ROOT.glob("test*.py")}


def read_from_root() -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for test in sorted(TESTS.rglob("*.py")):
        for name in JOINED_TO_ROOT.findall(test.read_text(encoding="utf-8")):
            names.setdefault(name, set()).add(test.relative_to(ROOT).as_posix())
    return names


def test_the_tests_are_read_for_root_names():
    names = read_from_root()
    assert {"pyproject.toml", "Dockerfile", ".github"} <= names.keys(), sorted(names)


def test_every_root_file_a_test_reads_is_copied_for_mutmut():
    missing = {name: sorted(tests) for name, tests in read_from_root().items()
               if (ROOT / name).exists() and name not in copied()}
    assert missing == {}, f"add to [tool.mutmut] also_copy: {missing}"
