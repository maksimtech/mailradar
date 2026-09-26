"""Every third-party module the tests import is either declared, or optional.

Written after the case that motivates it. Three of the five Radar had tests
doing `import yaml` while nothing in pyproject.toml asked for PyYAML: it arrived
through mutmut -> libcst, unasked and unnoticed. On 2026-09-25 libcst began
requiring pyyaml-ft, the free-threading fork, on Python 3.13 alone — so the
module `yaml` existed on 3.11, 3.12 and 3.14 and not on 3.13, and two Radar went
red on one matrix entry for a package neither of them had ever mentioned.

A borrowed dependency works until its lender changes its mind, and the lender is
under no obligation to say so. Hence a test rather than a note.

The rule is not "never import what you do not declare". apkradar reaches into
`loguru` on purpose — it belongs to androguard, and silencing androguard's
logger means touching it — and that is fine, because the test that does it says
`pytest.importorskip("loguru")` first and therefore skips rather than breaks if
it ever goes away. The rule is: what you do not declare, the suite has to
survive the loss of. `import yaml` did not.

Modules are resolved to the distributions that actually provide them rather than
guessed at from the name — `yaml` comes from PyYAML — so there is no map here to
keep in step with anything.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

# This project's own code, which needs no declaring.
FIRST_PARTY = {"mailradar", "tests", "conftest"}

# Installed by one workflow for its own job, deliberately not a project
# dependency: the suite must not need a benchmark runner to check correctness.
WORKFLOW_ONLY = {"pytest-codspeed"}


def normalised(name: str) -> str:
    return name.lower().replace("_", "-")


def repo_modules() -> set[str]:
    """Modules this repository provides itself, outside the package.

    scripts/ and tools/ hold this project's own code, and a test that reaches
    one of them through sys.path is not borrowing anything from anybody. The
    distinction is the whole point of this file: `bump_version` is declared
    nowhere because there is nobody to declare it to.
    """
    return {
        path.stem
        for folder in ("scripts", "tools")
        for path in (ROOT / folder).glob("*.py")
    }


def _optional_in(tree: ast.AST) -> set[str]:
    """Modules this file has declared it can do without.

    `pytest.importorskip("loguru")` — the name is the first argument, and it has
    to be a literal, because a computed one tells the reader nothing either.
    """
    optional = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "importorskip" or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            optional.add(first.value.split(".")[0])
    return optional


def _imports_in(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        # node.level == 0 excludes `from . import x`, which declares nothing.
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def required_modules() -> list[str]:
    """Top-level modules the suite imports without a way to do without them."""
    needed: set[str] = set()
    for path in sorted(TESTS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        needed |= _imports_in(tree) - _optional_in(tree)
    needed -= set(sys.stdlib_module_names) | FIRST_PARTY | repo_modules()
    return sorted(m for m in needed if not m.startswith("_"))


def declared_distributions() -> set[str]:
    """Everything pyproject.toml asks for, wherever it asks for it."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = config.get("project", {})

    requirements: list[str] = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        requirements.extend(group)
    for group in (config.get("dependency-groups") or {}).values():
        requirements.extend(r for r in group if isinstance(r, str))

    names = set()
    for raw in requirements:
        # "pyyaml>=6.0", "pyyaml (>=6.0,<7.0)", "pyyaml[speedups]>=6"
        name = raw.split(";")[0].strip()
        for stop in "[<>=!~( ":
            name = name.split(stop)[0]
        if name:
            names.add(normalised(name))
    return names


@pytest.mark.parametrize("module", required_modules())
def test_the_module_is_declared(module):
    declared = declared_distributions() | {normalised(w) for w in WORKFLOW_ONLY}
    providers = packages_distributions().get(module)

    if providers is None:
        pytest.fail(
            f"the tests import {module!r} and nothing installed provides it — "
            "either declare it, or reach it through pytest.importorskip so its "
            "absence skips a test instead of stopping the run"
        )

    assert any(normalised(dist) in declared for dist in providers), (
        f"the tests import {module!r}, provided by {providers}, and pyproject.toml "
        f"asks for none of them: it is on loan from something else's dependency "
        f"tree. Declare it, or use pytest.importorskip({module!r}) so the suite "
        f"survives losing it."
    )


def test_there_is_something_to_check():
    """An empty parametrize passes, so the walk finding nothing has to fail
    here instead of looking like a clean bill of health."""
    assert required_modules(), "no third-party imports found — the collection broke"
