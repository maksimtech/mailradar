"""The two helpers the Snyk workflow calls, and what they must refuse.

Snyk Code flagged three lines here as path traversal: a path arrives in argv
and reaches `open`. For a command-line tool that is the job, not a flaw — but
looking at why the scanner was unhappy turned up two defects that are real:

- the project directory is handed to `pip install` as an argument, so a
  relative path beginning with a dash is read as a flag, not a path;
- when the directory holds no pyproject.toml the project's own name is unknown,
  and the filter that removes it from its own dependency list silently stops
  working.

Neither is a security hole in CI, where the arguments are literals in a
workflow file. Both produce a wrong answer quietly, which is worse than an
error.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def load(name: str):
    """Import a script from tools/, which is not a package."""
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def requirements():
    return load("snyk_requirements")


@pytest.fixture(scope="module")
def ids():
    return load("snyk_ids")


def run(module, args: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["tool", *args])
    return module.main()


# --------------------------------------------------------------------------
# snyk_requirements
# --------------------------------------------------------------------------


def test_the_project_path_reaches_pip_as_an_absolute_path(requirements, tmp_path, monkeypatch):
    """A relative path starting with a dash is a pip flag, not a directory.

    `pip install -r` means "read a requirements file"; a directory that happens
    to be named that way, passed through as text, changes the command. An
    absolute path cannot begin with a dash on any platform, which removes the
    ambiguity rather than trying to detect it.
    """
    project = tmp_path / "-r"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    seen: list[list[str]] = []

    def fake_run(command, **kwargs):
        seen.append(command)
        report = Path(command[command.index("--report") + 1])
        report.write_text('{"install": []}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(requirements.subprocess, "run", fake_run)
    requirements.resolve(Path("-r"))

    assert seen, "pip was never called"
    passed = seen[0][-1]
    assert Path(passed).is_absolute()
    assert not Path(passed).name.startswith("-") or Path(passed).is_absolute()
    assert not passed.startswith("-")


def test_a_directory_that_is_not_there_is_refused_before_pip_runs(
    requirements, tmp_path, monkeypatch
):
    """Otherwise pip fails with a CalledProcessError traceback."""
    def fake_run(command, **kwargs):
        raise AssertionError("pip must not be called for a missing directory")

    monkeypatch.setattr(requirements.subprocess, "run", fake_run)
    assert run(requirements, [str(tmp_path / "nowhere"), str(tmp_path / "out.txt")], monkeypatch) == 2


def test_a_directory_without_pyproject_is_refused(requirements, tmp_path, monkeypatch):
    """The quiet wrong answer this prevents.

    Without pyproject.toml the project's own name is unknown, so the filter
    that keeps a distribution out of its own dependency list matches nothing
    and the project is reported as depending on itself.
    """
    project = tmp_path / "empty"
    project.mkdir()

    def fake_run(command, **kwargs):
        raise AssertionError("pip must not be called without a manifest")

    monkeypatch.setattr(requirements.subprocess, "run", fake_run)
    assert run(requirements, [str(project), str(tmp_path / "out.txt")], monkeypatch) == 2


def test_an_output_directory_that_is_not_there_is_refused(requirements, tmp_path, monkeypatch):
    project = tmp_path / "demo"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    def fake_run(command, **kwargs):
        raise AssertionError("pip must not be called for an unwritable target")

    monkeypatch.setattr(requirements.subprocess, "run", fake_run)
    target = tmp_path / "no" / "such" / "dir" / "out.txt"
    assert run(requirements, [str(project), str(target)], monkeypatch) == 2


def test_a_good_project_still_writes_its_requirements(requirements, tmp_path, monkeypatch):
    """The guards must not cost the tool its job."""
    project = tmp_path / "demo"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "Demo_Pkg"\n', encoding="utf-8")

    def fake_run(command, **kwargs):
        report = Path(command[command.index("--report") + 1])
        report.write_text(
            '{"install": ['
            '{"metadata": {"name": "Demo_Pkg", "version": "1.0"}},'
            '{"metadata": {"name": "httpx", "version": "0.28.1"}}'
            ']}',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(requirements.subprocess, "run", fake_run)
    target = tmp_path / "out.txt"
    assert run(requirements, [str(project), str(target)], monkeypatch) == 0

    written = target.read_text(encoding="utf-8").split()
    assert written == ["httpx==0.28.1"], "the distribution must not list itself"


# --------------------------------------------------------------------------
# snyk_ids
# --------------------------------------------------------------------------


def test_a_path_that_is_not_a_file_says_so(ids, tmp_path, monkeypatch, capsys):
    """A directory where a JSON file was meant is a caller mistake.

    It still exits 0 — the workflow reads "no ids" as "no information" and has
    its own check for that — but it must not pass in silence.
    """
    assert run(ids, [str(tmp_path)], monkeypatch) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not a file" in captured.err.lower()


def test_a_file_that_is_not_there_is_not_an_error(ids, tmp_path, monkeypatch, capsys):
    """A scan that never ran leaves no file; that is information, not a fault."""
    assert run(ids, [str(tmp_path / "absent.json")], monkeypatch) == 0
    assert capsys.readouterr().out == ""


def test_ids_come_out_sorted_and_unique(ids, tmp_path, monkeypatch, capsys):
    """`comm` in the workflow requires sorted input; duplicates would skew it."""
    payload = tmp_path / "snyk.json"
    payload.write_text(
        '[{"vulnerabilities": [{"id": "SNYK-B"}, {"id": "SNYK-A"}]},'
        ' {"vulnerabilities": [{"id": "SNYK-A"}]}]',
        encoding="utf-8",
    )
    assert run(ids, [str(payload)], monkeypatch) == 0
    assert capsys.readouterr().out.split() == ["SNYK-A", "SNYK-B"]
