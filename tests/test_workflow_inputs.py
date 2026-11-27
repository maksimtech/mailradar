"""A version from a tag or a dispatch form reaches a script as a string, and only
if it is a release tag (maksimtech/apkradar#151).

`${{ }}` inside `run:` is substituted into the script's text before bash reads it,
so a value with a quote in it becomes code; through `env:` it stays a string. Then
bash expands `"...'${STRIPPED}'..."` before Python reads it, and a git tag may hold
`'`, `(`, `)`, `+` and `;`: `python3 -c "parts='${STRIPPED}'..."` made the tag code
again, in jobs already logged in to Docker Hub. A dispatch input may also hold a
newline, which written to GITHUB_OUTPUT adds outputs of its own. So, in every
workflow:

1. an expression from outside reaches a `run:` only through `env:`;
2. no Python code string holds a shell variable;
3. a version from a tag or an input is checked to be a release tag before it is
   written anywhere;
4. in docker.yml, that check comes before the Docker Hub login.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# This Radar's release tags, spelled as the check in the workflows spells it.
RELEASE_TAG = r"^v[0-9]+(\.[0-9]+)+$"


def _workflows():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        yield path.name, yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _steps():
    for name, workflow in _workflows():
        for job_id, job in (workflow.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                yield name, job_id, step


def _where(name, job_id, step) -> str:
    return f"{name}: {job_id}: {step.get('name') or step.get('uses')}"


PASTED = re.compile(r"\$\{\{[^}]*\b(?:github\.event\.|inputs\.|github\.head_ref|github\.ref_name)")


def test_no_workflow_pastes_an_input_or_a_ref_into_a_script():
    """`${{ github.event.inputs.version }}` written straight into bash was the worst
    case: code before anything else runs. `github.ref_name` is a tag's name, which
    the pusher chooses."""
    found = [_where(*s) for s in _steps() if PASTED.search(s[2].get("run", ""))]
    assert found == []


PYTHON_CODE_WITH_A_VARIABLE = re.compile(r"""\bpython3?(?:\s+-[A-Za-z]+)*\s+-c\s+"[^"]*\$""")


def test_no_script_pastes_a_shell_variable_into_python_code():
    """A double-quoted code string with a `$` inside: bash puts the value into the
    program's text. The value goes in as an argument (`sys.argv[1]`), in a
    single-quoted program."""
    found = [_where(*s) for s in _steps() if PYTHON_CODE_WITH_A_VARIABLE.search(s[2].get("run", ""))]
    assert found == []


FROM_OUTSIDE = re.compile(r"\b(?:inputs\.version|github\.event\.inputs\.version|github\.ref_name)\b")


def _reads_a_version_from_outside(step) -> bool:
    return any(FROM_OUTSIDE.search(str(value)) for value in (step.get("env") or {}).values())


def test_every_version_from_a_tag_or_an_input_is_checked_before_it_is_written():
    problems = []
    for name, job_id, step in _steps():
        if not _reads_a_version_from_outside(step):
            continue
        run = step.get("run", "")
        if RELEASE_TAG not in run:
            problems.append(f"{_where(name, job_id, step)}: no {RELEASE_TAG} check")
        elif "GITHUB_OUTPUT" in run and run.index(RELEASE_TAG) > run.index("GITHUB_OUTPUT"):
            problems.append(f"{_where(name, job_id, step)}: written before it is checked")
    assert problems == []


def test_the_docker_version_is_checked_before_the_login():
    """A value refused at the check never reaches a runner that holds the Docker
    Hub credentials."""
    docker = dict(_workflows())["docker.yml"]
    for job_id, job in (docker.get("jobs") or {}).items():
        steps = job.get("steps") or []
        logins = [i for i, step in enumerate(steps) if "docker/login-action" in str(step.get("uses", ""))]
        versions = [i for i, step in enumerate(steps) if _reads_a_version_from_outside(step)]
        if logins and versions:
            assert max(versions) < min(logins), f"docker.yml: {job_id}: the login comes first"
