"""The only job PyPI trusts installs and runs nothing.

PyPI accepts an upload from this repository on the strength of an OIDC token,
and a job holding `id-token: write` can mint one. Until 2026-11-25 publish.yml
had one job, `build-and-publish`, that held it while it installed the newest
build tools of that minute, built in an isolation that fetched an unpinned
hatchling again, and after the upload installed the release with all its
runtime dependencies from PyPI. On 2026-11-18 two releases of
`agent-framework`, published from that project's own account, carried a `.pth`
file that runs at every Python start-up and mints OIDC tokens. A package like
that, anywhere in what the job installed, could have published a release of
mailradar under its name (maksimtech/apkradar#135, #166 here).

So the work is split the way PyPA documents for trusted publishing, as in
releaseradar, exeradar and patchradar:

- `build` installs the build tools from a hash-pinned file and builds without
  isolation, so the backend that runs is the pinned one; it holds no token;
- `publish` downloads what `build` made and uploads it: no checkout, no Python,
  no `run:` step, and the only job with `id-token: write`;
- `verify` waits for the index and installs the release, as before, without
  the token.

`publish` and `verify` run on a `v*` tag only. Dispatched from a branch, the
workflow builds and stops: that is the dry run.

The GPG signature went with the split. PyPI drops it on upload (twine said so
on releaseradar's v2026.8: "these will be silently ignored by the index"), and
the release is attested through Sigstore instead, by the publish action.
Keeping it would have kept a private key in a job that installs packages.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
BUILD_REQUIREMENTS = ROOT / ".github" / "requirements-build.txt"
BUILD_INPUT = ROOT / ".github" / "requirements-build.in"

# What a job holding the token may use, and nothing else.
TOKEN_ACTIONS = ("actions/download-artifact@", "pypa/gh-action-pypi-publish@")
ON_A_TAG = "startsWith(github.ref, 'refs/tags/v')"


def workflow() -> dict:
    return yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))


def jobs() -> dict:
    return workflow()["jobs"]


def holds_the_token(job: dict) -> bool:
    return (job.get("permissions") or {}).get("id-token") == "write"


def runs(job: dict) -> list[str]:
    return [s["run"] for s in job.get("steps", []) if "run" in s]


def needs(job: dict) -> list[str]:
    value = job.get("needs") or []
    return [value] if isinstance(value, str) else list(value)


def test_build_then_publish_then_verify():
    found = jobs()
    assert set(found) == {"build", "publish", "verify"}
    assert needs(found["publish"]) == ["build"]
    assert needs(found["verify"]) == ["publish"]


def test_the_workflow_grants_nothing_and_every_job_asks_for_what_it_needs():
    """A job without its own `permissions` inherits the workflow's, and without
    those the repository's default token, which can be broad."""
    assert workflow().get("permissions") == {}
    for name, job in jobs().items():
        assert "permissions" in job, f"{name} inherits its permissions"


def test_only_publish_holds_the_token():
    assert [name for name, job in jobs().items() if holds_the_token(job)] == ["publish"]
    assert jobs()["publish"]["permissions"] == {"id-token": "write"}


def test_the_job_holding_the_token_runs_nothing_and_uses_only_the_two_actions():
    for name, job in jobs().items():
        if not holds_the_token(job):
            continue
        assert not runs(job), f"{name} runs a command next to the token"
        uses = [s.get("uses", "") for s in job["steps"]]
        assert uses and all(u.startswith(TOKEN_ACTIONS) for u in uses), f"{name}: {uses}"


def test_no_job_that_runs_pip_or_python_holds_the_token():
    for name, job in jobs().items():
        if any(re.search(r"\b(?:pip3?|python3?)\b", run) for run in runs(job)):
            assert not holds_the_token(job), name


def test_publishing_is_on_the_pypi_environment():
    """PyPI's trusted publisher names the environment too, so a token minted by a
    job outside it (test.yml, codspeed.yml) is refused."""
    environment = jobs()["publish"]["environment"]
    assert environment == "pypi" or environment["name"] == "pypi"


@pytest.mark.parametrize("name", ["publish", "verify"])
def test_only_a_tag_publishes_and_a_dispatch_from_a_branch_is_a_dry_run(name):
    assert ON_A_TAG in str(jobs()[name].get("if", "")), f"{name} would run on a branch"
    assert "if" not in jobs()["build"], "the build is what the dry run proves"


def test_the_build_installs_from_hashes_and_builds_without_isolation():
    build = "\n".join(runs(jobs()["build"]))
    assert re.search(r"pip install --require-hashes -r \.github/requirements-build\.txt", build), build
    assert re.search(r"\bpython -m build --no-isolation\b", build), build
    assert "--upgrade" not in build, "the newest of the minute is what the hashes replace"


def test_publish_uploads_exactly_what_build_made():
    upload = [s for s in jobs()["build"]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    download = [s for s in jobs()["publish"]["steps"] if s.get("uses", "").startswith("actions/download-artifact@")]
    assert len(upload) == len(download) == 1
    assert upload[0]["with"]["name"] == download[0]["with"]["name"]
    assert upload[0]["with"]["path"].rstrip("/") == download[0]["with"]["path"].rstrip("/") == "dist"


def test_no_secret_reaches_the_workflow():
    """The GPG key and its passphrase were the only ones, for signatures PyPI drops."""
    assert "secrets." not in PUBLISH.read_text(encoding="utf-8")


# ─── the build tools ────────────────────────────────────────────────────────

def pinned() -> dict[str, str]:
    text = BUILD_REQUIREMENTS.read_text(encoding="utf-8")
    return dict(re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", text, re.MULTILINE))


def test_every_build_tool_is_pinned_with_its_hashes():
    text = BUILD_REQUIREMENTS.read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 2)[2])
    requirements = [b for b in blocks if re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*==", b)]
    assert len(requirements) == len(pinned()) >= 2
    for block in requirements:
        assert "--hash=sha256:" in block, block.splitlines()[0]


def test_the_backend_pyproject_names_is_one_of_them():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    backend = re.search(r'requires\s*=\s*\["([A-Za-z0-9_.-]+)', pyproject).group(1)
    assert backend in pinned()
    assert "build" in pinned()
    assert set(BUILD_INPUT.read_text(encoding="utf-8").split()) == {"build", backend}


def header_arguments() -> list[str]:
    header = BUILD_REQUIREMENTS.read_text(encoding="utf-8").splitlines()[1]
    command = header.removeprefix("#").split()
    assert command[:3] == ["uv", "pip", "compile"], header
    return command[3:]


def test_the_file_is_compiled_for_the_python_the_build_runs_and_for_any_system():
    """`--universal` keeps the file the same wherever it is compiled: colorama,
    which build wants on Windows only, is in it under `os_name == 'nt'`, and pip
    on the Linux runner skips it."""
    arguments = header_arguments()
    setup = next(s for s in jobs()["build"]["steps"] if s.get("uses", "").startswith("actions/setup-python@"))
    assert "--generate-hashes" in arguments
    assert "--universal" in arguments
    assert f"--python-version={setup['with']['python-version']}" in arguments
    assert "--output-file=.github/requirements-build.txt" in arguments
    assert ".github/requirements-build.in" in arguments


# What Renovate's pip-compile manager accepts in a `uv pip compile` header
# (renovatebot/renovate, lib/modules/manager/pip-compile/common.ts). Anything
# else, or an option whose argument follows a space instead of `=`, and it
# skips the file with "pip-compile error": releaseradar's first header had
# `--python-platform linux` and `--python-version 3.12`, and on 2026-11-25 its
# Dependency Dashboard (maksimtech/releaseradar#71) reported exactly that.
RENOVATE_UV_FLAGS = {"--no-strip-extras", "--universal", "-v", "--generate-hashes", "--emit-index-url", "--all-extras"}
RENOVATE_UV_WITH_ARGUMENT = {
    "--constraints", "--constraint", "--python-version", "--no-emit-package", "--prerelease", "--format",
    "--resolution", "--fork-strategy", "--exclude-newer", "--exclude-newer-package", "--group", "--override",
    "--overrides", "--output-file", "--extra", "--extra-index-url", "--index-url",
}


def test_renovate_can_read_the_header():
    for argument in header_arguments():
        if not argument.startswith("-"):
            continue
        option, equals, _ = argument.partition("=")
        if option in RENOVATE_UV_WITH_ARGUMENT:
            assert equals, f"{option} needs '=' before its argument for Renovate"
        else:
            assert option in RENOVATE_UV_FLAGS and not equals, f"Renovate does not accept {argument}"
