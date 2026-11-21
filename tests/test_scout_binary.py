"""Docker Scout's binary is fetched with the job's token, before docker/scout-action runs.

docker/scout-action (1.29.0, and 1.30.0 alike) builds an authenticated client, finds
its release with it, and then downloads its ~190 MB binary with
`tc.downloadTool(asset.url, binary, undefined, ...)`: the third argument is the
authentication, and it is undefined. The request goes to api.github.com anonymously,
on the 60-an-hour budget of the runner's address, which GitHub-hosted runners share.
When others have spent it the step fails with "Unexpected HTTP response: 403" before
anything is scanned, and Security Posture, which follows it, is skipped. It happened
in every Radar, pinned or not, five times on 2026-11-21 alone; a rerun on another
runner passes. Reported upstream as docker/scout-action#116, open since 2026-09-14.

The action also has a branch for a binary that is already there: if `dist/<name>`
exists next to its `index.js`, it uses that and downloads nothing. So
`.github/scripts/fetch_scout_binary.sh` puts it there first, fetched with the job's
token, after checking that the release tag is the commit the workflow pins and that
the file has the SHA-256 GitHub publishes for it. Where the runner keeps actions
(`_actions/<owner>/<repo>/<ref>` next to the workspace) is not documented, so when
the directory is not there the script says so and steps aside: the action then
downloads as before, never worse than without it. A wrong digest or a tag that
moved stops the job.

The script is the same file in all six Radar, as is this test.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FETCH = ROOT / ".github" / "scripts" / "fetch_scout_binary.sh"
NAME = "docker-scout-action_linux_amd64"
PINNED = re.compile(r"^\s*(?:-\s*)?uses:\s*docker/scout-action@([0-9a-f]{40})\s+#\s*(v\d+\.\d+\.\d+)\s*$")
CALL = re.compile(r"fetch_scout_binary\.sh\s+([0-9a-f]{40})\s+(v\d+\.\d+\.\d+)")


def _bash() -> str:
    """The bash the script is written for: the one on PATH, and Git's on Windows."""
    found = shutil.which("bash")
    if os.name != "nt":
        return found or "bash"
    system32 = Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32"
    if found and Path(found).parent != system32:
        return found
    git = shutil.which("git")
    bundled = Path(git).resolve().parent.parent / "bin" / "bash.exe" if git else None
    return str(bundled) if bundled and bundled.is_file() else (found or "bash")


BASH = _bash()


def _workflows_using_scout() -> list[Path]:
    return [p for p in sorted(WORKFLOWS.glob("*.yml")) if "docker/scout-action@" in p.read_text(encoding="utf-8")]


# ─── The workflows ─────────────────────────────────────────────────────────────


def test_there_is_a_scout_scan_to_look_at():
    assert _workflows_using_scout()


@pytest.mark.parametrize("path", _workflows_using_scout(), ids=lambda p: p.name)
def test_every_use_is_pinned_to_a_commit_and_a_full_version(path):
    loose = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
             if "docker/scout-action@" in line and not PINNED.match(line)]
    assert loose == [], f"{path.name}: {loose}"


@pytest.mark.parametrize("path", _workflows_using_scout(), ids=lambda p: p.name)
def test_every_job_fetches_the_binary_of_its_own_pin_first(path):
    text = path.read_text(encoding="utf-8")
    pins = {m.group(1): m.group(2) for m in map(PINNED.match, text.splitlines()) if m}
    for name, job in (yaml.safe_load(text).get("jobs") or {}).items():
        steps = job.get("steps", [])
        scout = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("docker/scout-action@")]
        if not scout:
            continue
        commits = {steps[i]["uses"].split("@", 1)[1] for i in scout}
        assert len(commits) == 1, f"{path.name}:{name} uses more than one commit of the action: {commits}"
        (commit,) = commits
        calls = [(i, CALL.search(str(s.get("run", "")))) for i, s in enumerate(steps)]
        calls = [(i, m) for i, m in calls if m]
        assert calls, f"{path.name}:{name} runs docker/scout-action without fetch_scout_binary.sh"
        first, match = calls[0]
        assert first < scout[0], f"{path.name}:{name} fetches the binary after the action has run"
        assert match.groups() == (commit, pins[commit]), f"{path.name}:{name} fetches {match.groups()}"
        assert "GH_TOKEN" in (steps[first].get("env") or {}), f"{path.name}:{name}: the fetch has no token"


# ─── The script, run by bash against a fake gh ─────────────────────────────────

COMMIT = "e7e2a72bf1485d10a58f30696b6c513b261ce4fa"
TAG = "v1.29.0"
CONTENT = "the scout binary"

FAKE_GH = r"""#!/usr/bin/env bash
# Answers the three calls fetch_scout_binary.sh makes, from FAKE_* variables.
case "$*" in
  *"commits/"*) echo "$FAKE_TAG_COMMIT" ;;
  *"releases/tags/"*) echo "$FAKE_DIGEST" ;;
  "release download"*)
    [ -n "${FAKE_DOWNLOAD_FAILS:-}" ] && { echo "HTTP 502" >&2; exit 1; }
    dir=""; prev=""
    for arg in "$@"; do [ "$prev" = "--dir" ] && dir="$arg"; prev="$arg"; done
    printf '%s' "$FAKE_CONTENT" > "$dir/docker-scout-action_linux_amd64" ;;
  *) echo "unexpected gh $*" >&2; exit 3 ;;
esac
"""


@pytest.fixture
def runner(tmp_path):
    """An _actions directory holding the pinned action, and a gh that answers from the environment."""
    actions = tmp_path / "_actions"
    (actions / "docker" / "scout-action" / COMMIT).mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH, encoding="utf-8", newline="\n")
    gh.chmod(0o755)
    env = dict(os.environ,
               SCOUT_ACTIONS_DIR=str(actions),
               PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
               FAKE_TAG_COMMIT=COMMIT,
               FAKE_DIGEST="sha256:" + hashlib.sha256(CONTENT.encode()).hexdigest(),
               FAKE_CONTENT=CONTENT)
    env.pop("FAKE_DOWNLOAD_FAILS", None)

    def run(**overrides):
        result = subprocess.run([BASH, str(FETCH), COMMIT, TAG], env={**env, **overrides},
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        return result, actions / "docker" / "scout-action" / COMMIT / "dist" / NAME

    return run


def test_puts_the_verified_binary_where_the_action_looks_first(runner):
    result, binary = runner()
    assert result.returncode == 0, result.stderr
    assert binary.read_text(encoding="utf-8") == CONTENT


def test_a_wrong_digest_stops_the_job_and_leaves_nothing(runner):
    result, binary = runner(FAKE_DIGEST="sha256:" + "0" * 64)
    assert result.returncode == 1
    assert "::error::" in result.stdout + result.stderr
    assert not binary.exists()


def test_a_tag_that_moved_stops_the_job(runner):
    result, binary = runner(FAKE_TAG_COMMIT="f" * 40)
    assert result.returncode == 1
    assert "::error::" in result.stdout + result.stderr
    assert not binary.exists()


def test_a_failed_download_steps_aside_for_the_action(runner):
    result, binary = runner(FAKE_DOWNLOAD_FAILS="1")
    assert result.returncode == 0
    assert "::warning::" in result.stdout
    assert not binary.exists()


def test_no_action_directory_steps_aside_for_the_action(runner, tmp_path):
    result, _ = runner(SCOUT_ACTIONS_DIR=str(tmp_path / "elsewhere"))
    assert result.returncode == 0
    assert "::warning::" in result.stdout
