"""The wait that keeps the Docker build from racing its own publish.

`docker.yml` and `publish.yml` both fire on the tag push, in parallel, and the
Dockerfile installs `mailradar==<new version>` from PyPI. A fixed `sleep 60`
stood in for the wait.

mailradar never went red on it, and that is the whole reason this is here:
apkradar had the identical step and lost the race twice — 2026.9.32 on
2026-09-24 and v2026.41 on 2026-09-30 — while mailradar published in the same
minutes of the second one and passed on timing alone. Both failures read as
`No matching distribution found`, listing versions up to the *previous*
release, which looks like a failed publish; both times PyPI already held the
files and only the index had not caught up.

Two things had to be right, and the second is not obvious: the wait has to ask
pip, because pip is what the Dockerfile uses and what the index answers for; and
it has to run *after* the version is extracted, because the tag is `v2026.41` and
`mailradar==v2026.41` is not a version pip can ever find. The `sleep` sat before
that step, where it had nothing to wait for by name.

Ported from cookieradar, which has polled since 2026-09-24.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WAIT_FOR_PYPI = ROOT / ".github" / "scripts" / "wait_for_pypi.sh"
WORKFLOWS = ROOT / ".github" / "workflows"

PACKAGE = "mailradar"
# The step output that holds the pip version — 2026.41, not v2026.41.
PIP_VERSION_OUTPUT = "PIP_VERSION"


@pytest.fixture
def fake_pip(tmp_path):
    """A `pip` on PATH that fails until the call count reaches SUCCEED_AT.

    The script is run for real, by bash, with the retry interval set to zero.
    What is faked is only the answer from the index.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    pip = bin_dir / "pip"
    pip.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log}"\n'
        f'n=$(wc -l < "{log}")\n'
        '[ "$n" -ge "$SUCCEED_AT" ]\n',
        encoding="utf-8",
    )
    pip.chmod(0o755)

    def run(succeed_at, *args):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "SUCCEED_AT": str(succeed_at)}
        proc = subprocess.run(
            ["bash", str(WAIT_FOR_PYPI), *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return proc, calls

    def start(succeed_at, *args):
        """The same script, left running, for the one case that is about *not* finishing."""
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "SUCCEED_AT": str(succeed_at)}
        return subprocess.Popen(
            ["bash", str(WAIT_FOR_PYPI), *args],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    run.start = start
    return run


def test_it_asks_pip_for_the_exact_version_and_stops_on_the_first_answer(fake_pip):
    proc, calls = fake_pip(1, PACKAGE, "2026.41", "5", "0", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 1
    assert "download" in calls[0]
    assert "--no-deps" in calls[0]          # the package, not its dependency tree
    assert f"{PACKAGE}==2026.41" in calls[0]


def test_it_keeps_asking_until_the_index_has_caught_up(fake_pip):
    proc, calls = fake_pip(3, PACKAGE, "2026.41", "5", "0", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 3


def test_it_gives_up_and_says_so_rather_than_letting_the_build_start(fake_pip):
    """A version that never appears is a failure, not something to build around.

    The failure has to name the version: "still not available" with no subject is
    the kind of message that sent the last two investigations the wrong way.
    """
    proc, calls = fake_pip(99, PACKAGE, "2026.41", "4", "0")

    assert proc.returncode != 0
    assert len(calls) == 4
    assert f"{PACKAGE}==2026.41" in proc.stderr


def test_it_refuses_to_run_without_a_package_and_a_version(fake_pip):
    """Called wrong, it must not wait for nothing and then report success."""
    proc, calls = fake_pip(1)

    assert proc.returncode != 0
    assert calls == []
    assert "Usage" in proc.stderr


def test_it_allows_the_index_a_grace_once_the_version_is_there(fake_pip):
    """The margin is a wait that happens, not a line in the log.

    apkradar 2026.42 built fifteen seconds after this script reported the version
    available — 16:31:21 against 16:31:36 — because the runner and the buildx
    container resolve different edges of the index. A grace that is printed and not
    taken would leave that exactly as it was while looking fixed.
    """
    start = time.monotonic()
    proc, calls = fake_pip(1, PACKAGE, "2026.41", "5", "0", "2")
    elapsed = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert elapsed >= 2, f"it reported a grace it did not take ({elapsed:.1f}s)"
    assert "agree with itself" in proc.stdout, "it waited without saying why"


def test_no_grace_waits_for_nothing_and_claims_nothing(fake_pip):
    """Zero has to mean zero, including in the log: a release that did not need the
    margin should not read as though it used one.

    Timed as a difference rather than against the clock. An absolute upper bound here
    read `< 2` and saw 21.4 seconds the first time five suites ran on one machine at
    once — measuring what the machine was doing rather than what the script was doing.
    The gap between a run that is given a grace and one that is not is the grace,
    whatever else is happening.
    """
    start = time.monotonic()
    proc, _ = fake_pip(1, PACKAGE, "2026.41", "5", "0", "0")
    without = time.monotonic() - start

    start = time.monotonic()
    waited, _ = fake_pip(1, PACKAGE, "2026.41", "5", "0", "3")
    with_grace = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert waited.returncode == 0, waited.stderr
    assert "agree with itself" not in proc.stdout
    assert with_grace - without >= 2, (
        f"no grace took {without:.1f}s and a three second grace took "
        f"{with_grace:.1f}s, so the grace was not waited for"
    )


def test_the_default_grace_is_a_wait_and_not_zero(fake_pip):
    """Measured, without the suite paying the whole default for it.

    Started with no grace argument against an index that answers on the first ask,
    the script must still be running a few seconds later. Remove the default, or set
    it to zero, and it exits immediately and this fails — which is the point: every
    other case here passes a grace explicitly, so without this one the default could
    be deleted and nothing would notice.
    """
    proc = fake_pip.start(1, PACKAGE, "2026.41", "5", "0")
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    finally:
        proc.kill()
        proc.wait(timeout=10)


# ─── the workflow: where the wait sits, and what it is given ────────────────

yaml = pytest.importorskip("yaml")


def _workflow(name):
    wf = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    wf["on"] = wf.pop(True, wf.get("on"))     # PyYAML reads the `on` key as True
    return wf


def _docker_steps():
    return _workflow("docker.yml")["jobs"]["docker"]["steps"]


def _wait_step():
    return next(s for s in _docker_steps() if "wait_for_pypi.sh" in s.get("run", ""))


def test_the_wait_runs_after_the_version_is_known_and_before_the_build():
    steps = _docker_steps()
    names = [s.get("name", s.get("uses", "")) for s in steps]

    version = next(i for i, s in enumerate(steps) if s.get("id") == "version")
    wait = next(i for i, s in enumerate(steps) if "wait_for_pypi.sh" in s.get("run", ""))
    build = next(i for i, s in enumerate(steps) if "build-push-action" in s.get("uses", ""))

    assert version < wait < build, names


def test_the_wait_is_given_the_pip_version_and_not_the_tag():
    """The part that would have made the fix useless.

    The tag is v2026.41 and the distribution is 2026.41. Waiting for the tag
    would poll for a version that cannot exist, for ten minutes, and then fail
    with the same message the race produced — the fix would have looked like the
    bug.
    """
    wait = _wait_step()

    assert wait["env"]["VERSION"] == f"${{{{ steps.version.outputs.{PIP_VERSION_OUTPUT} }}}}"
    assert '"$VERSION"' in wait["run"]        # through the environment, not interpolated


def test_only_a_tag_push_waits():
    """The scheduled rebuild and a manual dispatch name a version published long
    ago. Waiting for it would only move the failure of a wrong input earlier,
    and the weekly rebuild of `latest` has nothing to race with."""
    triggers = _workflow("docker.yml")["on"]

    assert set(triggers) == {"push", "schedule", "workflow_dispatch"}
    assert _wait_step()["if"] == "github.event_name == 'push'"


def test_nothing_in_the_docker_workflow_waits_by_sleeping():
    """The regression this file exists for.

    A fixed sleep is a guess about someone else's queue, and on a re-run it
    restarts from this job's own start rather than from the publish finishing.
    """
    for step in _docker_steps():
        assert "sleep" not in step.get("run", ""), step.get("name")
