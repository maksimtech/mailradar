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
import shutil
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


def _bash() -> str:
    """The bash the script is written for: the one on PATH, and Git's on Windows.

    On Windows `bash` is also WSL's launcher in System32. CreateProcess looks
    there before PATH, and so does `shutil.which` from a shell that lists
    System32 first, and WSL drops the backslashes of the Windows path it is
    handed: "No such file or directory", exit 127, and every case below failed
    without the script running at all. Git for Windows ships a bash next to git.
    """
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
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "SUCCEED_AT": str(succeed_at)}
        proc = subprocess.run(
            [BASH, str(WAIT_FOR_PYPI), *args],
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
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
               "SUCCEED_AT": str(succeed_at)}
        return subprocess.Popen(
            [BASH, str(WAIT_FOR_PYPI), *args],
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


def _publish_steps():
    return _workflow("publish.yml")["jobs"]["build-and-publish"]["steps"]


def test_the_release_image_is_built_from_the_tag_and_not_from_the_index():
    """What closes the race instead of narrowing it.

    The image installed `mailradar==<the new version>` from PyPI while publish.yml was
    still uploading it, and polled the index first to make that work. The poll runs on
    the runner; the multi-platform build resolves the index again, per platform, from
    whichever edge answers. apkradar lost that race on 2026-10-03 fifteen seconds after
    its poll had succeeded; this repository passed on timing alone. Nothing that waits
    can close it. Not asking does.
    """
    steps = _docker_steps()
    build = next(s for s in steps if "build-push-action" in s.get("uses", ""))
    args = build["with"]["build-args"]

    assert "MAILRADAR_SOURCE=local" in args
    assert "MAILRADAR_VERSION=" not in args, (
        "built from the checkout, there is no version to hand the image"
    )
    assert not [s for s in steps if "wait_for_pypi.sh" in s.get("run", "")], (
        "nothing here needs the index now, so nothing here should wait for it"
    )


def test_the_build_stands_on_the_tag_it_resolved():
    """Why this is a step and not a `ref:` on the checkout.

    Three triggers arrive here with the tag in three different places: a tag push has
    it in the ref, a dispatch in its input, and the weekly rebuild has it nowhere —
    the version step finds it with `git tag --list --sort=-v:refname`. A `ref:` on the
    checkout cannot express that, because the tag is not known until after the
    checkout has fetched the tags.

    So the job stands on the resolved tag afterwards. It matters most on the schedule:
    `latest` is rebuilt to pick up Debian's patches, and without this it would be
    rebuilt from whatever `main` holds — which is how `latest` ends up carrying
    unreleased code under a released version's name. There is no smoke test between
    the build and the push here to catch that.
    """
    steps = _docker_steps()
    version = next(i for i, s in enumerate(steps) if s.get("id") == "version")
    stand = next(i for i, s in enumerate(steps) if "git checkout" in s.get("run", ""))
    build = next(i for i, s in enumerate(steps) if "build-push-action" in s.get("uses", ""))

    assert version < stand < build, [s.get("name", "") for s in steps]
    assert "VERSION" in steps[stand].get("env", {}), (
        "it has to be given the tag the version step resolved"
    )


def test_the_checkout_fetches_the_tags_it_will_need():
    """The scheduled rebuild finds the newest tag with `git tag --list`, which needs
    the tags to be there. A shallow checkout has none of them, and the failure would
    be an empty version rather than a missing tag."""
    checkout = next(s for s in _docker_steps() if "actions/checkout" in s.get("uses", ""))

    assert checkout.get("with", {}).get("fetch-depth") == 0


def test_the_image_is_built_before_a_release_and_not_only_during_one():
    """Otherwise the first attempt at building the image is the one that publishes it.

    docker.yml pushes to Docker Hub, `:latest` included. docker-build-check.yml exists
    to build without publishing and was reachable by hand only — and had to be,
    because the Dockerfile could not build anything without a published version handed
    to it.
    """
    triggers = _workflow("docker-build-check.yml")["on"]

    assert "pull_request" in triggers, "a change that breaks the image should say so in its PR"
    assert "push" in triggers, "and on main, because that is what the next release builds"


def test_the_published_file_is_still_checked_where_it_was_published():
    """Taking the image off the index loses the one thing that arrangement proved by
    accident: that what lands on PyPI can be installed. publish.yml says it on purpose
    now, after the upload, where a slow index delays a check instead of failing a
    build."""
    steps = _publish_steps()
    names = [s.get("name", s.get("uses", "")) for s in steps]

    upload = next(i for i, s in enumerate(steps) if "gh-action-pypi-publish" in s.get("uses", ""))
    wait = next(i for i, s in enumerate(steps) if "wait_for_pypi.sh" in s.get("run", ""))
    verify = next(i for i, s in enumerate(steps) if "--version" in s.get("run", ""))

    assert upload < wait < verify, names
    assert "mailradar==" in steps[verify]["run"], "it has to be the version just uploaded"


def test_the_check_asks_for_no_margin_because_there_is_one_resolver():
    """The grace exists for two resolvers, the runner and the buildx container. In
    publish.yml there is only the runner, which has just had `pip download` answer."""
    wait = next(s for s in _publish_steps() if "wait_for_pypi.sh" in s.get("run", ""))
    arguments = wait["run"].split("wait_for_pypi.sh", 1)[1].split()

    assert arguments[-1] == "0", wait["run"]


def test_nothing_in_the_docker_workflow_waits_by_sleeping():
    """The regression this file exists for.

    A fixed sleep is a guess about someone else's queue, and on a re-run it
    restarts from this job's own start rather than from the publish finishing.
    """
    for step in _docker_steps():
        assert "sleep" not in step.get("run", ""), step.get("name")


# ── line endings ────────────────────────────────────────────────────────────


def test_the_shell_scripts_are_checked_out_with_lf():
    """With core.autocrlf=true the .sh scripts arrive in CRLF, and bash dies on `set -o pipefail\\r`."""
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "*.sh text eol=lf" in [line.strip() for line in attributes]
