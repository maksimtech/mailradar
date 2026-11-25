"""The install that checks a published wheel, asked again until the index has caught up.

publish.yml uploads to PyPI and then installs `mailradar==<version>` into a fresh venv,
because nothing else proves that what landed on the index can be installed. That
install is a request to PyPI's CDN, and a request can be answered by a cache that has
not caught up with the upload:

  releaseradar v2026.2, v2026.4  the second time with a 45 s grace before the install
  apkradar 2026.48, 2026-11-16   wait_for_pypi.sh saw the version at 15:04:30; the
                                 install, three seconds later on the same runner, was
                                 told "from versions: ... 2026.47"

Each time the upload had succeeded and only the check went red. A margin narrows
that; asking again until the install itself succeeds answers the question the check
asks. `.github/scripts/install_from_pypi.sh` does that, and is the same file in all
six Radar, as is this test but for the package name.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_FROM_PYPI = ROOT / ".github" / "scripts" / "install_from_pypi.sh"
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
PACKAGE = "mailradar"


def _bash() -> str:
    """The bash the script is written for: the one on PATH, and Git's on Windows.

    On Windows `bash` is also WSL's launcher in System32, which drops the
    backslashes of the Windows path it is handed. Git for Windows ships a bash
    next to git.
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
def fake_venv(tmp_path):
    """A venv whose `bin/pip` fails until the call count reaches SUCCEED_AT.

    The script is run for real, by bash, against this venv, as publish.yml runs it
    against the one it has just created. What is faked is only the answer from the
    index.
    """
    venv = tmp_path / "verify"
    (venv / "bin").mkdir(parents=True)
    log = tmp_path / "installs.log"
    pip = venv / "bin" / "pip"
    pip.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log.as_posix()}"\n'
        f'n=$(wc -l < "{log.as_posix()}")\n'
        '[ "$n" -ge "$SUCCEED_AT" ]\n',
        encoding="utf-8",
    )
    pip.chmod(0o755)

    def run(succeed_at, *args, with_venv=True):
        command = [BASH, str(INSTALL_FROM_PYPI), *([venv.as_posix()] if with_venv else []), *args]
        proc = subprocess.run(
            command,
            env={**os.environ, "SUCCEED_AT": str(succeed_at)},
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
        return subprocess.Popen(
            [BASH, str(INSTALL_FROM_PYPI), venv.as_posix(), *args],
            env={**os.environ, "SUCCEED_AT": str(succeed_at)},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    run.start = start
    return run


def test_the_install_asks_the_venv_for_the_exact_wheel_and_stops_on_success(fake_venv):
    proc, calls = fake_venv(1, PACKAGE, "2026.48", "5", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 1
    assert calls[0].split()[0] == "install"
    assert "--no-cache-dir" in calls[0]  # a cached answer is the one thing not to trust
    assert "--only-binary :all:" in calls[0]  # the wheel that was uploaded, not a build of the sdist
    assert f"{PACKAGE}==2026.48" in calls[0]


def test_the_install_is_asked_again_until_the_index_answering_it_has_caught_up(fake_venv):
    """The case the script exists for: one request seeing the file does not mean the
    next one will."""
    proc, calls = fake_venv(3, PACKAGE, "2026.48", "5", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 3
    assert "not installable yet" in proc.stdout, "it retried without saying why"


def test_the_install_gives_up_and_names_what_it_could_not_install(fake_venv):
    """A version that never becomes installable is a failure, and the message has to
    carry the version: patience for a CDN, not a verdict deferred for ever."""
    proc, calls = fake_venv(99, PACKAGE, "2026.48", "4", "0")

    assert proc.returncode != 0
    assert len(calls) == 4
    assert f"{PACKAGE}==2026.48" in proc.stderr


@pytest.mark.parametrize("args", [(), (PACKAGE,), (PACKAGE, "2026.48")])
def test_the_install_refuses_to_run_without_a_venv_a_package_and_a_version(fake_venv, args):
    """Called short, it must not install something else and then report success."""
    proc, calls = fake_venv(1, *args, with_venv=False)

    assert proc.returncode != 0
    assert calls == []
    assert "Usage" in proc.stderr


def test_the_default_interval_between_installs_is_a_wait_and_not_zero(fake_venv):
    """The default is what publish.yml would get if it stopped passing one: against an
    index that answers on the second ask, the script must still be waiting a few
    seconds after the first. No interval would ask the same stale cache again at once
    and give up within a second."""
    proc = fake_venv.start(2, PACKAGE, "2026.48")
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    finally:
        proc.kill()
        proc.wait(timeout=10)


# ─── publish.yml: the check goes through the script ─────────────────────────

yaml = pytest.importorskip("yaml")


def _jobs():
    return yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))["jobs"]


def _publish_steps():
    """The check runs in verify, after publish, without the token
    (tests/test_publish_contract.py)."""
    return _jobs()["verify"]["steps"]


def _check_step(steps):
    return next(s for s in steps if "install_from_pypi.sh" in s.get("run", ""))


def test_the_published_wheel_is_installed_after_the_upload_through_the_script():
    jobs = _jobs()
    uploads = [
        name for name, job in jobs.items()
        if any("gh-action-pypi-publish" in s.get("uses", "") for s in job["steps"])
    ]
    assert uploads == ["publish"]
    assert jobs["verify"]["needs"] in ("publish", ["publish"]), "the check waits for the upload"

    steps = _publish_steps()
    arguments = _check_step(steps)["run"].split("install_from_pypi.sh", 1)[1].split()
    assert arguments[1:3] == [PACKAGE, '"$VERSION"'], "it has to be the version just uploaded"
    assert "--version" in _check_step(steps)["run"], "installed is not yet runs"


def test_the_check_makes_no_single_install_of_its_own():
    """A bare `pip install` in that step is the shape that went red on a good release."""
    run = _check_step(_publish_steps())["run"]

    assert 'pip" install' not in run
    assert "pip install" not in run


def test_a_wait_before_the_check_buys_no_margin():
    """With the install asked again, a grace in front of it is a fixed wait that buys
    nothing: releaseradar's 45 s did not save v2026.4, and the retry is what holds."""
    for step in _publish_steps():
        if "wait_for_pypi.sh" in step.get("run", ""):
            arguments = step["run"].split("wait_for_pypi.sh", 1)[1].split()
            assert arguments[-1] == "0", step["run"]
