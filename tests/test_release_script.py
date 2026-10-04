"""
Tests for release.sh against throwaway git repositories (bare remote + clone).

Ported from cookieradar, which had them and did not have the defect: on 2026-10-03
this script stopped a release with `fatal: no tag message?`, because `git tag ${TAG}`
with no message is a signed tag where `tag.gpgsign` is true, and a signed tag needs
one. cookieradar's suite asserts `git cat-file -t <tag>` is `tag`; a bare `git tag`
makes a lightweight one, which resolves to `commit`, so that assertion would have
caught it here too. There simply was no suite.

The half of the incident that did the damage was not covered anywhere. The script
pushed main *before* tagging, so when the tag step died the bump was already on the
remote: a version nothing pointed at, and no workflow to react to it, because they
trigger on the tag. `test_a_tag_that_cannot_be_made_leaves_the_remote_untouched` is
that case, and it passes only because the tag is now made before anything is pushed
and the push is atomic.
"""
import pathlib
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
# The throwaway repository's starting version, which is deliberately not read
# from the package: the only test that must track the real one is the last, and
# it computes the next count itself. Tying this to the package broke the port to
# apkradar, which had just released 2026.42 — the version these cases release.
CURRENT = "2026.41"

# release.sh calls python3 and bash. Git Bash on Windows provides bash but not
# python3, so the script exits 127 before reaching any of the checks these cases
# assert on — a missing toolchain reported as a failing release script. Skipped
# with a reason instead: Linux CI, where the release actually runs, is unaffected.
pytestmark = pytest.mark.skipif(
    shutil.which("python3") is None,
    reason="release.sh requires python3 on PATH (absent in Git Bash on Windows)",
)


def _git(cwd, *args, check=True):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=check,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(
        "[user]\n\tname = Test\n\temail = test@example.com\n"
        "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")

    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(remote), str(work))
    (work / "mailradar").mkdir()
    (work / "mailradar" / "__init__.py").write_text(f'__version__ = "{CURRENT}"\n', encoding="utf-8")
    shutil.copy(ROOT / "release.sh", work / "release.sh")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "initial")
    _git(work, "push", "-q", "origin", "main")
    return work, remote


def _release(work, *args):
    return subprocess.run(["bash", "release.sh", *args], cwd=work, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60)


def _remote_tags(remote):
    return _git(remote, "tag").split()


def test_release_bumps_version_and_pushes_commit_and_tag(repo):
    work, remote = repo

    proc = _release(work, "2026.42")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (work / "mailradar" / "__init__.py").read_text(encoding="utf-8") == '__version__ = "2026.42"\n'
    assert _git(remote, "log", "-1", "--format=%s", "main") == "chore: bump version to 2026.42"
    assert _remote_tags(remote) == ["v2026.42"]
    assert _git(remote, "rev-parse", "v2026.42^{commit}") == _git(remote, "rev-parse", "main")
    assert _git(remote, "cat-file", "-t", "v2026.42") == "tag"  # annotated


def _assert_refused(proc, remote, message, work=None):
    """Refused, and nothing committed on the way to refusing.

    The local half was added after mutating the script: replacing the existing-tag
    check's `fail` with an `echo` of the same words left every one of these green,
    because the script carried on, bumped, committed, and only then did `git tag`
    refuse the tag that already existed. The release was still refused — after a
    commit, which is the opposite of what this script promises. A refusal may leave
    the version file modified, and nothing else.

    The commit is what is checked, not the local tags: the script runs
    `git fetch --tags`, so in the case where the tag exists only on the remote it
    arrives locally even when everything works.
    """
    assert proc.returncode != 0
    assert message in proc.stdout + proc.stderr
    assert _remote_tags(remote) == []
    assert _git(remote, "log", "-1", "--format=%s", "main") == "initial"

    if work is not None:
        # Its own commit, recognised by the message it writes, rather than "the local
        # branch is where it started": one case below puts an extra local commit there
        # on purpose, to make main and origin/main disagree.
        assert not _git(work, "log", "-1", "--format=%s", "main").startswith(
            "chore: bump version to"
        ), "it committed on its way to refusing"


def test_release_requires_argument(repo):
    work, remote = repo
    _assert_refused(_release(work), remote, "Usage:", work)


@pytest.mark.parametrize(
    "version",
    [
        "v2026.42",        # the tag, not the version
        "2026.42-rc1",     # not a release
        "latest",          # not a version at all
        "2026",            # a year on its own
        "2026.09.5",       # the old month form, which sorts below 2026.10 under PEP 440
        "2026.42.0",       # a fix numbered zero is the baseline, which already shipped
        "2026.0",          # a count of zero is nobody's release
    ],
)
def test_release_rejects_invalid_version(repo, version):
    work, remote = repo
    _assert_refused(_release(work, version), remote, "Invalid version", work)


@pytest.mark.parametrize("version", ["2026.9.5", "2026.12.3", "2026.1.1"])
def test_release_rejects_a_middle_segment_that_reads_as_a_month(repo, version):
    """Refused for saying so, rather than refused as malformed.

    2026.9.5 is the shape of both a count with a fix and the old YYYY.M.N, and
    nothing can tell them apart by looking: the count is past forty for every
    Radar, so a middle segment of twelve or less is a month by any reasonable
    reading. Being told which of the two rules refused it is the difference
    between fixing the version and arguing with the regex.
    """
    work, remote = repo
    _assert_refused(_release(work, version), remote, "Ambiguous version", work)


def test_release_rejects_current_version(repo):
    work, remote = repo
    _assert_refused(_release(work, CURRENT), remote, "is already the current version", work)


def test_release_requires_main_branch(repo):
    work, remote = repo
    _git(work, "checkout", "-q", "-b", "feature")

    _assert_refused(_release(work, "2026.42"), remote, "Not on main", work)


def test_release_requires_clean_tree(repo):
    work, remote = repo
    (work / "notes.txt").write_text("wip", encoding="utf-8")

    _assert_refused(_release(work, "2026.42"), remote, "Working tree not clean", work)


def test_release_refuses_when_behind_origin(repo, tmp_path):
    work, remote = repo
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", str(remote), str(other))
    (other / "x.txt").write_text("x", encoding="utf-8")
    _git(other, "add", ".")
    _git(other, "commit", "-q", "-m", "someone else")
    _git(other, "push", "-q", "origin", "main")

    proc = _release(work, "2026.42")

    assert proc.returncode != 0
    assert "is not aligned with origin/main" in proc.stdout + proc.stderr
    assert _remote_tags(remote) == []


def test_release_refuses_unpushed_commits(repo):
    work, remote = repo
    (work / "x.txt").write_text("x", encoding="utf-8")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "local only")

    _assert_refused(_release(work, "2026.42"), remote, "is not aligned with origin/main", work)


def test_release_refuses_tag_existing_only_on_remote(repo, tmp_path):
    work, remote = repo
    _git(remote, "tag", "v2026.42", "main")

    proc = _release(work, "2026.42")

    assert proc.returncode != 0
    assert "already exists" in proc.stdout + proc.stderr
    assert _git(remote, "log", "-1", "--format=%s", "main") == "initial"
    # Not routed through _assert_refused: the tag on the remote is this case's own
    # setup, so "no remote tags" cannot hold here. What has to hold is that it
    # refused *before committing* — replacing this check's `fail` with an `echo` of
    # the same words left every case in this file green, because `git tag` then
    # refused the tag that already existed by itself, one commit too late.
    assert not _git(work, "log", "-1", "--format=%s", "main").startswith(
        "chore: bump version to"
    ), "it committed on its way to refusing"


def _current_version() -> str:
    import re

    text = (ROOT / "mailradar" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "(.+?)"', text)
    assert match, "mailradar/__init__.py has no __version__"
    return match.group(1)


def test_the_script_accepts_the_version_this_repository_is_on(repo):
    """The check that the release path still fits the scheme in use.

    Read out of `mailradar/__init__.py` rather than written here: a literal
    passes for as long as somebody remembers to change it, which is exactly how the
    old YYYY.MM.N check survived the move to counts. What is released in the
    throwaway repository is the next count, but it has to get past the same
    validation the current version would.
    """
    work, remote = repo
    current = _current_version()
    year, count = current.split(".")[0], int(current.split(".")[1])

    proc = _release(work, f"{year}.{count + 1}")

    assert "Invalid version" not in proc.stderr, proc.stderr
    assert "Ambiguous version" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr


def test_the_tag_carries_a_message(repo):
    """Annotated is asserted above by `cat-file -t`; this is the message itself,
    which is what `git tag -a` without `-m` cannot produce."""
    work, remote = repo

    assert _release(work, "2026.42").returncode == 0
    message = _git(remote, "tag", "-l", "--format=%(contents)", "v2026.42")

    assert message.strip(), "the tag has no message"
    assert "MailRadar" in message


def test_a_tag_that_cannot_be_made_leaves_the_remote_untouched(repo, tmp_path):
    """The incident of 2026-10-03, as a test.

    Tag signing on and a signing program that does not exist, so `git tag -a` fails
    exactly where it failed then. What must not happen is what did happen: the bump
    reaching the remote while the tag does not, leaving a version nothing points at
    and no workflow reacting, since they trigger on the tag.

    It passes because the tag is now made before anything is pushed, and the push is
    atomic. Against the old order it fails on the last assertion.
    """
    work, remote = repo
    config = pathlib.Path(tmp_path / "gitconfig")
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace("[tag]\n\tgpgsign = false", "[tag]\n\tgpgsign = true")
        + "[gpg]\n\tprogram = /nonexistent/gpg\n",
        encoding="utf-8",
    )

    proc = _release(work, "2026.42")

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _remote_tags(remote) == []
    assert _git(remote, "log", "-1", "--format=%s", "main") == "initial", (
        "the bump reached the remote without its tag"
    )


@pytest.fixture
def python3_with_pytest(tmp_path, monkeypatch):
    """A `python3` on PATH that is this interpreter, because the gate runs
    `python3 -m pytest` and the machine's own python3 — a shim to the system
    install on Windows — has no pytest. What these cases are about is the gate, not
    the toolchain, and faking the interpreter is closer to the script's behaviour
    than giving the script a knob.
    """
    import os
    import sys

    folder = tmp_path / "bin"
    folder.mkdir(exist_ok=True)
    (folder / "python3").write_text(
        f'#!/bin/sh\nexec "{pathlib.PurePath(sys.executable).as_posix()}" "$@"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.environ['PATH']}")


def _add_suite(work, body: str) -> None:
    """A tests/ directory in the throwaway repository, committed and pushed.

    Every other case here runs against a repository with no tests at all, which is
    why the script must not treat their absence as a failure — and why these three
    have to put one there to say anything about the gate.
    """
    (work / "tests").mkdir(exist_ok=True)
    (work / "tests" / "test_sandbox.py").write_text(body, encoding="utf-8")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "a suite")
    _git(work, "push", "-q", "origin", "main")


def test_a_failing_suite_stops_the_release(repo, python3_with_pytest):
    """The gap this closes. The version is written first, so a suite run before the
    release cannot see what the bump breaks: on 2026-10-03 and again on 2026-10-04
    the README's stated version failed in CI, on main, with the tag already pushed.

    Nothing may be committed, tagged or pushed. The modified version file is left
    where it is, because that is the evidence of what was attempted.
    """
    work, remote = repo
    _add_suite(work, "def test_no():\n    assert False, 'the suite says no'\n")
    head_before = _git(work, "rev-parse", "HEAD")

    proc = _release(work, "2026.42")

    assert proc.returncode != 0, proc.stdout + proc.stderr
    said = proc.stdout + proc.stderr
    assert "suite" in said.lower() or "test" in said.lower()
    assert _remote_tags(remote) == []
    assert _git(work, "rev-parse", "HEAD") == head_before, "it committed anyway"
    assert _git(remote, "log", "-1", "--format=%s", "main") == "a suite"


def test_a_passing_suite_lets_it_through(repo, python3_with_pytest):
    work, remote = repo
    _add_suite(work, "def test_yes():\n    assert True\n")

    proc = _release(work, "2026.42")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _remote_tags(remote) == ["v2026.42"]


def test_a_repository_with_no_tests_is_not_held_up(repo):
    """Which is every other case in this file, and the reason the gate asks whether
    there is a suite before insisting on one."""
    work, remote = repo

    assert _release(work, "2026.42").returncode == 0
    assert _remote_tags(remote) == ["v2026.42"]


def test_the_push_is_atomic_so_a_refused_tag_leaves_main_alone(repo):
    """Half a release is worse than none, and this is the half that happens.

    Not measured until the script was mutated: replacing `git push --atomic origin
    main "$TAG"` with two separate pushes left every case here green. With two pushes
    main arrives and the tag does not, so the repository carries a version bump that
    no release and no published artifact corresponds to — and the tag that would
    produce them cannot be pushed by this script afterwards either, because the
    version it would be given is now "already the current version".

    The remote refuses tags through a pre-receive hook, which is the way to make the
    second half fail on demand.
    """
    work, remote = repo

    hook = remote / "hooks" / "pre-receive"
    hook.write_text(
        "#!/bin/sh\n"
        "while read -r _ _ ref; do\n"
        '  case "$ref" in refs/tags/*) echo "tags refused here" >&2; exit 1;; esac\n'
        "done\n"
        "exit 0\n",
        encoding="utf-8",
        # CRLF here and the shebang never runs, so the hook is never
        # consulted and the push it was written to refuse succeeds.
        newline="\n",
    )
    hook.chmod(0o755)

    proc = _release(work, "2026.42")

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _remote_tags(remote) == []
    assert _git(remote, "log", "-1", "--format=%s", "main") == "initial", (
        "main moved although the tag was refused: the push was not atomic"
    )
