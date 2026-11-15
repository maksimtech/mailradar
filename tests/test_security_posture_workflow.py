"""What Security Posture reads on a pull request, and when it reads it.

On 2026-10-11 the gate was found to judge every pull request by the state of
main. Measured on mailradar #39: the step that waits for the scanners finished
in two seconds, because it compared the runs' head commit with GITHUB_SHA, which
on a pull request is the merge commit and matches no run; and the alerts were
listed without a `ref`, which is main's. A finding a pull request introduced
reached main before the gate could see it.

Measured the same day on one recent pull request of each of the six Radar, with
the real tool: the open alerts of `refs/pull/N/merge` (CodeQL reports there only
what the change introduces) checked against the closed alerts of both that ref
and main gave the same verdict as main in all six. The closed alerts of main are
needed: an exception whose finding went quiet is "settled" because main still
holds the closed alert, and a pull request ref, which has no history, would call
it unused and fail every pull request.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
POSTURE = WORKFLOWS / "security-posture.yml"


def _steps() -> dict[str, dict]:
    workflow = yaml.safe_load(POSTURE.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    return {step.get("name", ""): step for step in job["steps"]}


@pytest.fixture(scope="module")
def wait() -> dict:
    return _steps()["Wait for this commit's analyses"]


@pytest.fixture(scope="module")
def collect() -> dict:
    return _steps()["Collect the open alerts"]


def test_the_wait_looks_for_the_runs_of_the_commit_under_review(wait):
    """On a pull request the scanners' runs carry the head of the branch, not the
    merge commit GITHUB_SHA names."""
    assert wait["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert 'os.environ["HEAD_SHA"]' in wait["run"]
    assert 'os.environ["GITHUB_SHA"]' not in wait["run"]


def test_the_wait_knows_every_workflow_that_uploads_alerts(wait):
    """A scanner left off the list is not waited for, and its alerts are read
    before it has uploaded them. Bandit was off the list until 2026-10-11."""
    uploaders = set(wait["env"]["UPLOADERS"].split(","))
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "upload-sarif" in text or "codeql-action/analyze" in text:
            name = yaml.safe_load(text)["name"]
            assert name in uploaders, f"{path.name} ({name}) uploads alerts and is not waited for"


def test_every_name_it_waits_for_is_a_workflow_that_still_exists(wait):
    """The other direction. A name with no workflow behind it has no run to wait
    for, so it costs nothing on the day — and it is how a retired scanner stays
    on the list as if it still spoke. Written when snyk.yml was retired, on
    2026-11-02."""
    names = {yaml.safe_load(path.read_text(encoding="utf-8"))["name"] for path in WORKFLOWS.glob("*.yml")}
    for uploader in wait["env"]["UPLOADERS"].split(","):
        assert uploader in names, f"{uploader} is waited for and no workflow has that name"


def test_the_open_alerts_are_those_of_the_ref_under_review(collect):
    """github.ref is refs/pull/N/merge on a pull request and refs/heads/main on a
    push, a schedule or a dispatch: the same call serves both."""
    assert collect["env"]["ALERT_REF"] == "${{ github.ref }}"
    assert "alerts?state=open&per_page=100&ref=${ALERT_REF}" in collect["run"]


def test_the_closed_alerts_come_from_the_ref_and_from_main(collect):
    """main's closed alerts keep a quiet finding "settled" on a pull request,
    where the ref has no history of its own."""
    run = collect["run"]
    assert "alerts?state=closed&per_page=100&ref=${ALERT_REF}" in run
    assert "alerts?state=closed&per_page=100&ref=refs/heads/main" in run
    assert "closed.json" in run


def test_main_s_open_alerts_count_as_known_on_a_pull_request(collect):
    """On a pull request ref CodeQL reports only what the change introduces. On
    cookieradar #37 (2026-10-12) it reported one new alert, so CodeQL had spoken,
    and an exception for findings still open on main, in files the change did not
    touch, read as unused and failed the gate. main's open alerts are history the
    tool may match an entry against, like the closed ones; simulated on #37's real
    alerts, the false "unused" goes and the real new alert stays."""
    run = collect["run"]
    assert "alerts?state=open&per_page=100&ref=refs/heads/main" in run
    assert "open-main.json" in run


# ── Every page of alerts ─────────────────────────────────────────────────────
# The code scanning API returns at most a hundred alerts per call. On
# 2026-11-13 cookieradar #68 had 123 open alerts on its ref and main had 142:
# the gate read the first hundred, three exceptions whose findings sat further
# down read as matching nothing, and the build failed on a product whose every
# alert was explained. Read the other way, an unexplained alert past the
# hundredth would not have been seen at all.

ALERTS_URL = "/code-scanning/alerts?"


def _alerts_function(run: str) -> str:
    """The shell function the step reads alerts with, as written in the step."""
    lines = run.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("alerts() {"))
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "}")
    return "\n".join(lines[start:end + 1])


def test_every_read_of_the_alerts_goes_through_every_page(collect):
    run = collect["run"]
    function = _alerts_function(run)
    assert "gh api --paginate --slurp" in function
    reads = [line.strip() for line in run.splitlines() if ALERTS_URL in line]
    assert len(reads) == 4, reads
    for line in reads:
        assert line.startswith(("alerts ", "if alerts ")), f"read without paging: {line}"


def _posix(path: Path) -> str:
    """A path for bash's PATH: Git Bash on Windows splits C:/... at the colon."""
    import re

    text = path.as_posix()
    drive = re.match(r"([A-Za-z]):/(.*)", text)
    return f"/{drive.group(1).lower()}/{drive.group(2)}" if drive else text


def _run_alerts(tmp_path, collect, pages_json: str, gh_exit: int = 0):
    import shutil
    import subprocess
    import sys

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash to run the step's function with")
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "pages.json").write_text(pages_json, encoding="utf-8")
    (fake / "gh").write_text(
        "#!/bin/sh\n"
        f'cat "$(dirname "$0")/pages.json"\n'
        f"exit {gh_exit}\n",
        encoding="utf-8", newline="\n",
    )
    (fake / "gh").chmod(0o755)
    python_dir = _posix(Path(sys.executable).parent)
    script = (
        f'export PATH="{_posix(fake)}:{python_dir}:$PATH"\n'
        # Never the real gh: a test that reached GitHub would pass on its answer.
        f'[ "$(command -v gh)" = "{_posix(fake)}/gh" ] || {{ echo "the fake gh is not first on PATH" >&2; exit 99; }}\n'
        "GITHUB_REPOSITORY=owner/repo\n"
        + _alerts_function(collect["run"])
        + '\nalerts "repos/${GITHUB_REPOSITORY}/code-scanning/alerts?state=open&per_page=100&ref=x" out.json\n'
    )
    return subprocess.run([bash, "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                          encoding="utf-8")


def test_the_pages_are_joined_into_one_list(tmp_path, collect):
    import json

    result = _run_alerts(tmp_path, collect, '[[{"number": 1}, {"number": 2}], [{"number": 3}]]')
    assert result.returncode == 0, result.stderr
    alerts = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert [a["number"] for a in alerts] == [1, 2, 3]


def test_an_api_error_still_reads_as_an_error(tmp_path, collect):
    """The step tells an unreadable list apart from an empty one by the exit
    status of the read: a fork's token gets an error, not a clean product."""
    result = _run_alerts(tmp_path, collect, "[]", gh_exit=1)
    assert result.returncode not in (0, 99), result.stderr
