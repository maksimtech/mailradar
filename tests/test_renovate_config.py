"""Renovate proposes what may be merged, and merges on its own only what nobody
needs to read.

Until 2026-11-24 Dependabot asked for mailradar's version updates
(`.github/dependabot.yml`, whose rules tests/test_dependabot_config.py held).
Renovate takes over with apkradar's rules, where it has run since 2026-11-18
(alignment to apkradar, step 4):

- a release is taken at least 14 days after it is out, unless a known
  vulnerability makes the older version the risk. Without the wait, on
  2026-10-29 and 2026-11-02, twelve pull requests across the Radar asked for
  releases two to thirteen days old;
- Actions updates arrive as one pull request a week, not one per action;

- one batch a week, on Thursday, the day before the Friday release;
- minor, patch and digest updates merge on their own once the required checks
  pass; a major waits for a person;
- the lower bounds in pyproject.toml are raised by hand, when the code needs
  them, and Renovate only moves uv.lock within them. A bound raised by a bot is a
  bound no test asked for, and the other way round is how apkradar went wrong on
  2026-11-15: code written against mailradar's main while the bound still said
  2026.44;
- the Python the image and the matrix run is a decision (the image's is held by
  tests/test_docker_python.py): no bot moves it;
- Actions are pinned to a commit digest, not to a tag that can be moved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github" / "renovate.json"


def config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def rules() -> list[dict]:
    return config().get("packageRules", [])


def _days(age: str) -> int:
    match = re.fullmatch(r"(\d+) days?", age)
    assert match, f"minimumReleaseAge {age!r} is not written in days"
    return int(match.group(1))


def test_dependabot_no_longer_asks_for_version_updates():
    """Two bots on one stream open every pull request twice."""
    assert not (ROOT / ".github" / "dependabot.yml").exists()


def test_every_release_waits_fourteen_days():
    assert _days(config()["minimumReleaseAge"]) >= 14


def test_a_known_vulnerability_does_not_wait():
    alerts = config()["vulnerabilityAlerts"]
    assert alerts.get("enabled", True) is True
    assert alerts["minimumReleaseAge"] is None
    assert alerts["schedule"] == ["at any time"]


def test_one_weekly_batch_the_day_before_the_release():
    assert config()["schedule"] == ["before 6am on thursday"]
    assert config()["timezone"] == "Europe/Rome"


def test_actions_updates_arrive_as_one_pull_request():
    actions = [r for r in rules() if r.get("matchManagers") == ["github-actions"]]
    assert len(actions) == 1 and actions[0].get("groupName"), actions


def test_actions_are_pinned_to_a_commit_and_a_full_version():
    """Pinned to a commit digest, with the full version beside it (`# v4.39.3`).

    `helpers:pinGitHubActionDigests` alone pins `@v4` as `@<sha> # v4`. Its later
    updates are digest moves, which carry no release timestamp; with Renovate's
    default `minimumReleaseAgeBehaviour: timestamp-required` they never pass the
    14-day wait, and the actions would never be updated again (seen on #111,
    2026-11-19: `renovate/stability-days` pending on commits 14 to 125 days old).
    The `ToSemver` preset extends it and tracks full versions, which have dates.
    """
    assert "helpers:pinGitHubActionDigestsToSemver" in config()["extends"]


def test_pinning_waits_for_nothing():
    """Pinning `@v4` to the commit `v4` names today changes no line that runs, so
    there is no release to let age; and the update has no timestamp to wait on."""
    pins = [r for r in rules() if r.get("matchUpdateTypes") == ["pinDigest"]]
    assert len(pins) == 1 and "minimumReleaseAge" in pins[0] and pins[0]["minimumReleaseAge"] is None, pins


def test_lower_bounds_are_raised_by_hand():
    python = [r for r in rules() if r.get("matchManagers") == ["pep621"]]
    assert python and all(r.get("rangeStrategy") == "update-lockfile" for r in python), python


def test_a_major_waits_for_a_person():
    for rule in rules():
        if rule.get("automerge"):
            types = rule.get("matchUpdateTypes")
            assert types, f"an automerge rule with no update types takes majors too: {rule}"
            assert "major" not in types, rule


def test_no_bot_moves_the_python_we_run():
    frozen = [
        r for r in rules()
        if r.get("matchDepNames") == ["python"] and r.get("enabled") is False
    ]
    assert frozen, "a rule has to keep Renovate off the Python version"
    assert set(frozen[0]["matchUpdateTypes"]) >= {"major", "minor"}


def test_uv_lock_is_the_only_lock_renovate_moves():
    """Renovate reads a `requirements*.txt` as one more manager and bumps it in
    pull requests of its own, apart from uv.lock. mailradar had one until
    2026-11-25: requirements-ci.txt, which no workflow had installed from since
    2026-09-05, and which a test held to uv.lock. Its first dashboard (#169)
    queued typer twice, once per file, and every one of those pull requests
    would have failed that test. One lock, as in the other five Radar."""
    assert sorted(p.name for p in ROOT.glob("requirements*.txt")) == []
