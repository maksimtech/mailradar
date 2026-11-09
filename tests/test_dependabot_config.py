"""Dependabot proposes what may be merged, and no more.

The Radar take a dependency once its release is at least 14 days old, unless a
known vulnerability makes the older version the risk. Without a cooldown
Dependabot opened, on 2026-10-29 and 2026-11-02 across the Radar, twelve pull
requests for releases two to thirteen days old: each one waited, red or not,
for a date nothing recorded. Dependabot's security updates are not subject to
the cooldown, so the exception keeps working on its own.

Actions updates come as one pull request a week rather than one per action.
"""
from __future__ import annotations

from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[1] / ".github" / "dependabot.yml"


def updates() -> list[dict]:
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))["updates"]


def test_every_ecosystem_waits_fourteen_days_after_a_release():
    for update in updates():
        days = (update.get("cooldown") or {}).get("default-days", 0)
        assert days >= 14, f"{update['package-ecosystem']}: cooldown {days} days"


def test_actions_updates_arrive_as_one_pull_request():
    actions = next(u for u in updates() if u["package-ecosystem"] == "github-actions")
    patterns = [p for group in (actions.get("groups") or {}).values() for p in group.get("patterns", [])]
    assert "*" in patterns, f"no group takes every action: {patterns}"
