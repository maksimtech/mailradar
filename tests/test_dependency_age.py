"""A release is taken at least 14 days after it is out, and uv enforces it.

Renovate's minimumReleaseAge alone is not enough: on 2026-11-19 Renovate opened
apkradar#81 for pytest-asyncio 1.4.1.post1, and the lock it wrote held 1.5.0,
published seven days earlier. Renovate updates the lock with
`uv lock --upgrade-package`, and uv takes the newest version the range allows,
whatever Renovate's minimumReleaseAge says. The age rule therefore lives in uv
itself, so every lock, Renovate's and ours, is written under it (alignment to
apkradar, step 4).

apkradar exempts mailradar and cookieradar, the Radars it builds on, whose
releases ship in the same monthly cycle. mailradar builds on neither, so
nothing is exempt here, in uv or in Renovate.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def uv_settings() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8")).get("tool", {}).get("uv", {})


def lock_options() -> dict:
    return tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8")).get("options", {})


def renovate_rules() -> list[dict]:
    config = json.loads((ROOT / ".github" / "renovate.json").read_text(encoding="utf-8"))
    return config.get("packageRules", [])


def test_uv_takes_nothing_newer_than_fourteen_days():
    age = uv_settings().get("exclude-newer")
    assert age, "pyproject.toml has no [tool.uv] exclude-newer"
    match = re.fullmatch(r"(\d+) days?", age)
    assert match, f"exclude-newer {age!r} is not a span in days"
    assert int(match.group(1)) >= 14


def test_no_package_is_exempt_in_uv():
    assert "exclude-newer-package" not in uv_settings(), uv_settings()


def test_the_lock_was_written_under_the_rule():
    """A lock written before the setting, or by hand, says nothing about age."""
    options = lock_options()
    assert options.get("exclude-newer-span") == "P14D", options
    assert "exclude-newer-package" not in options, options


def test_renovate_exempts_no_package_from_the_wait():
    """Only a pin to today's commit waits for nothing (tests/test_renovate_config.py)."""
    exempt = [r for r in renovate_rules() if "minimumReleaseAge" in r and r["minimumReleaseAge"] is None]
    assert all(r.get("matchUpdateTypes") == ["pinDigest"] for r in exempt), exempt
