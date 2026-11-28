"""SECURITY.md offers the same two private channels in every Radar, and names its own
repository (maksimtech/apkradar#153).

Email with GPG first, then GitHub's private vulnerability reporting. The six files
were copied from one another, and a copied PVR link would send a report to the
wrong project's advisories, unseen by the person reading this one.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
REPO = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]

ACKNOWLEDGEMENT = (
    "Reports are acknowledged within 7 days, and a vulnerability is disclosed in "
    "coordination with the reporter, who is credited in the advisory and the "
    "CHANGELOG if they wish."
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_email_channel_comes_first_with_its_key():
    reporting = POLICY.split("## Reporting a vulnerability", 1)[1].split("\n## ", 1)[0]
    assert "<security@maksimtech.com>" in reporting
    assert "keys.openpgp.org" in reporting
    assert reporting.index("security@maksimtech.com") < reporting.index("security/advisories/new")


def test_private_vulnerability_reporting_links_this_repository():
    assert f"<https://github.com/maksimtech/{REPO}/security/advisories/new>" in POLICY


def test_no_other_repository_is_linked_for_reports():
    linked = set(re.findall(r"github\.com/maksimtech/([A-Za-z0-9_.-]+)/security/advisories", POLICY))
    assert linked == {REPO}


def test_what_happens_after_a_report_is_said_as_in_every_radar():
    assert ACKNOWLEDGEMENT in _flat(POLICY)
