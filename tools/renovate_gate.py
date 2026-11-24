"""Refuse a Renovate pull request whose own checks are not green.

GitHub's auto-merge waits only for the required checks. Renovate reports its
own problems as commit statuses (`renovate/artifacts`, `renovate/stability-days`)
that are not required, and cannot be: pull requests that are not Renovate's
never get them. On 2026-11-19 that let apkradar#81 merge a lock Renovate itself
had marked as failed. This script is the required check that reads them
(tests/test_renovate_gate.py); it is apkradar's, unchanged but for this
paragraph (alignment to apkradar, step 4).

Run by `.github/workflows/renovate-gate.yml` with BRANCH (the PR's head
branch), SHA (the PR's head commit), REPO and GH_TOKEN. Uses only the standard
library: a gate should not depend on what it guards.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import time

# Renovate sets its statuses right after pushing the branch; a run started by
# that push can read the commit before they are there.
SETTLE_SECONDS = 30

# How a Renovate pull request is known: its branch starts with Renovate's
# `branchPrefix`, `renovate/` unless .github/renovate.json says otherwise
# (tests/test_renovate_gate.py holds the two equal). Renovate's own statuses
# are always `renovate/...`, whatever the branch prefix: STATUS_PREFIX.
BRANCH_PREFIX = "renovate/"
STATUS_PREFIX = "renovate/"


def verdict(branch: str, statuses: list[dict]) -> tuple[bool, str]:
    """(passes, why) for a pull request from `branch` whose head commit has `statuses`.

    `statuses` is the combined status of the commit: the latest state of each context.
    """
    if not branch.startswith(BRANCH_PREFIX):
        return True, f"{branch} is not a Renovate branch"
    own = sorted((s for s in statuses if s["context"].startswith(STATUS_PREFIX)), key=lambda s: s["context"])
    bad = [f"{s['context']} is {s['state']}" + (f" ({s['description']})" if s.get("description") else "")
           for s in own if s["state"] != "success"]
    if bad:
        return False, "; ".join(bad)
    names = ", ".join(s["context"] for s in own) or "none set"
    return True, f"Renovate's own checks are green ({names})"


def combined_statuses(repo: str, sha: str, token: str) -> list[dict]:
    """The latest status of each context on `sha`, from GitHub's combined status."""
    connection = http.client.HTTPSConnection("api.github.com", timeout=30)
    try:
        connection.request("GET", f"/repos/{repo}/commits/{sha}/status?per_page=100", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "renovate-gate",
        })
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
    if response.status != 200:
        raise RuntimeError(f"GitHub answered {response.status} for the statuses of {sha}")
    return json.loads(body)["statuses"]


def main() -> int:
    branch, sha, repo, token = (os.environ[k] for k in ("BRANCH", "SHA", "REPO", "GH_TOKEN"))
    if branch.startswith(BRANCH_PREFIX):
        time.sleep(SETTLE_SECONDS)
        statuses = combined_statuses(repo, sha, token)
    else:
        statuses = []
    ok, why = verdict(branch, statuses)
    print(("pass: " if ok else "refused: ") + why)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
