"""Print the issue ids in a `snyk test --json-file-output` file, one per line.

Sorted and deduplicated, because the caller compares this against the same
list from the base branch with `comm`, which requires sorted input. Output is
deliberately just ids: comparing whole findings would flag a pull request for a
wording change in Snyk's advisory text.

`snyk test` writes an object for one project and an array for several, and
writes neither when it fails to scan at all — an unreadable file means "no
information", which is not the same as "no issues" but is the only safe answer
here: on the base branch it would wrongly widen the set of "new" findings, so
the caller treats an empty base as suspicious rather than clean.

Usage:  python tools/snyk_ids.py <snyk-json-file>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def issue_ids(payload: object) -> set[str]:
    found: set[str] = set()
    projects = payload if isinstance(payload, list) else [payload]
    for project in projects:
        if not isinstance(project, dict):
            continue
        for vulnerability in project.get("vulnerabilities") or []:
            if isinstance(vulnerability, dict):
                identifier = vulnerability.get("id")
                if isinstance(identifier, str):
                    found.add(identifier)
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    path = Path(sys.argv[1]).resolve()

    # A path that exists but is not a regular file is a caller mistake, not a
    # scan that did not run, and it should not be swallowed by the same
    # "could not read" branch. The exit code stays 0 either way: the caller
    # reads an empty list as "no information" and has its own check for that.
    if path.exists() and not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 0

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"could not read {path}: {error}", file=sys.stderr)
        return 0

    for identifier in sorted(issue_ids(payload)):
        print(identifier)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
