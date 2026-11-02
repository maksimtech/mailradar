"""The address the package publishes is the project alias, not a person's mailbox.

PyPI shows the authors' email to anyone, and bulk senders harvest it: on
2026-10-31 a cold "patch offer" sent through a mass-mailing account reached
the personal address this file used to carry. github@ is an alias that can be
filtered or closed without touching anyone's own mailbox.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_the_published_author_address_is_the_project_alias():
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    people = project.get("authors", []) + project.get("maintainers", [])

    assert people
    assert {person.get("email") for person in people} == {"github@maksimtech.com"}
