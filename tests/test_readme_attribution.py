"""What the README says about how this code was written, and what it must not say.

Naming the tool is transparency about the process, and cheap to keep honest. The
thing to stop it becoming is a claim of endorsement. The maintainer holds Anthropic's
CVP — Cyber Verification Programme — as a verified researcher: that is his
credential, it says nothing about this project's code, and it is not what the
attribution is about. Setting the two side by side, or reaching for words like
"official" or "certified", would assert something nobody here is in a position to
assert, and would do it in the one file everybody reads first.
"""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"

TOOL = "Claude Code"
LINK = "https://claude.com/claude-code"

# What would turn an attribution into a claim about who stands behind this.
BORROWED_AUTHORITY = (
    "official",          # covers "officially" too
    "endorse",           # and "endorsed", "endorsement"
    "certified",
    "approved by",
    "partnership",
    "sponsored",
)


def _paragraphs_naming_the_tool() -> list[str]:
    blocks = README.read_text(encoding="utf-8").split("\n\n")
    return [block for block in blocks if TOOL in block]


def test_the_readme_names_the_tool_the_code_was_written_with():
    readme = README.read_text(encoding="utf-8")

    assert TOOL in readme, "the attribution is the point of this file"
    assert LINK in readme, "naming it without linking it makes it harder to check"


def test_the_attribution_does_not_borrow_authority_it_does_not_have():
    """The failure this file exists for.

    A verified researcher's credential and the editor his code was written in are
    unrelated facts. A README that runs them together reads as "Anthropic stands
    behind this project", which is not true, was never claimed, and would be the kind
    of thing nobody notices until somebody relies on it.
    """
    naming = _paragraphs_naming_the_tool()
    assert naming, "nothing names the tool, so there is nothing to check"

    for block in naming:
        lowered = block.lower()
        for word in BORROWED_AUTHORITY:
            assert word not in lowered, f"{word!r} in: {block.strip()!r}"
        assert "cvp" not in lowered and "cyber verification" not in lowered, (
            "the maintainer's credential is his own and says nothing about this code"
        )
