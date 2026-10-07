"""What the README says about how this code was written, and what it must not say.

Naming the tool is transparency about the process, and cheap to keep honest. The
thing to stop it becoming is a claim of endorsement. The maintainer holds Anthropic's
CVP — Cyber Verification Programme — as a verified researcher: that is his
credential, it says nothing about this project's code, and it is not what the
attribution is about. Setting the two side by side, or reaching for words like
"official" or "certified", would assert something nobody here is in a position to
assert, and would do it in the one file everybody reads first.

The same file is where the package credits what it ships and did not write: the
Public Suffix List is Mozilla's, under MPL-2.0, and a copy of it travels in every
wheel and image.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

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


# ─── Third-party data shipped in the package ────────────────────────────────

PSL_FILE = "mailradar/public_suffix_list.dat"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def test_the_readme_credits_the_public_suffix_list_and_its_licence():
    """The list is not MIT like the rest: the README says whose it is and under what."""
    blocks = README.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n\n")
    naming = [block for block in blocks if PSL_FILE in block]
    assert naming, f"the README does not name {PSL_FILE}"

    block = " ".join(" ".join(naming).split())
    for expected in ("Public Suffix List", "Mozilla", "MPL-2.0",
                     "https://publicsuffix.org", "https://mozilla.org/MPL/2.0/"):
        assert expected in block, f"{expected!r} missing where the README names {PSL_FILE}"


def test_the_shipped_list_keeps_its_licence_notice():
    """MPL-2.0 §3.1 asks recipients to be told the licence and where to read it: the
    file's own header does that, so a refresh must not lose it."""
    head = (ROOT / PSL_FILE).read_text(encoding="utf-8")[:1000]
    assert "Mozilla Public" in head and "https://mozilla.org/MPL/2.0/" in head
    assert "// VERSION: " in head, "the header says which release of the list this is"


def test_the_code_loading_the_list_says_how_to_refresh_it():
    """A vendored list goes stale as suffixes are added; the comment where it is
    loaded is where the next person looks for how to update it."""
    for source in sorted((ROOT / "mailradar").glob("*.py")):
        lines = source.read_text(encoding="utf-8").splitlines()
        loading = [i for i, line in enumerate(lines)
                   if "public_suffix_list.dat" in line and not line.lstrip().startswith("#")]
        if loading:
            break
    else:
        raise AssertionError("no module loads public_suffix_list.dat")

    comment = []
    i = loading[0] - 1
    while i >= 0 and lines[i].lstrip().startswith("#"):
        comment.insert(0, lines[i].lstrip("# ").strip())
        i -= 1
    text = " ".join(comment)
    assert "periodically" in text, f"{source.name}: the comment does not say to refresh the list periodically"
    assert PSL_URL in text, f"{source.name}: the comment does not say where to download it from"
