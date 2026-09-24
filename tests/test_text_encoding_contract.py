"""Nothing in this repository lets the locale choose a text encoding.

Breaking this rule produces the most expensive kind of failure: green on Linux
CI, where the default is UTF-8, and red on a Windows console, where it is
cp1252 — with a message that says nothing about encodings.

Three worked examples, all found on 2026-09-24:

- `subprocess.run(..., text=True)` with no `encoding=`. capture_output collects
  the pipes on reader threads, so the UnicodeDecodeError never reaches the
  calling frame; it leaves `.stdout` as None and the caller dies on
  "can only concatenate str (not NoneType)".
- `path.read_text()` on this repository's own source, which contains em dashes.
- `open(file)` on a user-supplied list of paths or domains.

Checked with ast, not with a regular expression, so that a keyword argument
written on its own line is still seen.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Directories that are not ours to fix.
SKIP_PARTS = {"__pycache__", ".venv", "venv", "node_modules", "mutants", ".hypothesis"}

# These read or write bytes, where an encoding would be meaningless.
BINARY_MODES = ("rb", "wb", "ab", "r+b", "w+b", "xb")


def _sources() -> list[pathlib.Path]:
    return [
        p for p in ROOT.rglob("*.py")
        if not SKIP_PARTS & set(p.parts)
    ]


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_binary(call: ast.Call) -> bool:
    mode = _kwarg(call, "mode")
    if mode is None and len(call.args) >= 2:
        mode = call.args[1]
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" in mode.value


def _offenders(path: pathlib.Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:                                   # not ours to parse
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)

        # subprocess.run/check_output/Popen decoding to str
        if name in ("run", "check_output", "Popen", "call", "check_call"):
            text = _kwarg(node, "text")
            universal = _kwarg(node, "universal_newlines")
            decodes = any(
                isinstance(v, ast.Constant) and v.value is True
                for v in (text, universal) if v is not None
            )
            if decodes and _kwarg(node, "encoding") is None:
                found.append(f"{path.name}:{node.lineno}: {name}(text=True) senza encoding=")

        # Path.read_text / Path.write_text
        elif name in ("read_text", "write_text") and _kwarg(node, "encoding") is None:
            found.append(f"{path.name}:{node.lineno}: .{name}() senza encoding=")

        # builtin open() in text mode
        elif name == "open" and isinstance(node.func, ast.Name):
            if not _is_binary(node) and _kwarg(node, "encoding") is None:
                found.append(f"{path.name}:{node.lineno}: open() in modo testo senza encoding=")

    return found


@pytest.mark.parametrize("path", _sources(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_text_is_decoded_with_the_locale_encoding(path):
    offenders = _offenders(path)
    assert not offenders, "\n".join(offenders)


def test_the_rule_actually_finds_something_when_it_is_broken(tmp_path):
    """A check that cannot fail is worse than no check.

    The three shapes above, written out, must all be caught — otherwise a green
    run here would mean only that the detector is broken.
    """
    bad = tmp_path / "bad.py"
    bad.write_text(
        "import subprocess, pathlib\n"
        "subprocess.run(['x'], capture_output=True, text=True)\n"
        "pathlib.Path('x').read_text()\n"
        "open('x')\n",
        encoding="utf-8",
    )
    assert len(_offenders(bad)) == 3


def test_the_rule_accepts_the_correct_forms(tmp_path):
    good = tmp_path / "good.py"
    good.write_text(
        "import subprocess, pathlib\n"
        "subprocess.run(['x'], text=True, encoding='utf-8')\n"
        "subprocess.run(['x'])\n"
        "pathlib.Path('x').read_text(encoding='utf-8')\n"
        "open('x', encoding='utf-8')\n"
        "open('x', 'rb')\n"
        "open('x', mode='wb')\n",
        encoding="utf-8",
    )
    assert _offenders(good) == []
