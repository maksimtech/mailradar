"""Write a pinned requirements file for Snyk to read.

Snyk builds a Python dependency tree from poetry.lock, requirements.txt,
Pipfile or setup.py. These projects have none of those: hatchling with PEP 621
dependencies in pyproject.toml and no lockfile. So the tree is resolved here
and handed over in the one format Snyk does read.

`pip install --dry-run --report` does the resolution without installing
anything, which is both faster in CI and honest about what the scan covers:
every transitive dependency pip would pull in, not just the direct ones listed
in pyproject.toml.

Usage:  python tools/snyk_requirements.py <project-dir> <output-file>
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


def project_name(project_dir: Path) -> str | None:
    """The distribution's own name, so it is not reported as its own dependency."""
    try:
        data = tomllib.loads((project_dir / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    name = data.get("project", {}).get("name")
    return name.lower().replace("_", "-") if isinstance(name, str) else None


def resolve(project_dir: Path) -> list[tuple[str, str]]:
    # Absolute, because this path becomes a pip argument. A relative path that
    # begins with a dash is read as a flag — a directory named "-r" would turn
    # `pip install -r` into "read a requirements file" — and an absolute path
    # cannot begin with a dash on any platform. Removing the ambiguity beats
    # trying to detect it.
    target = project_dir.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "--dry-run", "--quiet",
                "--ignore-installed",
                "--report", str(report),
                str(target),
            ],
            check=True,
        )
        data = json.loads(report.read_text(encoding="utf-8"))

    packages = []
    for entry in data.get("install", []):
        meta = entry.get("metadata", {})
        name, version = meta.get("name"), meta.get("version")
        if name and version:
            packages.append((name.lower().replace("_", "-"), version))
    return sorted(set(packages))


def checked(project_dir: Path, output: Path) -> str | None:
    """Why these arguments cannot be used, or None when they can.

    Checked before pip runs, so a mistyped path costs an error message rather
    than a CalledProcessError traceback from the middle of a resolution.

    The pyproject.toml requirement is the one that matters most, and it is not
    about tidiness: without it the distribution's own name is unknown, the
    filter that keeps it out of its own dependency list matches nothing, and
    the project is written into the file as depending on itself. That is a
    wrong answer produced in silence.
    """
    if not project_dir.is_dir():
        return f"not a directory: {project_dir}"
    if not (project_dir / "pyproject.toml").is_file():
        return f"no pyproject.toml in {project_dir}"
    if not output.parent.is_dir():
        return f"no directory to write into: {output.parent}"
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    project_dir, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()

    problem = checked(project_dir, output)
    if problem:
        print(problem, file=sys.stderr)
        return 2

    own = project_name(project_dir)

    lines = [
        f"{name}=={version}"
        for name, version in resolve(project_dir)
        if name != own
    ]
    if not lines:
        # An empty requirements file makes Snyk report "no supported target
        # files", which reads like a broken scan rather than a project with no
        # dependencies. Say which it is.
        print(f"No third-party dependencies resolved for {project_dir}", file=sys.stderr)

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
