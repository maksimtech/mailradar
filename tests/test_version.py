"""Tests for MailRadar --version option."""
import re
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

import mailradar
from mailradar.cli import app

ROOT = Path(__file__).resolve().parent.parent


class TestVersion(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_version_output(self):
        result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.output.strip(), f"MailRadar {mailradar.__version__}")

    def test_version_exit_code(self):
        result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.exit_code, 0)

    def test_version_not_hardcoded(self):
        with patch.object(mailradar, "__version__", "9999.99.99"):
            result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output.strip(), "MailRadar 9999.99.99")

    def test_version_aligned_with_pyproject(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = pyproject["project"]
        if "version" in project:
            expected = project["version"]
        else:
            self.assertIn("version", project.get("dynamic", []))
            source = ROOT / pyproject["tool"]["hatch"]["version"]["path"]
            match = re.search(
                r'^__version__\s*=\s*["\']([^"\']+)["\']', source.read_text(encoding="utf-8"), re.MULTILINE
            )
            self.assertIsNotNone(match)
            expected = match.group(1)
        self.assertEqual(mailradar.__version__, expected)

    def test_readme_does_not_call_a_released_option_unreleased(self):
        """The README said `--version` was "not yet in a published release" until
        2026-11-17, two months after 2026.09.9 shipped it and with 2026.47 on PyPI.

        A README paragraph that calls something unreleased may only name, in
        backticks, things no dated CHANGELOG section has recorded yet.
        """
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        released = changelog.split("\n## [Unreleased]", 1)[-1].split("\n## [", 1)[-1]
        unreleased_claim = re.compile(
            r"not\s+yet\s+(?:in\s+a\s+published\s+release|released|published)", re.IGNORECASE
        )
        for paragraph in re.split(r"\n\s*\n", readme):
            if not unreleased_claim.search(paragraph):
                continue
            for name in re.findall(r"`([^`\n]+)`", paragraph):
                self.assertFalse(
                    f"`{name}`" in released,
                    f"README calls `{name}` unreleased, but a dated CHANGELOG section records it",
                )


if __name__ == "__main__":
    unittest.main()
