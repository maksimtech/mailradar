"""Tests for Docker image build configuration and security policy."""
import re
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
DOCKER_WORKFLOW = (ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8")
SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def _run_instructions(dockerfile: str) -> list[str]:
    """Return each RUN instruction, with line continuations joined."""
    joined = re.sub(r"\\\n", " ", dockerfile)
    return [line for line in joined.splitlines() if line.startswith("RUN ")]


class TestDockerfile(unittest.TestCase):

    def test_pip_upgraded_before_installing_mailradar(self):
        runs = _run_instructions(DOCKERFILE)
        upgrade = [i for i, r in enumerate(runs)
                   if re.search(r"pip install .*(-U|--upgrade) pip\b", r)]
        install = [i for i, r in enumerate(runs) if "mailradar==" in r]
        self.assertTrue(upgrade, "no RUN step upgrades pip")
        self.assertTrue(install, "no RUN step installs mailradar")
        self.assertLess(upgrade[0], install[0])

    def test_pip_removed_after_installing_mailradar(self):
        runs = _run_instructions(DOCKERFILE)
        install = [i for i, r in enumerate(runs) if "mailradar==" in r]
        uninstall = [i for i, r in enumerate(runs)
                     if re.search(r"pip uninstall .*\bpip\b", r) and "-y" in r]
        self.assertTrue(uninstall, "no RUN step uninstalls pip")
        self.assertGreater(uninstall[0], install[-1])
        # Dopo la rimozione nessun altro passo può usare pip
        for r in runs[uninstall[0] + 1:]:
            self.assertNotRegex(r, r"\bpip3? install\b")

    def test_pip_removed_as_root(self):
        # La disinstallazione scrive in site-packages: deve precedere USER
        uninstall_pos = DOCKERFILE.find("pip uninstall")
        user_pos = DOCKERFILE.find("\nUSER ")
        self.assertNotEqual(uninstall_pos, -1)
        self.assertNotEqual(user_pos, -1)
        self.assertLess(uninstall_pos, user_pos)


class TestDockerWorkflow(unittest.TestCase):

    def test_weekly_schedule(self):
        match = re.search(r"schedule:\s*\n(?:\s*#.*\n)*\s*-\s*cron:\s*'([^']+)'", DOCKER_WORKFLOW)
        self.assertIsNotNone(match, "no schedule trigger")
        _minute, _hour, dom, month, dow = match.group(1).split()
        self.assertEqual((dom, month), ("*", "*"))
        self.assertRegex(dow, r"^[0-7]$", "cron must run on one day of the week")

    def test_schedule_rebuilds_latest_release_tag(self):
        self.assertIn("git tag --list 'v*' --sort=-v:refname", DOCKER_WORKFLOW)

    def test_schedule_pushes_only_latest(self):
        self.assertRegex(
            DOCKER_WORKFLOW,
            r"github\.event_name != 'schedule' && format\('maksimtech/mailradar:\{0\}'",
        )

    def test_schedule_builds_without_cache(self):
        # Senza questo la cache GHA riusa il layer di apt-get upgrade
        # e il rebuild non riceve le patch Debian
        self.assertIn("no-cache: ${{ github.event_name == 'schedule' }}", DOCKER_WORKFLOW)

    def test_workflow_does_not_create_tags_or_releases(self):
        # git tag è ammesso solo in lettura (--list)
        self.assertNotRegex(DOCKER_WORKFLOW, r"git tag (?!--list)")
        for forbidden in ("git push", "gh release", "action-gh-release",
                          "create-release"):
            self.assertNotIn(forbidden, DOCKER_WORKFLOW)
        self.assertRegex(DOCKER_WORKFLOW, r"permissions:\s*\n\s*contents:\s*read")


class TestSecurityPolicy(unittest.TestCase):

    def test_security_md_references_current_base_image(self):
        self.assertIn("Debian Trixie", SECURITY)
        self.assertNotIn("Bookworm", SECURITY)

    def test_openssl_not_listed_as_open_cve(self):
        # OpenSSL non compare nella scansione Trivy dell'immagine su Trixie
        self.assertNotIn("OpenSSL", SECURITY)

    def test_last_reviewed_after_trixie_scan(self):
        match = re.search(r"Last reviewed: (\d{4}-\d{2}-\d{2})", SECURITY)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(date.fromisoformat(match.group(1)), date(2026, 9, 18))


if __name__ == "__main__":
    unittest.main()
