"""Tests for MailRadar CLI."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mailradar.checker import (
    BIMIResult,
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    SPFResult,
    TLSRPTResult,
)
from mailradar.cli import app


def _make_domain_report(domain="example.com", score=75, grade="GOOD"):
    """Create a realistic DomainReport."""
    return DomainReport(
        domain=domain,
        dmarc=DMARCResult(
            present=True,
            policy="reject",
            pct=100,
            adkim="r",
            aspf="r",
            rua=["mailto:rua@example.com"],
            ruf=[],
            raw="v=DMARC1; p=reject",
            score=40,
            issues=[],
        ),
        spf=SPFResult(
            present=True,
            all_mechanism="~all",
            permissive=False,
            raw="v=spf1 ~all",
            score=20,
            issues=[],
        ),
        dkim=DKIMResult(
            present=True,
            selector="default",
            key_bits=2048,
            raw="v=DKIM1; k=rsa; p=...",
            score=10,
            issues=[],
        ),
        bimi=BIMIResult(
            present=False,
            svg_url=None,
            vmc_url=None,
            svg_valid=False,
            vmc_present=False,
            raw=None,
            score=0,
            issues=[],
        ),
        mta_sts=MTASTSResult(
            present=False,
            mode=None,
            score=0,
            issues=[],
        ),
        tls_rpt=TLSRPTResult(
            present=False,
            rua=[],
            score=0,
            issues=[],
        ),
        gpg=GPGResult(
            found=False,
            keyserver=None,
            uid=None,
            key_id=None,
            emails=[],
            score=0,
            issues=[],
        ),
        total_score=score,
        grade=grade,
    )


class TestCLIHelp(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("email security", result.output.lower())

    def test_check_help(self):
        result = self.runner.invoke(app, ["check", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_help(self):
        result = self.runner.invoke(app, ["batch", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_report_help(self):
        result = self.runner.invoke(app, ["report", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_send_help(self):
        result = self.runner.invoke(app, ["send", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_discover_help(self):
        result = self.runner.invoke(app, ["discover", "--help"])
        self.assertEqual(result.exit_code, 0)


class TestCheckCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_good(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("example.com", 75, "GOOD")
        result = self.runner.invoke(app, ["check", "example.com"])
        self.assertEqual(result.exit_code, 0)

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_critical(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("bad.com", 10, "CRITICAL")
        result = self.runner.invoke(app, ["check", "bad.com"])
        self.assertEqual(result.exit_code, 2)

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_poor(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("bad.com", 30, "POOR")
        result = self.runner.invoke(app, ["check", "bad.com"])
        self.assertEqual(result.exit_code, 1)

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_moderate(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("mid.com", 55, "MODERATE")
        result = self.runner.invoke(app, ["check", "mid.com"])
        self.assertEqual(result.exit_code, 1)

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_verbose(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("example.com", 75, "GOOD")
        result = self.runner.invoke(app, ["check", "example.com", "--verbose"])
        self.assertEqual(result.exit_code, 0)

    @patch("mailradar.cli.analyze_domain")
    def test_check_domain_score_90(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("example.com", 90, "GOOD")
        result = self.runner.invoke(app, ["check", "example.com"])
        self.assertEqual(result.exit_code, 0)


class TestBatchCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_batch_missing_file(self):
        result = self.runner.invoke(app, ["batch", "nonexistent.txt"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("mailradar.cli.analyze_domain")
    def test_batch_with_file(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            f.write("test.com\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIn(result.exit_code, [0, 1, 2])
        finally:
            os.unlink(tmp)

    @patch("mailradar.cli.analyze_domain")
    def test_batch_with_comments(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# comment\n")
            f.write("example.com\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIn(result.exit_code, [0, 1, 2])
        finally:
            os.unlink(tmp)

    @patch("mailradar.cli.analyze_domain")
    def test_batch_empty_file(self, mock_analyze):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# only comments\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIn(result.exit_code, [0, 1, 2])
        finally:
            os.unlink(tmp)

    @patch("mailradar.cli.analyze_domain")
    def test_batch_good_domain(self, mock_analyze):
        mock_analyze.return_value = _make_domain_report("example.com", 90, "GOOD")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIn(result.exit_code, [0, 1, 2])
        finally:
            os.unlink(tmp)

    def test_batch_missing_file_with_square_brackets_in_name(self):
        """The file name is escaped for Rich: '[/x]' in the path must not crash with a MarkupError."""
        result = self.runner.invoke(app, ["batch", "[/x]missing-file.txt"])
        self.assertEqual(result.exit_code, 1)
        self.assertIsInstance(result.exception, SystemExit, repr(result.exception))


class TestReportCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_report_domain_good(self, mock_cli, mock_checker):
        report = _make_domain_report("example.com", 75, "GOOD")
        mock_cli.return_value = report
        mock_checker.return_value = report
        result = self.runner.invoke(app, ["report", "example.com"])
        self.assertIn(result.exit_code, [0, 1, 2])

    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_report_domain_critical(self, mock_cli, mock_checker):
        report = _make_domain_report("bad.com", 10, "CRITICAL")
        mock_cli.return_value = report
        mock_checker.return_value = report
        result = self.runner.invoke(app, ["report", "bad.com"])
        self.assertIn(result.exit_code, [0, 1, 2])


if __name__ == "__main__":
    unittest.main()


class TestSendCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_send_help(self):
        result = self.runner.invoke(app, ["send", "--help"])
        self.assertEqual(result.exit_code, 0)

    @patch("mailradar.sender.send_report")
    @patch("mailradar.reporter.generate_report")
    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_send_no_smtp(self, mock_cli, mock_checker, mock_generate, mock_send):
        report = _make_domain_report("example.com", 75, "GOOD")
        mock_cli.return_value = report
        mock_checker.return_value = report
        mock_generate.return_value = "Test report text"
        send_result = MagicMock()
        send_result.method = "manual"
        send_result.recipient = "security@example.com"
        send_result.message = "No SMTP"
        mock_send.return_value = send_result
        result = self.runner.invoke(app, ["send", "example.com"])
        self.assertIn(result.exit_code, [0, 1, 2])

    @patch("mailradar.sender.send_report")
    @patch("mailradar.reporter.generate_report")
    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_send_gpg_encrypted(self, mock_cli, mock_checker, mock_generate, mock_send):
        report = _make_domain_report("example.com", 75, "GOOD")
        mock_cli.return_value = report
        mock_checker.return_value = report
        mock_generate.return_value = "Test report text"
        send_result = MagicMock()
        send_result.method = "gpg-encrypted"
        send_result.recipient = "security@example.com"
        send_result.message = "Sent successfully"
        mock_send.return_value = send_result
        result = self.runner.invoke(app, ["send", "example.com"])
        self.assertIn(result.exit_code, [0, 1, 2])


class TestDiscoverCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_discover_help(self):
        result = self.runner.invoke(app, ["discover", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_discover_invalid_domain(self):
        result = self.runner.invoke(app, ["discover", "invaliddomain"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("mailradar.discover.discover")
    @patch("mailradar.checker.domain_exists", return_value=True)
    def test_discover_no_emails(self, mock_exists, mock_discover):
        from mailradar.discover import DiscoveryResult
        mock_discover.return_value = DiscoveryResult(
            domain="example.com",
            emails=[],
            sources={},
        )
        result = self.runner.invoke(app, ["discover", "example.com"])
        self.assertIn(result.exit_code, [0, 1])

    @patch("mailradar.discover.discover")
    @patch("mailradar.checker.domain_exists", return_value=True)
    def test_discover_with_emails(self, mock_exists, mock_discover):
        from mailradar.discover import DiscoveryResult
        mock_discover.return_value = DiscoveryResult(
            domain="example.com",
            emails=["security@example.com", "info@example.com"],
            sources={"website": ["security@example.com", "info@example.com"]},
            gpg_capable=["security@example.com"],
        )
        result = self.runner.invoke(app, ["discover", "example.com"])
        self.assertIn(result.exit_code, [0, 1, 2])


class TestCheckCommandWithIssues(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.cli.analyze_domain")
    def test_check_with_issues(self, mock_analyze):
        """Test report with issues list populated."""
        from mailradar.checker import (
            BIMIResult,
            DKIMResult,
            DMARCResult,
            DomainReport,
            GPGResult,
            MTASTSResult,
            SPFResult,
            TLSRPTResult,
        )
        report = DomainReport(
            domain="example.com",
            dmarc=DMARCResult(
                present=False,
                policy=None,
                pct=100,
                adkim="r",
                aspf="r",
                rua=[],
                ruf=[],
                raw=None,
                score=0,
                issues=["DMARC not configured"],
            ),
            spf=SPFResult(
                present=False,
                all_mechanism=None,
                permissive=True,
                raw=None,
                score=0,
                issues=["SPF not configured"],
            ),
            dkim=DKIMResult(
                present=False,
                selector=None,
                key_bits=None,
                raw=None,
                score=0,
                issues=["DKIM not found"],
            ),
            bimi=BIMIResult(
                present=True,
                svg_url="https://example.com/logo.svg",
                vmc_url=None,
                svg_valid=True,
                vmc_present=False,
                raw="v=BIMI1; l=https://example.com/logo.svg",
                score=5,
                issues=[],
            ),
            mta_sts=MTASTSResult(present=False, mode=None, score=0, issues=[]),
            tls_rpt=TLSRPTResult(present=False, rua=[], score=0, issues=[]),
            gpg=GPGResult(
                found=True,
                keyserver="keys.openpgp.org",
                uid="Test User",
                key_id="ABCD1234",
                emails=["security@example.com"],
                score=5,
                issues=[],
            ),
            total_score=10,
            grade="CRITICAL",
        )
        mock_analyze.return_value = report
        result = self.runner.invoke(app, ["check", "example.com"])
        self.assertEqual(result.exit_code, 2)


class TestRichMarkupSafety(unittest.TestCase):
    """Untrusted DNS data and report text must never be parsed as Rich markup."""

    def setUp(self):
        self.runner = CliRunner()

    def _hostile_report(self):
        report = _make_domain_report("example.com", 75, "GOOD")
        report.spf.raw = "v=spf1 [/bold] -all"
        report.dmarc.raw = "v=DMARC1; p=reject; [/red]"
        report.dmarc.issues = ["pct=[/x] — not applied to 100% of emails"]
        return report

    @patch("mailradar.cli.analyze_domain")
    def test_check_does_not_crash_on_markup_in_dns_records(self, mock_analyze):
        mock_analyze.return_value = self._hostile_report()
        result = self.runner.invoke(app, ["check", "example.com", "--verbose"])
        self.assertIsNone(result.exception, result.output)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("v=spf1 [/bold] -all", result.output)
        self.assertIn("v=DMARC1; p=reject; [/red]", result.output)
        self.assertIn("pct=[/x]", result.output)

    @patch("mailradar.cli.analyze_domain")
    def test_batch_does_not_crash_on_markup_in_dns_records(self, mock_analyze):
        mock_analyze.return_value = self._hostile_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIsNone(result.exception, result.output)
        finally:
            os.unlink(tmp)

    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_report_text_is_printed_verbatim(self, mock_cli, mock_checker):
        report = _make_domain_report("example.com", 30, "POOR")
        report.spf.issues = ["SPF uses ~all (softfail) — consider -all (hardfail)"]
        mock_cli.return_value = mock_checker.return_value = report
        result = self.runner.invoke(app, ["report", "example.com", "--lang", "en"])
        self.assertIsNone(result.exception, result.output)
        # Previously Rich swallowed "[provider]" as a style tag
        self.assertIn("include:[provider] -all", result.output)
        self.assertIn("[NOME]", result.output)

    @patch("mailradar.sender.send_report")
    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_send_manual_report_is_printed_verbatim(self, mock_cli, mock_checker, mock_send):
        report = _make_domain_report("example.com", 30, "POOR")
        report.spf.issues = ["SPF uses ~all (softfail) — consider -all (hardfail)"]
        mock_cli.return_value = mock_checker.return_value = report
        mock_send.return_value = MagicMock(
            method="manual", recipient="security@example.com", message=""
        )
        result = self.runner.invoke(app, ["send", "example.com", "--lang", "en"])
        self.assertIsNone(result.exception, result.output)
        self.assertIn("include:[provider] -all", result.output)


class TestBatchResilience(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.cli.analyze_domain")
    def test_batch_continues_after_failing_domain(self, mock_analyze):
        mock_analyze.side_effect = [
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            _make_domain_report("good.com", 90, "EXCELLENT"),
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("broken.com\ngood.com\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
            self.assertIsNone(result.exception, result.output)
            self.assertEqual(mock_analyze.call_count, 2)
            self.assertIn("good.com", result.output)
            self.assertIn("Failed (1): broken.com", result.output)
        finally:
            os.unlink(tmp)


class TestSendGpgFailed(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.sender.send_report")
    @patch("mailradar.checker.analyze_domain")
    @patch("mailradar.cli.analyze_domain")
    def test_send_gpg_failed_exits_nonzero(self, mock_cli, mock_checker, mock_send):
        report = _make_domain_report("example.com", 75, "GOOD")
        mock_cli.return_value = mock_checker.return_value = report
        mock_send.return_value = MagicMock(
            method="gpg-failed",
            recipient="security@example.com",
            message="GPG key found for security@example.com but encryption failed — report NOT sent",
        )
        result = self.runner.invoke(app, ["send", "example.com"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("encryption failed", result.output)
        self.assertIn("Plaintext was not sent", result.output)


class TestDiscoverCandidatesOutput(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    @patch("mailradar.discover.discover")
    def test_only_candidates_are_not_presented_as_found(self, mock_discover):
        from mailradar.discover import DiscoveryResult
        mock_discover.return_value = DiscoveryResult(
            domain="example.com",
            emails=[],
            candidates=["security@example.com"],
            sources={"common contacts": ["security@example.com"]},
            gpg_capable=["security@example.com"],
        )
        result = self.runner.invoke(app, ["discover", "example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No email addresses found in public sources", result.output)
        self.assertIn("not verified", result.output)
        self.assertIn("security@example.com", result.output)
        self.assertNotIn("Found 1 email", result.output)


def _table_lines(report: DomainReport) -> list[str]:
    """What the results table prints for `report`, line by line."""
    from mailradar import cli
    with cli.console.capture() as capture:
        cli._print_report(report)
    return capture.get().splitlines()


def _dkim_report(domain: str, selectors=None) -> DomainReport:
    """A report whose DKIM result is check_dkim's on `domain`, from the DNS the test replays."""
    from mailradar.checker import check_dkim
    report = DomainReport(domain=domain)
    report.dkim = check_dkim(domain, selectors=selectors)
    return report


def _unverified_dmarc_report() -> DomainReport:
    """A report whose DMARC lookup timed out."""
    report = DomainReport(domain="example.com", total_score=40, grade="POOR")
    report.dmarc = DMARCResult(error="DNS lookup for _dmarc.example.com failed: Timeout",
                               issues=["DMARC not verified — DNS lookup for _dmarc.example.com failed: Timeout"])
    return report


def _timed_out(check: str, result_type, name: str):
    """The result `check` returns when the TXT lookup of `name` times out.

    Derived, not captured: the strings are the ones checker._unless_dns_fails
    builds from the DNSLookupError that _query_txt raises on a Timeout.
    """
    error = f"DNS lookup for {name} failed: Timeout"
    return result_type(error=error, issues=[f"{check} not verified — {error}"])


class TestReportTableRows(unittest.TestCase):
    """The table must not claim more than the checks found."""

    @pytest.fixture(autouse=True)
    def _dns(self, dns_replay):
        self.dns_replay = dns_replay

    def test_spf_permerror_is_not_shown_as_ok(self):
        """A record in permerror protects nothing: the table must not show ✅."""
        report = DomainReport(domain="example.com")
        report.spf = SPFResult(present=True, permerror=True, raw="v=spf1 -all", issues=["permerror"])
        row = next(line for line in _table_lines(report) if "SPF" in line and "v=spf1" in line)
        self.assertNotIn("✅", row)

    def test_unverified_dmarc_is_not_shown_as_not_configured(self):
        row = next(line for line in _table_lines(_unverified_dmarc_report()) if "DMARC" in line and "│" in line)
        self.assertNotIn("Not configured", row)
        self.assertIn("not verified", row.lower())

    def test_unverified_dkim_is_not_shown_as_not_found(self):
        report = DomainReport(domain="example.com")
        report.dkim = _timed_out("DKIM", DKIMResult, "default._domainkey.example.com")
        row = next(line for line in _table_lines(report) if line.startswith("│ DKIM"))
        self.assertNotIn("Not found", row)
        self.assertNotIn("✅", row)
        self.assertIn("not verified", row.lower())

    def test_unverified_bimi_is_not_shown_as_not_configured(self):
        report = DomainReport(domain="example.com")
        report.bimi = _timed_out("BIMI", BIMIResult, "default._bimi.example.com")
        row = next(line for line in _table_lines(report) if line.startswith("│ BIMI"))
        self.assertNotIn("Not configured", row)
        self.assertNotIn("✅", row)
        self.assertIn("not verified", row.lower())

    def test_ed25519_dkim_key_is_not_described_as_rsa(self):
        from mailradar.reporter import generate_report
        # archlinux.org signs with an Ed25519 key, under dkim-ed25519 (recorded)
        self.dns_replay("archlinux_org")
        report = _dkim_report("archlinux.org", selectors=["dkim-ed25519"])
        row = next(line for line in _table_lines(report) if "DKIM" in line and "selector" in line)
        self.assertIn("Ed25519", row)
        self.assertNotIn("RSA", row)
        for lang in ("en", "it"):
            self.assertNotIn("256-bit RSA", generate_report(report, lang=lang))

    def test_dkim_revoked_on_every_selector_is_said_briefly_and_honestly(self):
        """example.com publishes an empty p= under every selector: no list of 17 names, and not 'Not found'."""
        self.dns_replay("example_com")
        report = _dkim_report("example.com")
        issue = next(i for i in report.dkim.issues if "revoked" in i)
        self.assertNotIn("mailchimp", issue)
        self.assertIn("more", issue)
        row = next(line for line in _table_lines(report) if line.startswith("│ DKIM"))
        self.assertNotIn("Not found", row)
        self.assertIn("revoked", row)


class TestIncompleteAnalysis(unittest.TestCase):
    """A report goes to the domain's owner: it must not state what could not be verified."""

    @pytest.fixture(autouse=True)
    def _network(self, dns_replay, http_replay, smtp_server, trusted_ca):
        # example.com as recorded, DNS and keyservers, except that
        # _dmarc.example.com never answers: the DMARC lookup times out
        dns_replay("example_com", silent=["_dmarc.example.com TXT"])
        http_replay("example_com")
        self.smtp = smtp_server("tls", trusted_ca.server_context("127.0.0.1"))

    def setUp(self):
        self.runner = CliRunner()

    def test_report_is_not_generated_from_an_incomplete_analysis(self):
        result = self.runner.invoke(app, ["report", "example.com"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Report not generated", result.output)
        self.assertNotIn("Generating email report", result.output)

    def test_send_does_not_send_a_report_from_an_incomplete_analysis(self):
        result = self.runner.invoke(app, [
            "send", "example.com", "--smtp-host", "127.0.0.1", "--smtp-port", str(self.smtp.port),
            "--smtp-user", "security@example.org", "--smtp-pass", "secret", "--from", "security@example.org",
        ])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Report not generated", result.output)
        self.assertEqual(self.smtp.connections, 0, "the SMTP server was contacted")


class TestModuleEntryPoint(unittest.TestCase):

    def test_python_m_mailradar_cli_registers_every_command(self):
        """`python -m mailradar.cli` used to call main() before report, send and discover were defined."""
        import subprocess
        import sys
        from pathlib import Path
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "COLUMNS": "200", "NO_COLOR": "1"}
        proc = subprocess.run([sys.executable, "-m", "mailradar.cli", "--help"],
                              cwd=Path(__file__).resolve().parent.parent,
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              env=env, timeout=60)
        for command in ("check", "batch", "report", "send", "discover"):
            self.assertIn(command, proc.stdout, f"command {command!r} missing from python -m mailradar.cli")

    def test_main_block_in_process_registers_every_command(self):
        """The same check in-process, so coverage sees the `__main__` block run: the subprocess is invisible to it."""
        import contextlib
        import io
        import runpy
        import sys
        import warnings
        saved_argv = sys.argv
        out = io.StringIO()
        sys.argv = ["mailradar", "--help"]
        try:
            with warnings.catch_warnings(), contextlib.redirect_stdout(out):
                # This file already imported the module; runpy warns about it,
                # and running it afresh as __main__ is exactly the point.
                warnings.filterwarnings("ignore", message=".*found in sys.modules", category=RuntimeWarning)
                with self.assertRaises(SystemExit) as cm:
                    runpy.run_module("mailradar.cli", run_name="__main__")
        finally:
            sys.argv = saved_argv
        self.assertIn(cm.exception.code, (0, None))
        for command in ("check", "batch", "report", "send", "discover"):
            self.assertIn(command, out.getvalue(), f"command {command!r} missing from the __main__ block's app")
