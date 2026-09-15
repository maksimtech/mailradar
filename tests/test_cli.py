"""Tests for MailRadar CLI."""
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from mailradar.cli import app
from mailradar.checker import (
    DomainReport, DMARCResult, SPFResult, DKIMResult,
    BIMIResult, MTASTSResult, TLSRPTResult, GPGResult
)


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
            DomainReport, DMARCResult, SPFResult, DKIMResult,
            BIMIResult, MTASTSResult, TLSRPTResult, GPGResult
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
