"""Tests for report generation."""
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
from mailradar.reporter import generate_report


def make_report(domain="example.com", score=85, grade="GOOD") -> DomainReport:
    report = DomainReport()
    report.domain = domain
    report.total_score = score
    report.grade = grade
    report.dmarc = DMARCResult(present=True, policy="reject", pct=100,
                                adkim="s", aspf="s", rua=True, ruf=True,
                                raw="v=DMARC1; p=reject", score=50, issues=[])
    report.spf = SPFResult(present=True, all_mechanism="-all",
                           permissive=False, raw="v=spf1 -all", score=20, issues=[])
    report.dkim = DKIMResult(present=True, selector="default",
                             key_bits=2048, score=15, issues=[])
    report.bimi = BIMIResult(present=False, score=0,
                             issues=["No BIMI record configured"])
    report.mta_sts = MTASTSResult(present=False, score=0,
                                   issues=["No MTA-STS configured"])
    report.tls_rpt = TLSRPTResult(present=False, score=0,
                                   issues=["No TLS-RPT configured"])
    report.gpg = GPGResult(found=False, score=0,
                           issues=["No GPG public key found"])
    return report


class TestGenerateReport:

    def test_generate_report_italian(self):
        report = make_report()
        text = generate_report(report, lang="it",
                               sender_name="Test User",
                               sender_role="Analyst",
                               sender_org="TestOrg")
        assert "example.com" in text
        assert "Test User" in text
        assert "DMARC" in text

    def test_generate_report_english(self):
        report = make_report()
        text = generate_report(report, lang="en",
                               sender_name="Test User",
                               sender_role="Analyst",
                               sender_org="TestOrg")
        assert "example.com" in text
        assert "Test User" in text
        assert "DMARC" in text

    def test_generate_report_with_issues(self):
        report = make_report(score=35, grade="POOR")
        report.dmarc = DMARCResult(present=False, score=0,
                                    issues=["No DMARC record found — domain is spoofable"])
        text = generate_report(report, lang="it")
        assert "example.com" in text

    def test_generate_report_fallback_to_english(self):
        """Unknown language falls back to English."""
        report = make_report()
        text = generate_report(report, lang="xx")
        assert "example.com" in text
        assert "DMARC" in text


def _section(text: str, start: str) -> str:
    """The paragraph of `text` that begins with `start`."""
    tail = text.split(start, 1)[1]
    return tail.split("\n\n", 1)[0]


def _mta_sts_in_testing() -> DomainReport:
    report = make_report()
    report.mta_sts = MTASTSResult(present=True, mode="testing", score=2,
                                  issues=["MTA-STS in testing mode — upgrade to enforce"])
    return report


class TestMTASTSSection:
    """The report sent to the owner must not say 'Not configured' for a policy in testing mode."""

    def test_english_report_does_not_say_not_configured(self):
        text = generate_report(_mta_sts_in_testing(), lang="en")
        assert "Not configured" not in _section(text, "MTA-STS —")

    def test_italian_report_does_not_say_not_configured(self):
        text = generate_report(_mta_sts_in_testing(), lang="it")
        assert "Non configurato" not in _section(text, "MTA-STS —")
