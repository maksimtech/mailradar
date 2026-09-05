"""Tests for report generation."""
import pytest
from unittest.mock import MagicMock
from mailradar.reporter import generate_report
from mailradar.checker import DomainReport, DMARCResult, SPFResult, DKIMResult
from mailradar.checker import BIMIResult, MTASTSResult, TLSRPTResult, GPGResult


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
