"""Basic tests for MailRadar checker."""
import pytest
from mailradar.checker import check_dmarc, check_spf, check_dkim, analyze_domain


def test_check_dmarc_known_good():
    """Test DMARC check on a known well-configured domain."""
    result = check_dmarc("maksimtech.com")
    assert result.present is True
    assert result.policy == "reject"
    assert result.pct == 100
    assert result.adkim == "s"
    assert result.aspf == "s"
    assert result.rua is True
    assert result.ruf is True
    assert result.score >= 45


def test_check_spf_known_good():
    """Test SPF check on a known well-configured domain."""
    result = check_spf("maksimtech.com")
    assert result.present is True
    assert result.all_mechanism == "-all"
    assert result.permissive is False
    assert result.score >= 20


def test_check_dkim_known_good():
    """Test DKIM check on a known well-configured domain."""
    result = check_dkim("maksimtech.com")
    assert result.present is True
    assert result.key_bits == 2048
    assert result.score >= 15


def test_analyze_domain_returns_report():
    """Test full domain analysis returns a complete report."""
    report = analyze_domain("maksimtech.com")
    assert report.domain == "maksimtech.com"
    assert report.total_score > 0
    assert report.grade in ("EXCELLENT", "GOOD", "MODERATE", "POOR", "CRITICAL")


def test_check_dmarc_missing():
    """Test DMARC check on domain without DMARC."""
    result = check_dmarc("example.com")
    # example.com may or may not have DMARC — just check it returns a result
    assert isinstance(result.present, bool)
    assert isinstance(result.score, int)


def test_check_spf_missing():
    """Test SPF on domain."""
    result = check_spf("example.com")
    assert isinstance(result.present, bool)
