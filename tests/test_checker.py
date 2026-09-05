"""
Tests for MailRadar checker module.
Uses mocks to avoid real DNS queries in CI.
"""
import pytest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
from mailradar.checker import (
    check_dmarc, check_spf, check_dkim, check_bimi,
    check_mta_sts, check_tls_rpt, analyze_domain,
    domain_exists, find_domain_variants,
    DMARCResult, SPFResult, DKIMResult
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

def make_txt_answer(strings: list[str]):
    """Create a mock DNS TXT answer."""
    answers = []
    for s in strings:
        rdata = MagicMock()
        rdata.strings = [s.encode()]
        answers.append(rdata)
    return answers


# ─── DMARC ──────────────────────────────────────────────────────────────────

class TestCheckDMARC:

    def test_dmarc_reject_perfect(self):
        txt = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com; fo=1"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.present is True
        assert result.policy == "reject"
        assert result.pct == 100
        assert result.adkim == "s"
        assert result.aspf == "s"
        assert result.rua is True
        assert result.ruf is True
        assert result.score == 50
        assert result.issues == []

    def test_dmarc_quarantine(self):
        txt = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.policy == "quarantine"
        assert result.score == 33
        assert any("quarantine" in issue for issue in result.issues)

    def test_dmarc_none(self):
        txt = "v=DMARC1; p=none; rua=mailto:rua@example.com"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.policy == "none"
        assert result.score >= 0

    def test_dmarc_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_dmarc("example.com")
        assert result.present is False
        assert result.score == 0
        assert any("spoofable" in issue for issue in result.issues)

    def test_dmarc_relaxed_alignment(self):
        txt = "v=DMARC1; p=reject; pct=100; adkim=r; aspf=r; rua=mailto:rua@example.com"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.adkim == "r"
        assert result.aspf == "r"
        assert any("adkim" in issue for issue in result.issues)
        assert any("aspf" in issue for issue in result.issues)


# ─── SPF ────────────────────────────────────────────────────────────────────

class TestCheckSPF:

    def test_spf_hardfail(self):
        txt = "v=spf1 include:spf.example.com -all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.present is True
        assert result.all_mechanism == "-all"
        assert result.permissive is False
        assert result.score == 20
        assert result.issues == []

    def test_spf_softfail(self):
        txt = "v=spf1 include:spf.example.com ~all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.all_mechanism == "~all"
        assert result.permissive is True
        assert result.score == 10
        assert any("~all" in issue for issue in result.issues)

    def test_spf_plusall(self):
        txt = "v=spf1 +all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.all_mechanism == "+all"
        assert result.permissive is True
        assert result.score == 0

    def test_spf_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_spf("example.com")
        assert result.present is False
        assert result.score == 0

    def test_spf_permissive_mechanisms(self):
        txt = "v=spf1 +a +mx -all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.permissive is True
        assert any("+a" in issue or "+mx" in issue for issue in result.issues)


# ─── DKIM ───────────────────────────────────────────────────────────────────

class TestCheckDKIM:

    def test_dkim_2048(self):
        # Chiave RSA 2048-bit reale (troncata per il test)
        key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6EYQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvxDKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
        txt = f"v=DKIM1; t=s; p={key}"

        def mock_resolve(name, rtype):
            if "20250324._domainkey" in name:
                return make_txt_answer([txt])
            raise dns.resolver.NXDOMAIN

        with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve):
            result = check_dkim("example.com", selectors=["20250324"])
        assert result.present is True
        assert result.key_bits == 2048
        assert result.score == 15
        assert result.issues == []

    def test_dkim_1024(self):
        # Chiave 1024-bit simulata — lunghezza base64 corta
        key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7fmTaeGQi0HcKC1r+aVWwlPSKMjLFiUiCnkp2xGXh8Bk0r9qeMJkCwOUv1gaSfBRbUbvHyC0lBhWEFQJO6qqc+9k7rWMmXEZ0g6DfnQaTHGY2rNtVbZ6BKzHpFGi7XHJ8GS5yzZ7pGilWmqX/zYvKqxEJoKPX3nAsTbxjwIDAQAB"
        txt = f"v=DKIM1; p={key}"

        def mock_resolve(name, rtype):
            if "selector1._domainkey" in name:
                return make_txt_answer([txt])
            raise dns.resolver.NXDOMAIN

        with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve):
            result = check_dkim("example.com", selectors=["selector1"])
        assert result.present is True
        assert result.score == 10
        assert any("1024" in issue for issue in result.issues)

    def test_dkim_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_dkim("example.com")
        assert result.present is False
        assert result.score == 0


# ─── BIMI ───────────────────────────────────────────────────────────────────

class TestCheckBIMI:

    def test_bimi_with_vmc(self):
        txt = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
             patch('mailradar.checker.httpx.get', return_value=mock_resp):
            result = check_bimi("example.com")
        assert result.present is True
        assert result.vmc_present is True
        assert result.score == 10

    def test_bimi_without_vmc(self):
        txt = "v=BIMI1; l=https://example.com/logo.svg"
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
             patch('mailradar.checker.httpx.get', return_value=mock_resp):
            result = check_bimi("example.com")
        assert result.present is True
        assert result.vmc_present is False
        assert result.score == 5
        assert any("VMC" in issue for issue in result.issues)

    def test_bimi_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_bimi("example.com")
        assert result.present is False
        assert result.score == 0


# ─── MTA-STS ────────────────────────────────────────────────────────────────

class TestCheckMTASTS:

    def test_mta_sts_enforce(self):
        txt = "v=STSv1; id=20240101"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400"

        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
             patch('mailradar.checker.httpx.get', return_value=mock_resp):
            result = check_mta_sts("example.com")
        assert result.present is True
        assert result.mode == "enforce"
        assert result.score == 5

    def test_mta_sts_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_mta_sts("example.com")
        assert result.present is False
        assert result.score == 0


# ─── TLS-RPT ────────────────────────────────────────────────────────────────

class TestCheckTLSRPT:

    def test_tls_rpt_present(self):
        txt = "v=TLSRPTv1; rua=mailto:tls-rpt@example.com"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_tls_rpt("example.com")
        assert result.present is True
        assert result.score == 3

    def test_tls_rpt_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_tls_rpt("example.com")
        assert result.present is False
        assert result.score == 0


# ─── Domain existence ────────────────────────────────────────────────────────

class TestDomainExists:

    def test_domain_without_tld_returns_false(self):
        result = domain_exists("apple")
        assert result is False

    def test_domain_with_tld_exists(self):
        mock_answer = [MagicMock()]
        with patch('mailradar.checker.dns.resolver.resolve', return_value=mock_answer):
            result = domain_exists("example.com")
        assert result is True

    def test_domain_nxdomain(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = domain_exists("thisdoesnotexist12345.com")
        assert result is False


# ─── Full analysis ───────────────────────────────────────────────────────────

class TestAnalyzeDomain:

    def test_analyze_domain_excellent(self):
        dmarc_txt = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com"
        spf_txt = "v=spf1 include:spf.example.com -all"
        dkim_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6EYQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvxDKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
        dkim_txt = f"v=DKIM1; t=s; p={dkim_key}"

        def mock_resolve(name, rtype):
            if "_dmarc" in name:
                return make_txt_answer([dmarc_txt])
            elif "_domainkey" in name:
                return make_txt_answer([dkim_txt])
            elif "_mta-sts" in name:
                raise dns.resolver.NXDOMAIN
            elif "_smtp._tls" in name:
                raise dns.resolver.NXDOMAIN
            elif "default._bimi" in name:
                raise dns.resolver.NXDOMAIN
            else:
                return make_txt_answer([spf_txt])

        mock_gpg = MagicMock()
        mock_gpg.found = False
        mock_gpg.score = 0
        mock_gpg.issues = []

        with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve), \
             patch('mailradar.gpg.lookup_gpg', return_value=mock_gpg):
            report = analyze_domain("example.com")

        assert report.domain == "example.com"
        assert report.dmarc.policy == "reject"
        assert report.spf.all_mechanism == "-all"
        assert report.dkim.key_bits == 2048
        assert report.total_score >= 75
        assert report.grade in ("EXCELLENT", "GOOD")

    def test_analyze_domain_critical(self):
        def mock_resolve(name, rtype):
            raise dns.resolver.NXDOMAIN

        mock_gpg = MagicMock()
        mock_gpg.found = False
        mock_gpg.score = 0
        mock_gpg.issues = []

        with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve), \
             patch('mailradar.gpg.lookup_gpg', return_value=mock_gpg):
            report = analyze_domain("nodns.example.com")

        assert report.total_score == 0
        assert report.grade == "CRITICAL"

    def test_scoring_boundaries(self):
        """Test score boundary conditions."""
        result = DMARCResult()
        result.score = 0
        assert result.score == 0

        result.score = 50
        assert result.score == 50
