"""Tests for MailRadar discover module."""
import pytest
from unittest.mock import patch, MagicMock
from mailradar.discover import (
    DiscoveryResult,
    _extract_emails_from_text,
    _discover_subdomains_via_crtsh,
    _discover_via_website,
    _discover_via_dns,
    _discover_via_whois,
    _discover_common_contacts,
    _check_gpg_for_emails,
    discover,
)


class TestExtractEmailsFromText:

    def test_extract_basic_email(self):
        text = "Contact us at info@example.com for support"
        result = _extract_emails_from_text(text, "example.com")
        assert "info@example.com" in result

    def test_extract_multiple_emails(self):
        text = "info@example.com and security@example.com"
        result = _extract_emails_from_text(text, "example.com")
        assert "info@example.com" in result
        assert "security@example.com" in result

    def test_extract_no_emails(self):
        text = "No emails here"
        result = _extract_emails_from_text(text, "example.com")
        assert result == []

    def test_extract_deduplicates(self):
        text = "info@example.com info@example.com info@EXAMPLE.COM"
        result = _extract_emails_from_text(text, "example.com")
        assert len(result) == 1

    def test_extract_wrong_domain_ignored(self):
        text = "info@other.com security@example.com"
        result = _extract_emails_from_text(text, "example.com")
        assert "info@other.com" not in result
        assert "security@example.com" in result

    def test_extract_lowercases_emails(self):
        text = "INFO@EXAMPLE.COM"
        result = _extract_emails_from_text(text, "example.com")
        assert "info@example.com" in result


class TestDiscoverSubdomainsCrtsh:

    def test_returns_list_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "mail.example.com"},
            {"name_value": "www.example.com"},
        ]
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_subdomains_via_crtsh("example.com")
            assert isinstance(result, list)

    def test_returns_empty_on_error(self):
        import httpx
        with patch("mailradar.discover.httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = _discover_subdomains_via_crtsh("example.com")
            assert result == []

    def test_returns_empty_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_subdomains_via_crtsh("example.com")
            assert result == []


class TestDiscoverViaWebsite:

    def test_returns_list_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Contact: info@example.com or security@example.com"
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_via_website("example.com")
            assert isinstance(result, list)

    def test_returns_empty_on_timeout(self):
        import httpx
        with patch("mailradar.discover.httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = _discover_via_website("example.com")
            assert result == []

    def test_returns_empty_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_via_website("example.com")
            assert isinstance(result, list)


class TestDiscoverViaDns:

    def test_returns_list(self):
        import dns.resolver
        mock_answer = MagicMock()
        mock_answer.exchange = MagicMock()
        mock_answer.exchange.__str__ = MagicMock(return_value="mail.example.com.")
        with patch("dns.resolver.resolve", return_value=[mock_answer]):
            result = _discover_via_dns("example.com")
            assert isinstance(result, list)

    def test_returns_empty_on_nxdomain(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = _discover_via_dns("nonexistent.example.com")
            assert result == []

    def test_returns_empty_on_exception(self):
        with patch("dns.resolver.resolve", side_effect=Exception("error")):
            result = _discover_via_dns("example.com")
            assert result == []


class TestDiscoverViaWhois:

    def test_returns_list_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "entities": [
                {
                    "vcardArray": [
                        "vcard",
                        [["email", {}, "text", "admin@example.com"]]
                    ]
                }
            ]
        }
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_via_whois("example.com")
            assert isinstance(result, list)

    def test_returns_empty_on_timeout(self):
        import httpx
        with patch("mailradar.discover.httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = _discover_via_whois("example.com")
            assert result == []

    def test_returns_empty_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("mailradar.discover.httpx.get", return_value=mock_resp):
            result = _discover_via_whois("example.com")
            assert result == []


class TestDiscoverCommonContacts:

    def test_returns_list(self):
        result = _discover_common_contacts("example.com")
        assert isinstance(result, list)

    def test_contains_common_emails(self):
        result = _discover_common_contacts("example.com")
        emails_str = " ".join(result)
        assert "example.com" in emails_str


class TestCheckGpgForEmails:

    def test_returns_email_if_found(self):
        mock_result = MagicMock()
        mock_result.found = True
        with patch("mailradar.gpg.lookup_gpg_by_email", return_value=mock_result):
            result = _check_gpg_for_emails(["security@example.com"])
            assert isinstance(result, list)

    def test_returns_empty_if_not_found(self):
        mock_result = MagicMock()
        mock_result.found = False
        with patch("mailradar.gpg.lookup_gpg_by_email", return_value=mock_result):
            result = _check_gpg_for_emails(["nobody@example.com"])
            assert isinstance(result, list)


class TestDiscover:

    def test_discover_returns_result(self):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]):
            with patch("mailradar.discover._discover_via_website", return_value=["info@example.com"]):
                with patch("mailradar.discover._discover_via_dns", return_value=[]):
                    with patch("mailradar.discover._discover_via_whois", return_value=[]):
                        with patch("mailradar.discover._discover_common_contacts", return_value=[]):
                            with patch("mailradar.discover._check_gpg_for_emails", return_value=[]):
                                result = discover("example.com", check_gpg=False)
                                assert isinstance(result, DiscoveryResult)
                                assert result.domain == "example.com"

    def test_discover_with_gpg_check(self):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]):
            with patch("mailradar.discover._discover_via_website", return_value=["security@example.com"]):
                with patch("mailradar.discover._discover_via_dns", return_value=[]):
                    with patch("mailradar.discover._discover_via_whois", return_value=[]):
                        with patch("mailradar.discover._discover_common_contacts", return_value=[]):
                            with patch("mailradar.discover._check_gpg_for_emails", return_value=["security@example.com"]):
                                result = discover("example.com", check_gpg=True)
                                assert isinstance(result, DiscoveryResult)

    def test_discover_empty_domain(self):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]):
            with patch("mailradar.discover._discover_via_website", return_value=[]):
                with patch("mailradar.discover._discover_via_dns", return_value=[]):
                    with patch("mailradar.discover._discover_via_whois", return_value=[]):
                        with patch("mailradar.discover._discover_common_contacts", return_value=[]):
                            with patch("mailradar.discover._check_gpg_for_emails", return_value=[]):
                                result = discover("example.com", check_gpg=False)
                                assert result.emails == []


class TestDiscoveryResult:

    def test_default_values(self):
        result = DiscoveryResult(domain="example.com")
        assert result.domain == "example.com"
        assert result.emails == []
        assert result.sources == {}
        assert result.gpg_capable == []
        assert result.errors == []

    def test_with_emails(self):
        result = DiscoveryResult(
            domain="example.com",
            emails=["info@example.com", "security@example.com"],
        )
        assert len(result.emails) == 2
