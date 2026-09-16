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

    @pytest.mark.parametrize("text", [
        "info@example.community",
        "info@example.com.evil.org",
        "info@example.com-phish.net",
        "info@example.comx",
    ])
    def test_extract_rejects_lookalike_domains(self, text):
        assert _extract_emails_from_text(text, "example.com") == []

    @pytest.mark.parametrize("text", [
        "Write to info@example.com.",
        "<a href=\"mailto:info@example.com\">",
        "(info@example.com)",
        "info@example.com, security@other.org",
        "info@example.com\n",
    ])
    def test_extract_accepts_email_followed_by_punctuation(self, text):
        assert _extract_emails_from_text(text, "example.com") == ["info@example.com"]

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


def _mx(*exchanges):
    return [MagicMock(exchange=e) for e in exchanges]


class TestDiscoverCommonContacts:

    def test_returns_role_addresses_when_domain_has_mx(self):
        with patch("dns.resolver.resolve", return_value=_mx("mail.example.com.")):
            result = _discover_common_contacts("example.com")
        assert "security@example.com" in result
        assert "postmaster@example.com" in result
        assert all(e.endswith("@example.com") for e in result)

    def test_returns_empty_without_mx(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer):
            assert _discover_common_contacts("example.com") == []

    def test_returns_empty_on_null_mx(self):
        """RFC 7505: '0 .' means the domain accepts no email."""
        with patch("dns.resolver.resolve", return_value=_mx(".")):
            assert _discover_common_contacts("example.com") == []


class TestCheckGpgForEmails:

    def test_returns_only_found_preserving_order(self):
        found = {"a@example.com", "c@example.com"}
        with patch("mailradar.gpg.lookup_gpg_by_email",
                   side_effect=lambda e: MagicMock(found=e in found)):
            result = _check_gpg_for_emails(
                ["a@example.com", "b@example.com", "c@example.com"]
            )
        assert result == ["a@example.com", "c@example.com"]

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


class TestDiscoverCandidatesSeparation:

    def _run(self, website, common, gpg_capable=()):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]), \
             patch("mailradar.discover._discover_via_website", return_value=website), \
             patch("mailradar.discover._discover_via_dns", return_value=[]), \
             patch("mailradar.discover._discover_via_whois", return_value=[]), \
             patch("mailradar.discover._discover_common_contacts", return_value=common), \
             patch("mailradar.discover._check_gpg_for_emails",
                   return_value=list(gpg_capable)) as mock_gpg:
            return discover("example.com", check_gpg=True), mock_gpg

    def test_guessed_contacts_are_not_reported_as_found_emails(self):
        result, _ = self._run(website=[], common=["security@example.com", "info@example.com"])
        assert result.emails == []
        assert result.candidates == ["info@example.com", "security@example.com"]

    def test_candidate_also_found_in_source_is_not_duplicated(self):
        result, _ = self._run(
            website=["info@example.com"],
            common=["security@example.com", "info@example.com"],
        )
        assert result.emails == ["info@example.com"]
        assert result.candidates == ["security@example.com"]

    def test_gpg_check_covers_emails_and_candidates(self):
        _, mock_gpg = self._run(
            website=["jane@example.com"], common=["security@example.com"],
        )
        mock_gpg.assert_called_once_with(["jane@example.com", "security@example.com"])
