"""Tests for MailRadar discover module."""
import re
from unittest.mock import MagicMock, patch

import pytest

from mailradar.discover import (
    DiscoveryResult,
    _check_gpg_for_emails,
    _discover_common_contacts,
    _discover_subdomains_via_crtsh,
    _discover_via_dns,
    _discover_via_website,
    _discover_via_whois,
    _extract_emails_from_text,
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

    def test_soa_rname_in_mixed_case(self, dns_replay):
        """DNS names are case-insensitive: Hostmaster.Example.COM. is hostmaster@example.com."""
        dns_replay("example_com", "example_com_soa_mixed_case")
        assert "hostmaster@example.com" in _discover_via_dns("example.com")

    def test_a_txt_record_that_is_not_utf8_does_not_cost_the_others(self, dns_replay):
        dns_replay("example_com", "example_com_txt_not_utf8")
        assert "security@example.com" in _discover_via_dns("example.com")


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

    def test_does_not_accept_addresses_of_other_domains(self, http_replay, dns_replay):
        """'admin@example.com.evil.org' is not an address of example.com (as the text extractor already knows)."""
        # rdap.org redirects to rdap.verisign.com, whose addresses are asked before following (recorded)
        dns_replay("rdap_verisign_com")
        proxy = http_replay("rdap_example_com_foreign_contact")
        emails = _discover_via_whois("example.com")
        assert "admin@example.com.evil.org" not in emails
        # Followed, so the registry's answer was read and not merely missed
        assert "GET https://rdap.verisign.com/com/v1/domain/example.com" in proxy.requests


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
                   side_effect=lambda e: MagicMock(found=e in found, error="")):
            result, unverified = _check_gpg_for_emails(
                ["a@example.com", "b@example.com", "c@example.com"]
            )
        assert result == ["a@example.com", "c@example.com"]
        assert unverified == []

    def test_returns_email_if_found(self):
        mock_result = MagicMock()
        mock_result.found = True
        with patch("mailradar.gpg.lookup_gpg_by_email", return_value=mock_result):
            result, _ = _check_gpg_for_emails(["security@example.com"])
            assert isinstance(result, list)

    def test_returns_empty_if_not_found(self):
        mock_result = MagicMock()
        mock_result.found = False
        with patch("mailradar.gpg.lookup_gpg_by_email", return_value=mock_result):
            result, _ = _check_gpg_for_emails(["nobody@example.com"])
            assert isinstance(result, list)


class TestDiscover:

    def test_discover_returns_result(self):
        with (
            patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]),
            patch("mailradar.discover._discover_via_website", return_value=["info@example.com"]),
            patch("mailradar.discover._discover_via_dns", return_value=[]),
            patch("mailradar.discover._discover_via_whois", return_value=[]),
            patch("mailradar.discover._discover_common_contacts", return_value=[]),
            patch("mailradar.discover._check_gpg_for_emails", return_value=([], [])),
        ):
            result = discover("example.com", check_gpg=False)
            assert isinstance(result, DiscoveryResult)
            assert result.domain == "example.com"

    def test_discover_with_gpg_check(self):
        with (
            patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]),
            patch("mailradar.discover._discover_via_website", return_value=["security@example.com"]),
            patch("mailradar.discover._discover_via_dns", return_value=[]),
            patch("mailradar.discover._discover_via_whois", return_value=[]),
            patch("mailradar.discover._discover_common_contacts", return_value=[]),
            patch("mailradar.discover._check_gpg_for_emails", return_value=(["security@example.com"], [])),
        ):
            result = discover("example.com", check_gpg=True)
            assert isinstance(result, DiscoveryResult)

    def test_discover_empty_domain(self):
        with (
            patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]),
            patch("mailradar.discover._discover_via_website", return_value=[]),
            patch("mailradar.discover._discover_via_dns", return_value=[]),
            patch("mailradar.discover._discover_via_whois", return_value=[]),
            patch("mailradar.discover._discover_common_contacts", return_value=[]),
            patch("mailradar.discover._check_gpg_for_emails", return_value=([], [])),
        ):
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
                   return_value=(list(gpg_capable), [])) as mock_gpg:
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


# ─── Redirects are followed by hand ──────────────────────────────────────────

class TestRedirects:
    """httpx followed every redirect, to any host and scheme: a page, or anyone on the path, could send
    the tool to http://127.0.0.1 on the network it runs from."""

    def test_a_redirect_to_loopback_is_not_followed(self, http_replay):
        """rdap_example_com_redirect_loopback.json (derived): rdap.org's 302, Location http://127.0.0.1:8080/admin."""
        proxy = http_replay("rdap_example_com_redirect_loopback")
        assert _discover_via_whois("example.com") == []
        assert not any("127.0.0.1" in request for request in proxy.requests), proxy.requests

    def test_a_redirect_to_a_public_host_of_another_domain_is_followed(self, http_replay, dns_replay):
        """rdap.org sends example.com to rdap.verisign.com (recorded), whose addresses are global (recorded)."""
        dns_replay("rdap_verisign_com")
        proxy = http_replay("rdap_example_com")
        _discover_via_whois("example.com")
        assert "GET https://rdap.verisign.com/com/v1/domain/example.com" in proxy.requests

    @pytest.mark.parametrize("target", [
        "http://www.example.com/",           # not https
        "https://127.0.0.1/",                 # loopback
        "https://10.0.0.1/admin",             # private
        "https://[::1]/",                     # loopback, IPv6
        "https://169.254.169.254/latest",     # link-local: cloud metadata
        "file:///etc/passwd",
    ])
    def test_refused_targets(self, target):
        from mailradar.discover import _may_follow
        assert _may_follow(target, "https://example.com/contact") is False

    def test_the_same_registrable_domain_is_followed_without_asking_dns(self, dns_replay):
        from mailradar.discover import _may_follow
        server = dns_replay()
        assert _may_follow("https://www.example.com/contatti", "https://example.com/contatti") is True
        assert server.queries == []


# ─── Keyservers that did not answer ──────────────────────────────────────────

class TestUnansweredKeyservers:

    def test_an_address_no_keyserver_answered_for_is_not_verified(self, http_replay):
        """keys.openpgp.org answered 429 for security@github.com (recorded): not "no key"."""
        http_replay("keyservers_github_com")
        found, unverified = _check_gpg_for_emails(["security@github.com"])
        assert found == []
        assert unverified == ["security@github.com"]

    def test_discover_says_not_verified_instead_of_no_keys(self):
        from typer.testing import CliRunner

        from mailradar.cli import app
        result_ = DiscoveryResult(domain="github.com", emails=["security@github.com"],
                                  sources={"website": ["security@github.com"]},
                                  gpg_unverified=["security@github.com"])
        with patch("mailradar.discover.discover", return_value=result_):
            out = CliRunner().invoke(app, ["discover", "github.com"], env={"COLUMNS": "300"}).output
        assert "No GPG public keys found" not in out
        assert "not verified" in out.lower()


# ─── Addresses whole or not at all ───────────────────────────────────────────

class TestWholeAddresses:

    @pytest.mark.parametrize("text,address", [
        ("Write to o'brien@example.com today", "o'brien@example.com"),
        ("DPO: josé.dpo@example.com", "josé.dpo@example.com"),
        ('<a href="mailto:%20dpo@example.com">', "dpo@example.com"),
        ('<a href="mailto:Privacy%40example.com">', "privacy@example.com"),
        ("first.last+tag@example.com", "first.last+tag@example.com"),
        ("data-x='info@example.com'", "info@example.com"),
    ])
    def test_the_local_part_is_read_whole(self, text, address):
        """`o'brien@` came out as `brien@`, `josé.dpo@` as `.dpo@`, `mailto:%20dpo@` as `%20dpo@`."""
        assert _extract_emails_from_text(text, "example.com") == [address]

    @pytest.mark.parametrize("text", [".dpo@example.com", "a..b@example.com", "x.@example.com"])
    def test_a_local_part_that_is_no_dot_atom_is_not_reported_in_part(self, text):
        assert _extract_emails_from_text(text, "example.com") == []


class TestSOAEscapedDot:

    def test_an_escaped_dot_belongs_to_the_local_part(self, dns_replay):
        """RFC 1035 §8: john\\.doe.example.com. is john.doe@example.com; the rname was dropped."""
        dns_replay("example_com", "example_com_soa_escaped_dot")
        assert "john.doe@example.com" in _discover_via_dns("example.com")


class TestGuessedListIsWhatIsCounted:
    """mailradar#144: on 2026-11-20 `discover` printed "15 common role address(es)
    guessed" and then listed 16. The count is `candidates` (the guesses no source
    confirmed), but the list shown was the whole "common contacts" source, which
    still held privacy@, already found on the website."""

    def _discover(self):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]), \
             patch("mailradar.discover._discover_via_website", return_value=["privacy@example.com"]), \
             patch("mailradar.discover._discover_via_dns", return_value=[]), \
             patch("mailradar.discover._discover_via_whois", return_value=[]), \
             patch("mailradar.discover._discover_common_contacts",
                   return_value=["privacy@example.com", "security@example.com", "info@example.com"]):
            return discover("example.com", check_gpg=False)

    def test_the_guessed_source_is_the_candidates(self):
        result = self._discover()
        assert result.sources["common contacts"] == result.candidates == [
            "info@example.com", "security@example.com",
        ]
        assert result.sources["website"] == ["privacy@example.com"]

    def test_nothing_guessed_means_no_guessed_source(self):
        with patch("mailradar.discover._discover_subdomains_via_crtsh", return_value=[]), \
             patch("mailradar.discover._discover_via_website", return_value=["info@example.com"]), \
             patch("mailradar.discover._discover_via_dns", return_value=[]), \
             patch("mailradar.discover._discover_via_whois", return_value=[]), \
             patch("mailradar.discover._discover_common_contacts", return_value=["info@example.com"]):
            result = discover("example.com", check_gpg=False)
        assert result.candidates == []
        assert "common contacts" not in result.sources

    def test_the_printed_count_is_the_number_of_addresses_listed_as_guessed(self):
        from typer.testing import CliRunner

        from mailradar.cli import app

        result = self._discover()
        with patch("mailradar.discover.discover", return_value=result):
            out = CliRunner().invoke(app, ["discover", "example.com", "--no-gpg"]).output
        guessed = out.split("Source: common contacts", 1)[1].split("Source:", 1)[0]
        listed = re.findall(r"\S+@example\.com", guessed)
        assert re.search(r"(\d+) common role address\(es\) guessed", out)[1] == str(len(listed)) == "2"
        assert "privacy@example.com" not in guessed
        assert out.count("privacy@example.com") == 1
