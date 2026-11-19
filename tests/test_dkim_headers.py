"""
DKIM selectors from a received message (`check DOMAIN --headers mail.eml`).

MailRadar looks for DKIM keys under a list of common selectors. Bulk senders
do not use them: Amazon SES signs with a random 32-letter selector, and a
newsletter delivered on 2026-11-18 was found "not signed" for that reason,
while its DKIM-Signature header named the selector in clear (s=). Given the
message, the selectors signed for the domain analysed are asked for first.

The message is tests/fixtures/mail/dkim_ses_newsletter.eml (_derived, it says
from what); the key it names is in dns/dkim_ses_selector.json (_derived).
"""
from pathlib import Path

from typer.testing import CliRunner

from mailradar.checker import DKIM_SELECTORS, analyze_domain, dkim_selectors_in
from mailradar.cli import app

EML = Path(__file__).parent / "fixtures" / "mail" / "dkim_ses_newsletter.eml"
SES_SELECTOR = "sy1ziwiwe1ghbrfucyeaz6ou950rk4o1"
ENV = {"COLUMNS": "300"}


def _example_com(dns_replay, http_replay):
    dns_replay("example_com", "example_com_dkim_more_selectors", "dkim_ses_selector")
    http_replay("example_com", "keyservers_example_com")


class TestSelectorsIn:
    def test_the_selector_signed_for_the_domain_is_found(self):
        assert dkim_selectors_in(EML.read_bytes(), "example.com") == [SES_SELECTOR]

    def test_the_domain_is_compared_as_dns_compares_it(self):
        assert dkim_selectors_in(EML.read_bytes(), "Example.COM.") == [SES_SELECTOR]

    def test_the_sending_service_signature_is_its_own(self):
        """d=amazonses.com says nothing about example.com's keys."""
        assert dkim_selectors_in(EML.read_bytes(), "amazonses.com") == ["6ytbqojtdm1e0w7ef08zzslbsagycb45"]
        assert dkim_selectors_in(EML.read_bytes(), "example.org") == []

    def test_an_s_that_is_no_dns_name_is_not_asked_for(self):
        """The third signature has s=../../etc: a message is read, not obeyed."""
        assert "../../etc" not in dkim_selectors_in(EML.read_bytes(), "example.com")

    def test_a_message_with_no_signature_names_none(self):
        assert dkim_selectors_in(b"From: a@example.com\nSubject: x\n\nbody\n", "example.com") == []

    def test_the_ses_selector_is_not_a_common_one(self):
        assert SES_SELECTOR not in DKIM_SELECTORS


class TestAnalysis:
    def test_without_the_message_the_key_is_not_found(self, dns_replay, http_replay):
        _example_com(dns_replay, http_replay)
        report = analyze_domain("example.com")
        assert not report.dkim.present

    def test_with_its_selector_the_key_is_found_and_measured(self, dns_replay, http_replay):
        _example_com(dns_replay, http_replay)
        report = analyze_domain("example.com", dkim_selectors=[SES_SELECTOR])
        assert (report.dkim.present, report.dkim.selector, report.dkim.key_bits) == (True, SES_SELECTOR, 1024)
        assert report.dkim.tried == len(DKIM_SELECTORS) + 1

    def test_a_common_selector_is_not_asked_twice(self, dns_replay, http_replay):
        _example_com(dns_replay, http_replay)
        report = analyze_domain("example.com", dkim_selectors=["default"])
        assert report.dkim.tried == len(DKIM_SELECTORS)


class TestCheckCommand:
    def test_headers_adds_the_selector_and_says_so(self, dns_replay, http_replay):
        _example_com(dns_replay, http_replay)
        result = CliRunner().invoke(app, ["check", "example.com", "--headers", str(EML)], env=ENV)
        assert "DKIM selectors from" in result.output and SES_SELECTOR in result.output
        assert "1024-bit" in result.output

    def test_a_message_not_signed_for_the_domain_says_so(self, dns_replay, http_replay, tmp_path):
        _example_com(dns_replay, http_replay)
        eml = tmp_path / "other.eml"
        eml.write_bytes(b"DKIM-Signature: v=1; d=example.org; s=sel; b=AAAA\nFrom: a@example.org\n\nbody\n")
        result = CliRunner().invoke(app, ["check", "example.com", "--headers", str(eml)], env=ENV)
        assert "No DKIM signature for example.com" in result.output

    def test_a_missing_file_is_a_message_not_a_traceback(self, dns_replay, tmp_path):
        dns_replay("example_com")
        result = CliRunner().invoke(app, ["check", "example.com", "--headers", str(tmp_path / "none.eml")], env=ENV)
        assert result.exit_code == 1
        assert "File not found" in result.output
