"""
What comes from outside reaches the terminal as it was published, and never as
terminal control.

`rich.markup.escape` neutralises `[tag]` and nothing else, and Rich strips only
BEL, BS, VT, FF and CR: an ESC in a DNS TXT record, a keyserver uid or an
MTA-STS policy went to the terminal as it was, so a domain's owner could clear
the screen of whoever audited it, or put a hyperlink in its output. And Rich
reads `:100:` as an emoji shortcode, so `ip6:2001:db8:100::/48` came out as
`2001:db8💯:/48`.

DNS and HTTP are replayed from fixtures that say what they derive from
(spf_terminal_escape, spf_ip6_shortcode, example_com_mta_sts_mode_escape).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mailradar.cli import app

ENV = {"COLUMNS": "300"}

# The SPF record of spf_terminal_escape.json, as the tool must show it
HOSTILE_SPF_SHOWN = r"v=spf1 \x1b[2J\x1b]8;;https://evil.example\x1b\click\x1b]8;;\x1b\ -all"


def _example_com(dns_replay, http_replay, *dns_fixtures, http_fixtures=()):
    dns_replay("example_com", "example_com_dkim_more_selectors", *dns_fixtures)
    http_replay("example_com", "keyservers_example_com", *http_fixtures)


def _no_terminal_control(output: str) -> None:
    assert "\x1b" not in output
    assert not any(0x80 <= ord(c) <= 0x9f or (ord(c) < 0x20 and c not in "\n") or ord(c) == 0x7f for c in output)


@pytest.mark.parametrize("args", [["check", "example.com"], ["check", "example.com", "--verbose"]])
def test_check_sends_no_escape_from_a_txt_record(dns_replay, http_replay, args):
    _example_com(dns_replay, http_replay, "spf_terminal_escape")
    result = CliRunner().invoke(app, args, env=ENV)
    assert isinstance(result.exception, SystemExit | None), result.exception
    _no_terminal_control(result.output)
    # Shown, not dropped: whoever reads the output must see what is published
    assert r"\x1b[2J" in result.output


def test_verbose_shows_the_record_with_its_controls_written_out(dns_replay, http_replay):
    _example_com(dns_replay, http_replay, "spf_terminal_escape")
    result = CliRunner().invoke(app, ["check", "example.com", "--verbose"], env=ENV)
    assert f"SPF:   {HOSTILE_SPF_SHOWN}" in result.output


def test_check_sends_no_escape_from_an_mta_sts_mode(dns_replay, http_replay):
    _example_com(dns_replay, http_replay, "example_com_mta_sts", http_fixtures=["example_com_mta_sts_mode_escape"])
    result = CliRunner().invoke(app, ["check", "example.com"], env=ENV)
    _no_terminal_control(result.output)
    assert r"\x1b[31mtesting" in result.output


def test_batch_sends_no_escape(dns_replay, http_replay, tmp_path):
    _example_com(dns_replay, http_replay, "spf_terminal_escape")
    domains = tmp_path / "domains.txt"
    domains.write_text("example.com\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["batch", str(domains)], env=ENV)
    _no_terminal_control(result.output)


def test_report_sends_no_escape(dns_replay, http_replay):
    _example_com(dns_replay, http_replay, "spf_terminal_escape")
    result = CliRunner().invoke(app, ["report", "example.com", "--lang", "en"], env=ENV)
    assert result.exit_code == 0, result.output
    _no_terminal_control(result.output)
    # The letter quotes the record too
    assert HOSTILE_SPF_SHOWN in result.output


def test_send_sends_no_escape(dns_replay, http_replay):
    _example_com(dns_replay, http_replay, "spf_terminal_escape")
    result = CliRunner().invoke(app, ["send", "example.com", "--lang", "en"], env=ENV)
    _no_terminal_control(result.output)


def test_discover_sends_no_escape():
    """crt.sh names and scraped addresses are third-party text as much as DNS is."""
    from mailradar.discover import DiscoveryResult
    hostile = "\x1b]8;;https://evil.example\x1b\\x\x1b]8;;\x1b\\.example.com"
    found = DiscoveryResult(domain="example.com", emails=["info@example.com"],
                            sources={"crt.sh subdomains": [hostile], "website": ["info@example.com"]})
    with patch("mailradar.discover.discover", return_value=found):
        result = CliRunner().invoke(app, ["discover", "example.com", "--no-gpg"], env=ENV)
    _no_terminal_control(result.output)
    assert r"\x1b]8;;https://evil.example" in result.output


# ─── Emoji shortcodes ────────────────────────────────────────────────────────

def test_an_ip6_range_is_shown_as_published(dns_replay, http_replay):
    """`:100:` is Rich's shortcode for 💯: the table and --verbose both showed 2001:db8💯:/48."""
    _example_com(dns_replay, http_replay, "spf_ip6_shortcode")
    result = CliRunner().invoke(app, ["check", "example.com", "--verbose"], env=ENV)
    assert "💯" not in result.output
    # Once in the table, once among the raw records
    assert result.output.count("v=spf1 ip6:2001:db8:100::/48 -all") == 2, result.output
