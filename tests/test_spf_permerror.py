"""
MailRadar — SPF records that receivers cannot evaluate.

RFC 7208 §4.6: a syntax error anywhere in the record makes check_host() return
permerror at once, and §5.2 does the same for an `include:` whose target has no
SPF record. A permerror means receivers apply no SPF at all, so a record that
says `-all` and has one bad term protects nothing. MailRadar dropped such terms
and kept scoring the rest, and an `-al` typo even read as "no all mechanism".
"""
from __future__ import annotations

import pytest

from mailradar.checker import check_spf


class TestSyntaxErrors:

    @pytest.mark.parametrize("domain, term", [
        ("unknown-mechanism.example.com", "foo:bar"),
        ("not-a-name.example.com", "1x"),
        ("all-typo.example.com", "-al"),
        ("all-semicolon.example.com", "-all;"),
    ])
    def test_a_term_that_is_not_spf_is_a_permerror(self, dns_replay, domain, term):
        dns_replay("spf_syntax_errors")
        result = check_spf(domain)
        assert result.permerror is True
        assert result.score == 0
        # The issue shows the term, so the owner knows what to fix
        assert any(term in issue and "permerror" in issue for issue in result.issues)

    @pytest.mark.parametrize("domain", ["all-typo.example.com", "all-semicolon.example.com"])
    def test_a_typo_of_all_is_not_reported_as_a_missing_all(self, dns_replay, domain):
        """`-al` and `-all;` are not "no all mechanism — add one": the owner wrote
        one, and the record is a permerror, not neutral."""
        dns_replay("spf_syntax_errors")
        result = check_spf(domain)
        assert not any("no all mechanism" in issue for issue in result.issues)

    def test_redirect_twice_is_a_permerror(self, dns_replay):
        """RFC 7208 §6: redirect= may appear once. No query is made for either
        target: the record fails before evaluation."""
        server = dns_replay("spf_syntax_errors")
        result = check_spf("two-redirects.example.com")
        assert result.permerror is True
        assert result.score == 0
        assert any("redirect=" in issue and "permerror" in issue for issue in result.issues)
        assert server.queries == ["two-redirects.example.com. TXT"]

    @pytest.mark.parametrize("domain, term", [
        ("a-cidr.example.com", "a/33"),
        ("mx-cidr6.example.com", "mx//129"),
        ("mx-semicolon.example.com", "mx;"),
        ("include-empty.example.com", "include:"),
        ("exists-bare.example.com", "exists"),
        ("redirect-qualified.example.com", "-redirect=a.example.net"),
        ("redirect-empty.example.com", "redirect="),
    ])
    def test_a_known_name_in_a_form_spf_does_not_allow_is_a_permerror(self, dns_replay, domain, term):
        dns_replay("spf_syntax_forms")
        result = check_spf(domain)
        assert result.permerror is True
        assert result.score == 0
        assert any(f"term {term} " in issue and "permerror" in issue for issue in result.issues)

    def test_a_qualifier_on_a_modifier_is_named_as_such(self, dns_replay):
        """`-redirect=` is not an unknown mechanism: it is redirect= with a
        qualifier, which only mechanisms take (RFC 7208 §4.6.1)."""
        dns_replay("spf_syntax_forms")
        result = check_spf("redirect-qualified.example.com")
        assert any("qualifier" in issue for issue in result.issues)

    def test_every_allowed_form_stays_valid(self, dns_replay):
        """a/24, mx//64, a:domain/24//64, an upper-case name, ptr with and without a
        domain, an IPv4-mapped ip6, ip4 with and without a prefix length, exp=:
        a false permerror would take every point from a record that works."""
        dns_replay("spf_syntax_forms")
        result = check_spf("valid-forms.example.com")
        assert result.permerror is False
        assert result.issues == []
        assert result.score == 20

    def test_an_unknown_modifier_is_allowed(self, dns_replay):
        """RFC 7208 §6: `name=value` with an unknown name is ignored, not an error."""
        dns_replay("spf_syntax_errors")
        result = check_spf("unknown-modifier.example.com")
        assert result.permerror is False
        assert result.score == 20
        assert result.issues == []


class TestInvalidRanges:
    """RFC 7208 §5.6: `ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT)`, and the
    same for ip6 with up to three digits. Python's ip_network also takes a
    netmask, a hostmask, a leading zero and a zone id: none of them is SPF."""

    @pytest.mark.parametrize("domain, term", [
        ("netmask.example.com", "ip4:192.0.2.0/255.255.255.0"),
        ("hostmask.example.com", "ip4:192.0.2.0/0.0.0.255"),
        ("leading-zero.example.com", "ip4:192.0.2.0/027"),
        ("leading-zero6.example.com", "ip6:2001:db8::/064"),
        ("too-long.example.com", "ip4:192.0.2.0/33"),
        ("zone-id.example.com", "ip6:2001:db8::1%eth0/64"),
    ])
    def test_a_range_outside_the_abnf_is_a_permerror(self, dns_replay, domain, term):
        dns_replay("spf_ranges_invalid")
        result = check_spf(domain)
        assert result.permerror is True
        assert result.score == 0
        assert any(term in issue and "permerror" in issue for issue in result.issues)
        # Not a range this can say anything about either
        assert not any("authorises all of" in note for note in result.notes)


class TestIncludeTarget:
    """RFC 7208 §5.2: an include whose target has no SPF record, or more than
    one, is a permerror whenever it is evaluated. Common after a change of
    provider: the old provider's include stays, and its name no longer
    publishes SPF. It scored 20 and said nothing."""

    def test_an_include_without_spf_is_a_permerror(self, dns_replay):
        """_spf.example.net has no TXT record, as recorded in dns/example_net.json."""
        dns_replay("spf_include_without_spf", "example_net")
        result = check_spf("example.com")
        assert result.permerror is True
        assert result.score == 0
        assert any("include:_spf.example.net" in issue and "permerror" in issue
                   for issue in result.issues)

    def test_an_include_with_two_records_is_a_permerror(self, dns_replay):
        dns_replay("spf_include_two_records")
        result = check_spf("example.com")
        assert result.permerror is True
        assert result.score == 0
        assert any("include:two.example.net" in issue and "permerror" in issue
                   for issue in result.issues)

    def test_an_include_that_gets_no_answer_is_not_verified(self, dns_replay):
        """A lookup nobody answered is not a record that is missing: the check
        stays "not verified", it does not become a permerror."""
        dns_replay("spf_include_without_spf", silent=["_spf.example.net TXT"])
        result = check_spf("example.com")
        assert result.error
        assert result.permerror is False

    def test_a_syntax_error_in_the_included_record_is_a_permerror(self, dns_replay):
        """§4.6 holds for every record evaluated: the included record's permerror
        is the include's (§5.2), and so the domain's."""
        dns_replay("spf_include_syntax_error")
        result = check_spf("example.com")
        assert result.permerror is True
        assert result.score == 0
        assert any("include:bad.example.net" in issue and "foo:bar" in issue
                   for issue in result.issues)
