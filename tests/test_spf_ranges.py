"""
MailRadar — what an SPF record says beyond its `all`: the ranges it writes and
the DNS lookups it spends.

Three things a receiver never complains about and the owner still wants to know,
all seen in qnap.com's record on 2026-11-16:

- `ip4:113.196.74.98/27` is written from an address inside the range. RFC 7208
  §5.6 compares the first 27 bits, so the record authorises all 32 addresses of
  113.196.74.96/27, whether .98 alone was meant or the whole block was.
- the same range is listed again in `include:_ac.qnap.com`: one of the two is
  redundant, and the next edit has two places to keep in step.
- the lookup count was only ever compared with the limit. A record at 10 of 10
  passes today and breaks with the next include, and nothing said so.

None of these changes the score: the record does what it says, and the issue
says what it says.
"""
from __future__ import annotations

from mailradar.checker import SPF_MAX_LOOKUPS, check_spf


class TestHostBits:

    def test_a_range_written_from_an_inner_address_is_reported(self, dns_replay):
        dns_replay("spf_cidr_host_bits")
        result = check_spf("example.com")
        issue = next(i for i in result.issues if "192.0.2.98/27" in i)
        # The range that is actually authorised, and how big it is
        assert "192.0.2.96/27" in issue
        assert "32 addresses" in issue

    def test_ip6_too(self, dns_replay):
        dns_replay("spf_cidr_host_bits")
        result = check_spf("example.com")
        assert any("2001:db8::1/64" in i and "2001:db8::/64" in i for i in result.issues)

    def test_the_score_is_unchanged(self, dns_replay):
        """The record authorises what the range says; the warning is about intent."""
        dns_replay("spf_cidr_host_bits")
        result = check_spf("example.com")
        assert result.score == 20
        assert result.permissive is False

    def test_ranges_written_from_their_first_address_raise_nothing(self, dns_replay):
        dns_replay("spf_cidr_aligned")
        result = check_spf("example.com")
        assert result.issues == []

    def test_values_that_are_not_addresses_of_their_family_are_left_alone(self, dns_replay):
        """A name under ip4:, an IPv6 network under ip4:, an IPv4 one under ip6:
        are not ranges this can say anything about: no finding, and no crash."""
        dns_replay("spf_ranges_malformed")
        result = check_spf("example.com")
        assert not any("authorises all of" in i or "redundant" in i for i in result.issues)

    def test_a_range_spelled_another_way_is_not_written_from_inside(self, dns_replay):
        """`ip6:2001:DB8:0:1::/64` starts at its first address; only its spelling
        differs from Python's (`2001:db8:0:1::/64`). Comparing the text reported it;
        the address written is what has to be compared with the network's first."""
        dns_replay("spf_cidr_aligned")
        result = check_spf("example.com")
        assert not any("2001:DB8:0:1::/64" in i for i in result.issues)


class TestRedundantRange:

    def test_a_range_its_own_include_already_lists_is_reported(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        issue = next(i for i in result.issues if "192.0.2.96/27" in i)
        assert "include:_spf.example.net" in issue
        assert "192.0.2.0/24" in issue

    def test_a_range_the_include_does_not_cover_is_not(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert not any("198.51.100.0/24" in i for i in result.issues)

    def test_ip6_ranges_too(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert any("2001:db8:1::/48" in i and "2001:db8::/32" in i for i in result.issues)

    def test_a_range_that_denies_is_not_a_repetition(self, dns_replay):
        """`-ip4:192.0.2.200/29` lies inside the include's 192.0.2.0/24 and says the
        opposite: it fails those addresses before the include could pass them."""
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert not any("192.0.2.200/29" in i for i in result.issues)

    def test_the_include_is_asked_once(self, dns_replay):
        """Finding the overlap costs no query beyond those the lookup count makes."""
        server = dns_replay("spf_redundant_include")
        check_spf("example.com")
        assert server.queries.count("_spf.example.net. TXT") == 1

    def test_an_include_that_does_not_pass_makes_nothing_redundant(self, dns_replay):
        """`?include:` matches with neutral (RFC 7208 §5.2): what it lists is not
        authorised, so the domain's own range is the one that gives pass. Only an
        include with the pass qualifier, or none, authorises what it pulls in."""
        dns_replay("spf_neutral_include")
        result = check_spf("example.com")
        assert not any("redundant" in i for i in result.issues)
        assert result.lookups == 1


class TestLookupCount:

    def test_the_count_is_kept(self, dns_replay):
        """qwant.com as recorded: include:_spf.google.com, whose record is only ranges."""
        dns_replay("qwant_com")
        result = check_spf("qwant.com")
        assert result.lookups == 1

    def test_a_record_at_the_limit_is_reported(self, dns_replay):
        dns_replay("spf_lookups_at_limit")
        result = check_spf("example.com")
        assert result.lookups == SPF_MAX_LOOKUPS
        assert result.permerror is False
        assert any(f"{SPF_MAX_LOOKUPS} of {SPF_MAX_LOOKUPS}" in i for i in result.issues)

    def test_one_below_the_limit_is_not(self, dns_replay):
        dns_replay("spf_lookups_below_limit")
        result = check_spf("example.com")
        assert result.lookups == SPF_MAX_LOOKUPS - 1
        assert result.issues == []

    def test_not_counted_is_not_zero(self, dns_replay):
        """A lookup nobody answered leaves the count unknown, not 0 lookups."""
        dns_replay("qwant_com", silent=["qwant.com TXT"])
        result = check_spf("qwant.com")
        assert result.error
        assert result.lookups is None
