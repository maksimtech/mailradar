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

None of these changes the score: the record does what it says, and the note
says what it says. They are notes, not issues: the letter prints "SPF — Action
required" whenever `issues` is not empty, and a record that works needs no action.
"""
from __future__ import annotations

import pytest

from mailradar.checker import SPF_MAX_LOOKUPS, check_spf


class TestNotesAreNotIssues:
    """Each fixture below has one of the three findings and nothing wrong: the
    letter must not ask its owner to act on it."""

    @pytest.mark.parametrize("fixture, finding", [
        ("spf_cidr_host_bits", "192.0.2.98/27"),
        ("spf_redundant_include", "redundant"),
        ("spf_lookups_at_limit", f"{SPF_MAX_LOOKUPS} of {SPF_MAX_LOOKUPS}"),
    ])
    def test_the_finding_is_a_note_and_no_issue(self, dns_replay, fixture, finding):
        dns_replay(fixture)
        result = check_spf("example.com")
        assert result.issues == []
        assert any(finding in note for note in result.notes)
        assert result.score == 20


class TestHostBits:

    def test_a_range_written_from_an_inner_address_is_reported(self, dns_replay):
        dns_replay("spf_cidr_host_bits")
        result = check_spf("example.com")
        note = next(n for n in result.notes if "192.0.2.98/27" in n)
        # The range that is actually authorised, and how big it is
        assert "192.0.2.96/27" in note
        assert "32 addresses" in note

    def test_ip6_too(self, dns_replay):
        dns_replay("spf_cidr_host_bits")
        result = check_spf("example.com")
        assert any("2001:db8::1/64" in n and "2001:db8::/64" in n for n in result.notes)

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
        assert result.notes == []

    def test_values_that_are_not_addresses_of_their_family_are_left_alone(self, dns_replay):
        """A name under ip4:, an IPv6 network under ip4:, an IPv4 one under ip6:
        are not ranges this can say anything about: no note about them, and no
        crash. They are syntax errors, which receivers answer with a permerror
        (RFC 7208 §4.6; see test_spf_permerror.py)."""
        dns_replay("spf_ranges_malformed")
        result = check_spf("example.com")
        assert not any("authorises all of" in n or "redundant" in n for n in result.issues + result.notes)
        assert result.permerror is True

    def test_a_range_spelled_another_way_is_not_written_from_inside(self, dns_replay):
        """`ip6:2001:DB8:0:1::/64` starts at its first address; only its spelling
        differs from Python's (`2001:db8:0:1::/64`). Comparing the text reported it;
        the address written is what has to be compared with the network's first."""
        dns_replay("spf_cidr_aligned")
        result = check_spf("example.com")
        assert not any("2001:DB8:0:1::/64" in n for n in result.issues + result.notes)

    @pytest.mark.parametrize("term, says, network", [
        ("-ip4:192.0.2.98/27", "denies (fail) all of", "192.0.2.96/27"),
        ("~ip4:198.51.100.5/28", "softfails all of", "198.51.100.0/28"),
        ("?ip4:203.0.113.9/29", "marks all of", "203.0.113.8/29"),
        ("+ip4:192.0.2.130/30", "authorises all of", "192.0.2.128/30"),
    ])
    def test_the_note_says_what_the_qualifier_does(self, dns_replay, term, says, network):
        """`-ip4:` fails the range, it does not authorise it: saying "authorises"
        inverted the meaning for every qualifier but pass (RFC 7208 §4.6.2)."""
        dns_replay("spf_cidr_host_bits_qualified")
        result = check_spf("example.com")
        note = next(n for n in result.notes if term[1:] in n)
        assert f"{says} {network}" in note
        if not term.startswith("+"):
            assert "authorises" not in note
        # The term as written, qualifier included
        assert term in note

    def test_neutral_says_neutral(self, dns_replay):
        dns_replay("spf_cidr_host_bits_qualified")
        result = check_spf("example.com")
        note = next(n for n in result.notes if "ip4:203.0.113.9/29" in n)
        assert "neutral" in note


class TestRedundantRange:

    def test_a_range_its_own_include_already_lists_is_reported(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        note = next(n for n in result.notes if "192.0.2.96/27" in n)
        assert "include:_spf.example.net" in note
        assert "192.0.2.0/24" in note

    def test_a_range_the_include_does_not_cover_is_not(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert not any("198.51.100.0/24" in n for n in result.issues + result.notes)

    def test_ip6_ranges_too(self, dns_replay):
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert any("2001:db8:1::/48" in n and "2001:db8::/32" in n for n in result.notes)

    def test_a_range_that_denies_is_not_a_repetition(self, dns_replay):
        """`-ip4:192.0.2.200/29` lies inside the include's 192.0.2.0/24 and says the
        opposite: it fails those addresses before the include could pass them."""
        dns_replay("spf_redundant_include")
        result = check_spf("example.com")
        assert not any("192.0.2.200/29" in n for n in result.issues + result.notes)

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
        assert not any("redundant" in n for n in result.issues + result.notes)
        assert result.lookups == 1


class TestRangesOfEveryAddress:
    """A pass range with prefix length 0 covers every address of its family
    (RFC 7208 §5.6): any server passes, as with +all, and it scored 20."""

    @pytest.mark.parametrize("domain, term", [
        ("open4.example.com", "ip4:0.0.0.0/0"),
        ("open6.example.com", "ip6:::/0"),
        ("open-inner.example.com", "+ip4:192.0.2.1/0"),
        ("open-redirect.example.com", "ip4:0.0.0.0/0"),
    ])
    def test_it_scores_as_plus_all(self, dns_replay, domain, term):
        dns_replay("spf_open_ranges")
        result = check_spf(domain)
        assert result.score == 0
        assert result.permissive is True
        assert any(term in issue and "+all" in issue for issue in result.issues)

    def test_the_redirect_it_comes_from_is_named(self, dns_replay):
        dns_replay("spf_open_ranges")
        result = check_spf("open-redirect.example.com")
        assert any("redirect=open.example.net" in issue and "0.0.0.0/0" in issue
                   for issue in result.issues)

    @pytest.mark.parametrize("domain, score", [
        # -ip4:0.0.0.0/0 fails every IPv4 address: the record is ~all for the rest
        ("closed.example.com", 10),
        # after -all, never tested
        ("after-all.example.com", 20),
    ])
    def test_one_that_passes_nobody_does_not(self, dns_replay, domain, score):
        dns_replay("spf_open_ranges")
        result = check_spf(domain)
        assert result.score == score
        assert not any("+all" in issue for issue in result.issues)


class TestEvaluationOrder:
    """RFC 7208 §4.6.2 and §5.1: the first mechanism that matches decides, and
    nothing after `all` is tested. A range the include lists is "already
    authorised" only if the evaluation reaches it for those addresses: removing
    the domain's own range must not turn a pass into anything else."""

    @pytest.mark.parametrize("domain", [
        # the include's range comes after its -all and is never tested
        "after-all.example.com",
        # -ip4:192.0.2.64/26 fails .96/27 inside the include before its /24
        "denied-first.example.com",
        # -exists may match any address before the include's range
        "exists-first.example.com",
        # the domain's own -ip4:192.0.2.0/24 fails .96/27 before the include
        "top-denied.example.com",
    ])
    def test_a_range_the_evaluation_does_not_reach_first_is_not_redundant(self, dns_replay, domain):
        dns_replay("spf_redundant_order")
        result = check_spf(domain)
        assert not any("redundant" in n for n in result.issues + result.notes)

    def test_a_denied_range_that_does_not_touch_it_does_not_count(self, dns_replay):
        """-ip4:192.0.2.64/26 does not cover 192.0.2.0/27: the include's /24 passes
        those addresses, so the domain's own range is a repetition."""
        dns_replay("spf_redundant_order")
        result = check_spf("disjoint-denied.example.com")
        assert any("192.0.2.0/27" in n and "redundant" in n for n in result.notes)


class TestNestedRecords:

    def test_an_include_of_an_include_authorises(self, dns_replay):
        dns_replay("spf_nested_ranges")
        result = check_spf("deep.example.com")
        note = next(n for n in result.notes if "redundant" in n)
        assert "192.0.2.96/27" in note

    def test_the_note_names_the_domains_own_term(self, dns_replay):
        """The owner can only act on their own record: include:a.example.net is in
        it, include:b.example.net is in a.example.net's."""
        dns_replay("spf_nested_ranges")
        result = check_spf("deep.example.com")
        note = next(n for n in result.notes if "redundant" in n)
        assert "include:a.example.net" in note
        assert "include:b.example.net" not in note
        assert "through b.example.net" in note

    def test_a_redirect_inside_an_include_is_named_by_the_include(self, dns_replay):
        dns_replay("spf_nested_ranges")
        result = check_spf("via-redirect.example.com")
        note = next(n for n in result.notes if "redundant" in n)
        assert "include:c.example.net" in note
        assert "redirect=b.example.net" not in note

    def test_the_domains_own_redirect_authorises(self, dns_replay):
        """With no `all`, redirect= hands the evaluation to b.example.net (§6.1),
        whose /24 passes what the domain's own /27 passes."""
        dns_replay("spf_nested_ranges")
        result = check_spf("redirect.example.com")
        note = next(n for n in result.notes if "redundant" in n)
        assert "redirect=b.example.net" in note

    def test_a_neutral_include_inside_a_passing_one_authorises_nothing(self, dns_replay):
        """`?include:b.example.net` in d.example.net matches with neutral: d does
        not pass, and neither does the domain's include of it."""
        dns_replay("spf_nested_ranges")
        result = check_spf("neutral-nested.example.com")
        assert not any("redundant" in n for n in result.notes)

    def test_a_range_an_include_denies_is_not_authorised(self, dns_replay):
        """e.example.net lists the /24 with -ip4: it fails those addresses."""
        dns_replay("spf_nested_ranges")
        result = check_spf("denied-nested.example.com")
        assert not any("redundant" in n for n in result.notes)


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
        assert any(f"{SPF_MAX_LOOKUPS} of {SPF_MAX_LOOKUPS}" in n for n in result.notes)

    def test_one_below_the_limit_is_not(self, dns_replay):
        dns_replay("spf_lookups_below_limit")
        result = check_spf("example.com")
        assert result.lookups == SPF_MAX_LOOKUPS - 1
        assert result.issues == []
        assert result.notes == []

    def test_the_limit_reached_through_an_include_and_a_redirect(self, dns_replay):
        """Five lookups in the domain's record, three in its include's (one of them
        the redirect=), two in the redirect target's: the count follows both."""
        server = dns_replay("spf_lookups_at_limit_nested")
        result = check_spf("example.com")
        assert result.lookups == SPF_MAX_LOOKUPS
        assert result.lookups_partial is False
        assert result.permerror is False
        assert result.issues == []
        assert any(f"{SPF_MAX_LOOKUPS} of {SPF_MAX_LOOKUPS}" in n for n in result.notes)
        assert sorted(server.queries) == sorted(server.responses)

    def test_a_redirect_with_a_macro_is_counted(self, dns_replay):
        """`redirect=%{d}.r.example.net` costs a lookup like any redirect=; it was
        left out because its target could not be named."""
        dns_replay("spf_lookups_macro")
        result = check_spf("macro-redirect.example.com")
        assert result.lookups == SPF_MAX_LOOKUPS
        assert result.lookups_partial is True

    def test_a_count_with_a_macro_target_is_a_lower_bound(self, dns_replay):
        """An include: with a macro is counted and not followed: what its record
        would add is unknown, so the count is "at least", and says so."""
        dns_replay("spf_lookups_macro")
        result = check_spf("macro-include.example.com")
        assert result.lookups == 1
        assert result.lookups_partial is True
        note = next(n for n in result.notes if "at least 1 " in n)
        assert "include:%{d}.i.example.net" in note
        assert result.issues == []
        assert result.score == 20

    def test_a_count_without_macros_is_exact(self, dns_replay):
        dns_replay("qwant_com")
        result = check_spf("qwant.com")
        assert result.lookups_partial is False

    def test_the_verdict_of_a_macro_redirect_is_not_called_a_missing_all(self, dns_replay):
        """The record has no `all`, and its redirect= applies (§6.1): the result is
        the target's, which a macro hides, not the neutral of a record without
        either (§4.7)."""
        dns_replay("spf_lookups_macro")
        result = check_spf("macro-redirect.example.com")
        assert not any("no all mechanism" in i for i in result.issues)
        issue = next(i for i in result.issues if "redirect=%{d}.r.example.net" in i)
        assert "macro" in issue

    def test_not_counted_is_not_zero(self, dns_replay):
        """A lookup nobody answered leaves the count unknown, not 0 lookups."""
        dns_replay("qwant_com", silent=["qwant.com TXT"])
        result = check_spf("qwant.com")
        assert result.error
        assert result.lookups is None
