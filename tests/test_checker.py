"""
Tests for MailRadar checker module.
Uses mocks to avoid real DNS queries in CI.
"""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mailradar.checker import (
    DKIM_SELECTORS,
    DMARCResult,
    DNSLookupError,
    SPFResult,
    _apply_dmarc_record,
    _apply_spf_verdict,
    _spf_all,
    _spf_terms,
    analyze_domain,
    check_bimi,
    check_dkim,
    check_dmarc,
    check_mta_sts,
    check_spf,
    check_tls_rpt,
    dmarc_lookup_chain,
    domain_exists,
    find_domain_variants,
    organizational_domain,
)
from tests.replay import recorded_txt

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
        txt = (
            "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com; "
            "fo=1"
        )
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

    def test_dmarc_tag_values_are_case_insensitive(self):
        """RFC 7489 §6.4 (ABNF): "reject" is a case-insensitive literal, p=REJECT is p=reject.

        example.com's record with its values in upper case: reject, pct, adkim=s, aspf=s.
        """
        result = dmarc_record_of("dmarc_uppercase")
        assert result.policy == "reject"
        assert (result.adkim, result.aspf) == ("s", "s")
        assert result.score == 45

    def test_multiple_dmarc_records_apply_no_policy(self, dns_replay):
        """RFC 7489 §6.6.3: with more than one DMARC record, policy discovery ends with no policy."""
        dns_replay("dmarc_multiple")
        result = check_dmarc("example.com")
        assert result.score == 0
        assert any("multiple" in issue.lower() for issue in result.issues)

    def test_dmarc_version_tag_allows_spaces_around_equals(self, dns_replay):
        """RFC 7489 §6.4: dmarc-version = "v" *WSP "=" *WSP "DMARC1", so 'v = DMARC1' is valid."""
        dns_replay("dmarc_spaced_version")
        result = check_dmarc("example.com")
        assert result.present is True
        assert result.policy == "reject"

    def test_empty_rua_does_not_count_as_reports_configured(self):
        """RFC 7489 §6.4: rua needs at least one URI; an empty 'rua=' turns no aggregate reports on."""
        result = dmarc_record_of("dmarc_empty_rua")
        assert result.rua is False
        assert result.ruf is False


class TestDMARCInvalidValues:
    """RFC 7489 §6.6.3: a record with no valid p, or an sp that is not valid, acts as p=none
    when its rua names a valid URI, and otherwise no DMARC applies. The value was shown as
    the policy: p=rejected as 'rejected', an empty p= as '', an inherited sp=bogus as 'bogus'."""

    def test_an_invalid_p_with_a_rua_acts_as_none(self, dns_replay):
        dns_replay("dmarc_invalid_values")
        result = check_dmarc("p-typo.example.com")
        assert result.present is True
        assert result.policy == "none"
        assert result.score < 15
        assert any("p=rejected" in issue for issue in result.issues)

    def test_a_missing_p_with_a_rua_acts_as_none(self, dns_replay):
        dns_replay("dmarc_invalid_values")
        result = check_dmarc("p-missing.example.com")
        assert result.policy == "none"
        assert any("no p=" in issue for issue in result.issues)

    def test_an_empty_p_without_a_rua_applies_no_dmarc(self, dns_replay):
        """Discovery ends there: the organizational domain is not asked (the fixture has no answer for it)."""
        dns_replay("dmarc_invalid_values")
        result = check_dmarc("p-empty.example.com")
        assert result.present is False
        assert result.policy != ""
        assert result.score == 0
        assert result.found_at == "p-empty.example.com"
        assert any("p=" in issue and "no DMARC" in issue for issue in result.issues)
        assert not any("No DMARC record found" in issue for issue in result.issues)

    def test_an_inherited_invalid_sp_is_not_the_policy(self, dns_replay):
        dns_replay("dmarc_invalid_values")
        result = check_dmarc("mail.example.net")
        assert result.policy != "bogus"
        assert result.present is False
        assert result.score == 0
        assert any("sp=bogus" in issue for issue in result.issues)

    def test_a_rua_without_mailto_is_no_report_address(self, dns_replay):
        """rua=dmarc@example.com is no URI (RFC 7489 §6.4): it earned the 3 points of reports configured."""
        dns_replay("dmarc_invalid_values")
        result = check_dmarc("rua-no-mailto.example.com")
        assert result.rua is False
        assert result.policy == "reject"
        assert any("dmarc@example.com" in issue and "mailto:" in issue for issue in result.issues)


def dmarc_record_of(fixture: str) -> DMARCResult:
    """_apply_dmarc_record on the _dmarc.example.com record a fixture holds: the text alone, no DNS."""
    [record] = recorded_txt(fixture, "_dmarc.example.com")
    result = DMARCResult()
    _apply_dmarc_record(result, record)
    return result


# ─── DMARC tree walk — RFC 7489 §6.6.3 ──────────────────────────────────────

def make_zone_resolver(zone: dict[str, list[str]], queried: list[str] = None):
    """Resolver mock: solo i nomi presenti in `zone` rispondono, gli altri
    raise NXDOMAIN. Every name queried is recorded in `queried`."""
    def resolve(name, rdtype="TXT", *args, **kwargs):
        key = str(name).rstrip(".")
        if queried is not None:
            queried.append(key)
        if key in zone:
            return make_txt_answer(zone[key])
        raise dns.resolver.NXDOMAIN
    return resolve


class TestOrganizationalDomain:

    # fvg.it is itself a public suffix (ICANN section of the PSL), so the
    # registrable name below it is the organizational domain
    @pytest.mark.parametrize("domain,expected", [
        ("asufc.sanita.fvg.it", "sanita.fvg.it"),
        ("sanita.fvg.it", "sanita.fvg.it"),
        ("sub.domain.com", "domain.com"),
        ("domain.com", "domain.com"),
        ("mail.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("a.b.c.d.example.gov.uk", "example.gov.uk"),
    ])
    def test_organizational_domain(self, domain, expected):
        assert organizational_domain(domain) == expected

    def test_normalizes_case_and_trailing_dot(self):
        assert organizational_domain("Sub.Domain.COM.") == "domain.com"

    def test_single_label_is_returned_as_is(self):
        assert organizational_domain("localhost") == "localhost"

    def test_follows_the_psl_wildcard_and_exception_rules(self):
        """PSL: '*.kawasaki.jp' makes every name under kawasaki.jp public, '!city.kawasaki.jp' does not."""
        assert organizational_domain("a.b.example.kawasaki.jp") == "b.example.kawasaki.jp"
        assert organizational_domain("www.city.kawasaki.jp") == "city.kawasaki.jp"
        assert organizational_domain("mail.example.co.at") == "example.co.at"

    def test_follows_the_private_section_of_the_psl(self):
        """github.io is in the private section: each site under it is a domain of its own, not GitHub's."""
        assert organizational_domain("mail.project.github.io") == "project.github.io"

    def test_idn_suffix_in_punycode(self):
        """The PSL lists '公司.cn' in Unicode; the same suffix can arrive as xn--55qx5d.cn."""
        assert organizational_domain("mail.example.xn--55qx5d.cn") == "example.xn--55qx5d.cn"
        assert organizational_domain("mail.example.公司.cn") == "example.公司.cn"


class TestDMARCLookupChain:

    def test_chain_multilevel_it_domain(self):
        assert dmarc_lookup_chain("asufc.sanita.fvg.it") == [
            "asufc.sanita.fvg.it",
            "sanita.fvg.it",
        ]

    def test_chain_multi_label_public_suffix(self):
        assert dmarc_lookup_chain("mail.example.co.uk") == [
            "mail.example.co.uk",
            "example.co.uk",
        ]

    def test_chain_normal_subdomain(self):
        assert dmarc_lookup_chain("sub.domain.com") == [
            "sub.domain.com",
            "domain.com",
        ]

    def test_chain_apex_domain_is_single_step(self):
        assert dmarc_lookup_chain("example.com") == ["example.com"]

    def test_chain_skips_the_names_between_the_domain_and_its_organizational_domain(self):
        """RFC 7489 §6.6.3: the domain, then the organizational domain; no label-by-label walk."""
        assert dmarc_lookup_chain("a.b.c.example.com") == ["a.b.c.example.com", "example.com"]

    @pytest.mark.parametrize("domain,forbidden", [
        ("asufc.sanita.fvg.it", "it"),
        ("asufc.sanita.fvg.it", "fvg.it"),
        ("mail.example.co.uk", "co.uk"),
        ("mail.example.co.uk", "uk"),
        ("sub.domain.com", "com"),
    ])
    def test_chain_never_reaches_the_public_suffix(self, domain, forbidden):
        assert forbidden not in dmarc_lookup_chain(domain)

    def test_chain_never_queries_a_suffix_outside_the_old_subset(self):
        """README: "The public suffix itself is never queried". co.at is a public suffix (PSL)."""
        chain = dmarc_lookup_chain("mail.example.co.at")
        assert "co.at" not in chain
        assert chain[-1] == "example.co.at"


class TestCheckDMARCTreeWalk:

    def test_climbs_to_organizational_domain(self, dns_replay):
        """asufc.sanita.fvg.it with no record of its own -> policy from sanita.fvg.it,
        where the real one is published (_dmarc.fvg.it is NXDOMAIN, checked 2026-10-07).

        The answers are the real ones, recorded the same day: NXDOMAIN for the
        subdomain, p=none on sanita.fvg.it.
        """
        server = dns_replay("sanita_fvg_it")
        result = check_dmarc("asufc.sanita.fvg.it")
        assert result.present is True
        assert result.policy == "none"
        assert result.found_at == "sanita.fvg.it"
        assert result.inherited is True
        assert server.queries == [
            "_dmarc.asufc.sanita.fvg.it. TXT",
            "_dmarc.sanita.fvg.it. TXT",
        ]
        assert any("sanita.fvg.it" in issue for issue in result.issues)

    def test_a_record_on_an_intermediate_name_is_not_the_policy(self, dns_replay):
        """RFC 7489 §6.6.3 asks _dmarc.<domain> and then _dmarc.<organizational domain>.
        For sub.a.example.com the p=none on _dmarc.a.example.com was reported, while a
        receiver applies example.com's p=reject."""
        server = dns_replay("dmarc_org_domain")
        result = check_dmarc("sub.a.example.com")
        assert result.policy == "reject"
        assert result.found_at == "example.com"
        assert result.inherited is True
        assert server.queries == ["_dmarc.sub.a.example.com. TXT", "_dmarc.example.com. TXT"]

    def test_stops_at_the_first_parent_that_answers(self):
        zone = {
            "_dmarc.sanita.fvg.it": ["v=DMARC1; p=quarantine"],
            "_dmarc.fvg.it": ["v=DMARC1; p=reject"],
        }
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("asufc.sanita.fvg.it")
        assert result.found_at == "sanita.fvg.it"
        assert result.policy == "quarantine"
        assert "_dmarc.fvg.it" not in queried

    def test_own_record_wins_over_parent(self):
        zone = {
            "_dmarc.asufc.sanita.fvg.it": ["v=DMARC1; p=reject; adkim=s; aspf=s"],
            "_dmarc.fvg.it": ["v=DMARC1; p=none"],
        }
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone)):
            result = check_dmarc("asufc.sanita.fvg.it")
        assert result.found_at == "asufc.sanita.fvg.it"
        assert result.inherited is False
        assert result.policy == "reject"
        assert not any("inherited" in issue.lower() for issue in result.issues)

    def test_multi_label_suffix_climbs_only_to_org_domain(self):
        """mail.example.co.uk → example.co.uk, mai _dmarc.co.uk."""
        zone = {"_dmarc.example.co.uk": ["v=DMARC1; p=reject; rua=mailto:r@example.co.uk"]}
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("mail.example.co.uk")
        assert result.present is True
        assert result.found_at == "example.co.uk"
        assert result.inherited is True
        assert queried == ["_dmarc.mail.example.co.uk", "_dmarc.example.co.uk"]

    def test_normal_subdomain_falls_back_to_apex(self):
        zone = {"_dmarc.domain.com": ["v=DMARC1; p=reject; adkim=s; aspf=s"]}
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("sub.domain.com")
        assert result.present is True
        assert result.found_at == "domain.com"
        assert result.inherited is True
        assert queried == ["_dmarc.sub.domain.com", "_dmarc.domain.com"]

    def test_normal_subdomain_with_own_record(self):
        zone = {"_dmarc.sub.domain.com": ["v=DMARC1; p=reject"]}
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("sub.domain.com")
        assert result.found_at == "sub.domain.com"
        assert result.inherited is False
        assert queried == ["_dmarc.sub.domain.com"]

    def test_nothing_anywhere_never_queries_the_tld(self):
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver({}, queried)):
            result = check_dmarc("sub.domain.com")
        assert result.present is False
        assert result.found_at == ""
        assert result.inherited is False
        assert queried == ["_dmarc.sub.domain.com", "_dmarc.domain.com"]
        assert "_dmarc.com" not in queried
        assert any("spoofable" in issue for issue in result.issues)

    def test_non_dmarc_txt_on_subdomain_does_not_stop_the_walk(self):
        zone = {
            "_dmarc.sub.domain.com": ["some unrelated txt record"],
            "_dmarc.domain.com": ["v=DMARC1; p=reject"],
        }
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone)):
            result = check_dmarc("sub.domain.com")
        assert result.found_at == "domain.com"
        assert result.policy == "reject"

    def test_sp_overrides_policy_for_subdomains(self):
        """RFC 7489 §6.3: `sp` è la policy che vale per i sottodomini."""
        zone = {"_dmarc.domain.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:r@domain.com"]}
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone)):
            result = check_dmarc("sub.domain.com")
        assert result.inherited is True
        assert result.sp == "none"
        assert result.policy == "none"
        assert any("sp=none" in issue for issue in result.issues)

    def test_sp_ignored_when_record_is_the_domains_own(self):
        zone = {"_dmarc.domain.com": ["v=DMARC1; p=reject; sp=none"]}
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone)):
            result = check_dmarc("domain.com")
        assert result.inherited is False
        assert result.sp == "none"
        assert result.policy == "reject"


# ─── SPF ────────────────────────────────────────────────────────────────────

class TestCheckSPF:

    def test_spf_hardfail(self, dns_replay):
        # qwant.com as recorded: include:_spf.google.com -all. The include is
        # followed to the name it names and nowhere else
        dns_replay("qwant_com")
        result = check_spf("qwant.com")
        assert result.present is True
        assert result.all_mechanism == "-all"
        assert result.permissive is False
        assert result.score == 20
        assert result.issues == []

    def test_spf_softfail(self, dns_replay):
        # fastmail.com as recorded: include:spf.messagingengine.com ~all
        dns_replay("fastmail_com")
        result = check_spf("fastmail.com")
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
        """`+a` and `+mx` authorise the domain's own A and MX hosts: that is what
        most records mean to do, not a weakness. RFC 7208 §4.6.2 makes `+` the
        default qualifier, so `+a` is the same term as a bare `a`, which was never
        flagged: the "too permissive" warning judged the spelling, not the record."""
        txt = "v=spf1 +a +mx -all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.permissive is False
        assert result.score == 20
        assert result.issues == []

    def test_bare_all_is_plus_all(self, dns_replay):
        """RFC 7208 §4.6.2: 'all' with no qualifier is '+all', a pass for anyone."""
        dns_replay("spf_bare_all")
        result = check_spf("example.com")
        assert result.permissive is True
        assert result.score == 0

    def test_dash_all_inside_a_host_name_is_not_a_hardfail(self, dns_replay):
        """'-all' inside 'include:spf-all.example.net' is not the all mechanism: the final ~all is."""
        dns_replay("spf_dash_all_in_host")
        result = check_spf("example.com")
        assert result.all_mechanism == "~all"
        assert result.score == 10

    def test_mechanism_names_are_case_insensitive(self, dns_replay):
        """RFC 7208 §4.6.1: mechanism names are case-insensitive, '-ALL' is a hardfail."""
        dns_replay("spf_uppercase_all")
        result = check_spf("example.com")
        assert result.all_mechanism == "-all"
        assert result.score == 20

    def test_redirect_follows_the_target_record(self, dns_replay):
        """RFC 7208 §6.1: with redirect= the target's record decides (gmail.com uses redirect alone).

        gmail.com as recorded: "v=spf1 redirect=_spf.google.com", and _spf.google.com ends in ~all.
        """
        dns_replay("gmail_com")
        result = check_spf("gmail.com")
        assert result.all_mechanism == "~all"
        assert result.score == 10

    def test_redirect_to_a_name_without_spf_is_a_permerror(self, dns_replay):
        """RFC 7208 §6.1: if the redirect= domain has no SPF record, the result is a permerror."""
        dns_replay("spf_redirect_without_spf", "example_net")
        result = check_spf("example.com")
        assert result.permerror is True
        assert result.score == 0

    def test_no_all_and_no_redirect_is_neutral_and_reported(self, dns_replay):
        """RFC 7208 §4.7: with neither 'all' nor 'redirect=' the default result is neutral, and is said."""
        dns_replay("spf_no_all")
        result = check_spf("example.com")
        assert result.permissive is True
        assert any("neutral" in issue.lower() for issue in result.issues)

    def test_multiple_spf_records_are_a_permerror(self, dns_replay):
        """RFC 7208 §4.5: more than one v=spf1 record on the same name is a permerror, no full score."""
        dns_replay("spf_multiple")
        result = check_spf("example.com")
        assert result.score == 0
        assert any("multiple" in issue.lower() or "permerror" in issue.lower() for issue in result.issues)

    def test_more_than_10_dns_lookups_is_a_permerror(self, dns_replay):
        """RFC 7208 §4.6.4: more than 10 mechanisms that need a DNS lookup is a permerror.

        hostgator.com as recorded needs more than 10: the count stops at the
        eleventh, so the names past it were never asked for.
        """
        dns_replay("hostgator_com")
        result = check_spf("hostgator.com")
        assert result.permerror is True
        assert result.score == 0
        assert any("lookup" in issue.lower() for issue in result.issues)

    def test_exactly_10_dns_lookups_is_still_valid(self, dns_replay):
        """The RFC 7208 §4.6.4 boundary: the limit is "more than 10", 10 lookups (nested ones included) pass.

        github.com as recorded needs exactly 10, nested includes counted, and ends in ~all.
        """
        server = dns_replay("github_com")
        result = check_spf("github.com")
        assert result.permerror is False
        assert result.all_mechanism == "~all"
        assert result.score == 10
        # Every name the 10 lookups lead to, and no other, was asked for
        assert sorted(server.queries) == sorted(server.responses)

    def test_include_loop_is_a_permerror(self, dns_replay):
        """An include that comes back to itself runs out of lookups: a permerror, not a 20-point hardfail."""
        dns_replay("spf_include_loop")
        result = check_spf("example.com")
        assert result.permerror is True
        assert result.score == 0

    def test_plus_all_does_not_raise_the_plus_a_or_plus_mx_warning(self, dns_replay):
        """'+all' holds the substring '+a': it must not raise the '+a or +mx' warning."""
        dns_replay("spf_plus_all")
        result = check_spf("example.com")
        assert not any("+a or +mx" in issue for issue in result.issues)

    def test_question_mark_all_is_neutral_and_reported(self):
        """RFC 7208 §8.2: '?all' is neutral, no enforcement — 5 points, not the 10 of '~all'.

        No DNS and no stand-in for it: ip4: and all cost no lookup (§4.6.4) and the
        record has no redirect=, so check_spf would hand this text to the verdict as is.
        """
        record = "v=spf1 ip4:192.0.2.0/24 ?all"
        terms = _spf_terms(record)
        result = SPFResult(present=True, raw=record, all_mechanism=_spf_all(terms))
        _apply_spf_verdict(result, terms)
        assert result.all_mechanism == "?all"
        assert result.permissive is True
        assert result.score == 5
        assert result.issues == ["SPF uses ?all (neutral) — no enforcement"]


# ─── DKIM ───────────────────────────────────────────────────────────────────

class TestCheckDKIM:

    def test_dkim_2048(self):
        # A real 2048-bit RSA key, truncated for the test
        key = (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6E"
            "YQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvx"
            "DKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38"
            "/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
        )
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

    def test_dkim_1024(self, dns_replay):
        # polimi.it's selector1, as recorded: a real 1024-bit key. The one this
        # test made up did not decode, and scored 10 only by its length.
        dns_replay("polimi_it")
        result = check_dkim("polimi.it", selectors=["selector1"])
        assert result.present is True
        assert result.key_bits == 1024
        assert result.score == 10
        assert any("1024" in issue for issue in result.issues)

    def test_dkim_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            result = check_dkim("example.com")
        assert result.present is False
        assert result.score == 0

    def test_ed25519_key_is_not_weak(self, dns_replay):
        """RFC 8463: an Ed25519 key (32 raw bytes) is strong, not a 512-bit RSA key.

        archlinux.org signs with one, under the selector dkim-ed25519 (recorded).
        """
        dns_replay("archlinux_org")
        result = check_dkim("archlinux.org", selectors=["dkim-ed25519"])
        assert result.present is True
        assert not any("weak" in issue.lower() for issue in result.issues)
        assert result.score == 15
        assert result.key_type == "ed25519"

    def test_malformed_ed25519_key_does_not_get_the_full_score(self, dns_replay):
        dns_replay("dkim_ed25519_malformed")
        result = check_dkim("archlinux.org", selectors=["dkim-ed25519"])
        assert result.score < 15
        assert result.issues

    def test_empty_p_is_a_revoked_key_not_a_weak_one(self, dns_replay):
        """RFC 6376 §3.6.1: an empty 'p=' means the key is revoked (it was a known limitation in the README).

        example.com publishes "v=DKIM1; p=" under every selector (recorded).
        """
        dns_replay("example_com")
        result = check_dkim("example.com", selectors=["default"])
        assert not any("weak" in issue.lower() for issue in result.issues)
        assert any("revok" in issue.lower() for issue in result.issues)

    def test_revoked_selector_does_not_hide_the_active_key(self, dns_replay):
        """Rotation: the old, revoked selector does not count when another one has the active key."""
        dns_replay("example_com", "dkim_rotation")
        result = check_dkim("example.com", selectors=["s1", "s2"])
        assert result.selector == "s2"
        assert not any("revok" in issue.lower() for issue in result.issues)


class TestDKIMKeysThatCannotBeUsed:
    """A key that does not decode as the type it declares verifies no signature (RFC 6376 §3.6.1).

    Each was scored by the length of p=: a 2048-bit key cut at 255 characters
    as 1024-bit (10 points), 400 'A' as 2048-bit (15), no p= at all as a weak
    0-bit key (3), an RSA key under k=ecdsa as 2048-bit (15).
    """

    @pytest.mark.parametrize("selector", ["truncated", "zeros", "nop", "ecdsa"])
    def test_a_key_that_cannot_be_used_scores_nothing(self, dns_replay, selector):
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=[selector])
        assert result.score == 0
        assert result.key_bits == 0
        assert any("malformed" in issue and "cannot be verified" in issue and selector in issue
                   for issue in result.issues)
        assert not any("1024" in issue or "weak" in issue for issue in result.issues)
        assert "malformed" in result.keys[selector]

    def test_a_dmarc_record_under_a_selector_is_no_dkim_key(self, dns_replay):
        """'v=DMARC1;p=reject…' holds 'p=': it was read as a 512-bit RSA key."""
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=["dmarc"])
        assert result.present is False
        assert result.keys == {}
        assert not any("512" in issue for issue in result.issues)

    def test_a_pkcs1_key_is_a_key(self, dns_replay):
        """RFC 6376 §3.6.1 names RSAPublicKey (PKCS#1); SubjectPublicKeyInfo is what most publish."""
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=["pkcs1"])
        assert (result.key_bits, result.score) == (2048, 15)

    def test_a_usable_key_decides_beside_a_malformed_one(self, dns_replay):
        """A malformed key verifies nothing, so it lets nobody forge either: the posture is the
        weakest key that works, and the broken one is reported on its own."""
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=["truncated", "active"])
        assert result.selector == "active"
        assert result.score == 15
        assert any("truncated" in issue and "malformed" in issue for issue in result.issues)

    def test_a_key_in_testing_mode_counts_as_unsigned(self, dns_replay):
        """RFC 6376 §3.6.1, t=y: verifiers MUST NOT treat mail from a signer in testing mode
        differently from unsigned mail. A 2048-bit key there earned the full 15 points."""
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=["testing"])
        assert result.present is True
        assert result.score == 0
        assert any("testing" in issue and "t=y" in issue for issue in result.issues)

    def test_a_key_in_testing_mode_beside_an_active_one(self, dns_replay):
        dns_replay("dkim_unusable")
        result = check_dkim("example.com", selectors=["testing", "active"])
        assert result.selector == "active"
        assert result.score == 15
        assert any("testing" in issue and "under testing" in issue for issue in result.issues)


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

    def test_bimi_does_not_fetch_a_url_that_is_not_https(self, dns_replay, http_replay):
        """BIMI requires https for l=; an http URL into the internal network must not be fetched (SSRF).

        Every HTTP request of the test goes through the proxy, and nothing is
        recorded there: one request reaching it is one too many.
        """
        dns_replay("bimi_ssrf")
        proxy = http_replay()
        result = check_bimi("http-loopback.example.com")
        assert proxy.requests == []
        assert result.svg_valid is False

    def test_bimi_does_not_fetch_https_from_an_internal_ip_literal(self, dns_replay, http_replay):
        """Even over https, a loopback, private or link-local IP literal is not contacted."""
        dns_replay("bimi_ssrf")
        proxy = http_replay()
        for case in ("https-loopback", "https-ipv6-loopback", "https-private", "https-link-local"):
            result = check_bimi(f"{case}.example.com")
            assert proxy.requests == [], case
            assert result.svg_valid is False, case

    def test_bimi_declination_record_scores_nothing(self, dns_replay):
        """BIMI: 'v=BIMI1; l=; a=;' declines explicitly, it is not a 3-point BIMI without a VMC.

        icloud.com publishes exactly that (recorded).
        """
        dns_replay("icloud_com")
        result = check_bimi("icloud.com")
        assert result.score == 0

    @pytest.mark.parametrize("case", ["malformed-l", "malformed-port"])
    def test_a_logo_url_that_cannot_be_parsed_is_an_issue_not_a_crash(self, dns_replay, http_replay, case):
        """urlsplit raises ValueError on l=https://[::1/logo.svg, and .port on a port past 65535:
        it escaped check_bimi and ended the whole analysis. The URL comes from the domain's DNS."""
        dns_replay("bimi_malformed_url")
        proxy = http_replay()
        result = check_bimi(f"{case}.example.com")
        assert result.present is True
        assert any("logo URL is malformed" in issue for issue in result.issues)
        assert result.svg_valid is False
        assert proxy.requests == []

    def test_a_vmc_url_that_cannot_be_parsed_is_no_vmc(self, dns_replay, http_replay):
        """a=https://[::1/vmc.pem names no certificate anyone could fetch: it earns no VMC points."""
        dns_replay("bimi_malformed_url")
        proxy = http_replay()
        result = check_bimi("malformed-a.example.com")
        assert result.vmc_present is False
        assert result.score < 8
        assert any("VMC URL is malformed" in issue for issue in result.issues)
        assert proxy.requests == []

    @pytest.mark.parametrize("case", ["https-short", "https-decimal", "https-hex", "https-octal",
                                      "https-hex-dotted", "https-private-short"])
    def test_bimi_does_not_fetch_an_ipv4_literal_in_a_form_inet_aton_reads(self, dns_replay, http_replay, case):
        """glibc's getaddrinfo, in the Docker image, reads 127.1, 2130706433, 0x7f000001 and
        0177.0.0.1 as 127.0.0.1: ipaddress does not, so they passed as host names."""
        dns_replay("bimi_ssrf_ipv4_forms")
        proxy = http_replay()
        result = check_bimi(f"{case}.example.com")
        assert proxy.requests == []
        assert result.svg_valid is False
        assert any("not a public https:// URL" in issue for issue in result.issues)

    @pytest.mark.parametrize("url,fetchable", [
        ("https://amplify.valimail.com/bimi/logo.svg", True),
        ("https://192.0.2.1/logo.svg", False),           # TEST-NET-1 is not global
        ("https://134744072/logo.svg", True),             # 8.8.8.8 written as one number: global
        ("https://0x08080808/logo.svg", True),
        ("https://08.0.0.1/logo.svg", False),             # numeric, and no address: nothing to fetch
        ("https://4294967296/logo.svg", False),           # past 32 bits
        ("https://127.0.0.1./logo.svg", False),           # the trailing dot of a FQDN
        ("https://[2001:db8::1]/logo.svg", False),
        ("https://[::ffff:127.0.0.1]/logo.svg", False),
        ("https://0x7f.example/logo.svg", True),          # a host name whose first label looks hex
    ])
    def test_which_hosts_are_fetched(self, url, fetchable):
        from mailradar.checker import _fetchable
        assert _fetchable(url) is fetchable


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

    def test_mta_sts_unreachable_policy_raises_an_issue(self, dns_replay, http_replay):
        """_mta-sts record present but the policy answers HTTP 404: MTA-STS does not work, and is said.

        ecosia.org, as recorded: the TXT record is there, the policy file is a 404.
        """
        dns_replay("ecosia_org")
        http_replay("ecosia_org")
        result = check_mta_sts("ecosia.org")
        assert result.issues, "no issue raised with the policy file answering 404"

    def test_mta_sts_mode_none_is_not_an_unknown_mode(self, dns_replay, http_replay):
        """RFC 8461 §5: 'none' is a valid mode (the policy withdrawn), not 'mode unknown'."""
        dns_replay("fastmail_com")
        http_replay("fastmail_mta_sts_mode_none")
        result = check_mta_sts("fastmail.com")
        assert result.mode == "none"
        assert result.score == 0
        assert not any("unknown" in issue for issue in result.issues)
        assert any("none" in issue for issue in result.issues)


class TestMTASTSValidity:
    """RFC 8461 §3.1 and §3.2: what senders accept as a policy, and what they ignore.

    Each case below scored 5 with mode enforce.
    """

    @pytest.mark.parametrize("case,named", [
        ("mode-only", ["version", "max_age", "mx"]),
        ("stsv2", ["STSv2"]),
        ("no-mx", ["mx"]),
    ])
    def test_an_invalid_policy_file_is_no_policy(self, dns_replay, http_replay, case, named):
        dns_replay("mta_sts_invalid")
        http_replay("mta_sts_invalid")
        result = check_mta_sts(f"{case}.example.com")
        assert result.score == 0
        assert result.mode != "enforce"
        issue = next(issue for issue in result.issues if "policy is invalid" in issue)
        for word in named:
            assert word in issue

    @pytest.mark.parametrize("case,said", [
        ("two-records", "Multiple MTA-STS records"),
        ("no-id", "id="),
        ("not-first", "begin with v=STSv1"),
    ])
    def test_a_txt_record_senders_do_not_accept_announces_no_policy(self, dns_replay, http_replay, case, said):
        """Senders discard a record that does not begin with v=STSv1, and with zero or several
        left, or one without a valid id=, look for no policy: the file is not even fetched."""
        dns_replay("mta_sts_invalid")
        proxy = http_replay("mta_sts_invalid")
        result = check_mta_sts(f"{case}.example.com")
        assert result.present is False
        assert result.score == 0
        assert any(said in issue for issue in result.issues)
        assert proxy.requests == []

    def test_a_valid_policy_with_crlf_line_ends_is_enforced(self, dns_replay, http_replay):
        """§3.2 ends policy lines with CRLF or LF."""
        dns_replay("mta_sts_invalid")
        http_replay("mta_sts_invalid")
        result = check_mta_sts("valid.example.com")
        assert (result.present, result.mode, result.score) == (True, "enforce", 5)
        assert result.issues == []


def _no_proxy_answers(monkeypatch) -> None:
    """httpx goes through a proxy on a 127.0.0.1 port nobody listens on: every request
    ends in a real ConnectError, as when the host has no address to connect to."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    for variable in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(variable, f"http://127.0.0.1:{port}")
    for variable in ("ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(variable, raising=False)


class TestHTTPFailures:
    """Not measured is not zero, for HTTP as for DNS since 2026.47: a request that got no
    answer leaves its check not verified. An answer from the domain's server, a 404
    included, is a finding."""

    def test_an_mta_sts_policy_fetch_with_no_answer_is_not_verified(self, dns_replay, http_replay):
        dns_replay("mta_sts_invalid")
        http_replay("mta_sts_invalid")
        result = check_mta_sts("unreachable.example.com")
        assert "mta-sts.unreachable.example.com" in result.error
        assert any("MTA-STS not verified" in issue for issue in result.issues)
        assert not any("not accessible" in issue for issue in result.issues)

    def test_an_http_status_from_the_policy_host_is_a_finding(self, dns_replay, http_replay):
        dns_replay("ecosia_org")
        http_replay("ecosia_org")
        result = check_mta_sts("ecosia.org")
        assert result.error == ""
        assert any("HTTP 404" in issue for issue in result.issues)

    def test_a_policy_host_dns_does_not_know_is_a_finding(self, dns_replay, monkeypatch):
        """The connection fails, and mta-sts.<domain> is NXDOMAIN: no server could have
        answered, so that is what the domain publishes, not a failure of the scanner's network."""
        dns_replay("mta_sts_invalid")
        _no_proxy_answers(monkeypatch)
        result = check_mta_sts("no-host.example.com")
        assert result.error == ""
        assert result.score == 0
        assert any("mta-sts.no-host.example.com" in issue and "does not exist" in issue
                   for issue in result.issues)

    def test_a_connection_that_fails_to_a_host_that_exists_is_not_verified(self, dns_replay, monkeypatch):
        """example.com has addresses (recorded): a ConnectError to it says nothing about the domain."""
        dns_replay("bimi_example_com", "amplify_valimail_com_a")
        _no_proxy_answers(monkeypatch)
        result = check_bimi("example.com")
        assert "amplify.valimail.com" in result.error
        assert any("BIMI not verified" in issue for issue in result.issues)

    def test_a_bimi_logo_fetch_with_no_answer_is_not_verified(self, dns_replay, http_replay):
        dns_replay("bimi_example_com")
        http_replay("bimi_logo_unreachable")
        result = check_bimi("example.com")
        assert "amplify.valimail.com" in result.error
        assert result.score == 0
        assert not any("timeout or error" in issue for issue in result.issues)


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

    @pytest.mark.parametrize("case,said", [
        ("no-rua", "rua"),
        ("rua-no-scheme", "mailto: or https:"),
        ("two-records", "Multiple TLS-RPT records"),
    ])
    def test_a_record_senders_cannot_use_scores_nothing(self, dns_replay, case, said):
        """RFC 8460 §3: rua is required, its URIs are mailto: or https:, and with more than one
        v=TLSRPTv1 record senders assume the domain does not implement TLS-RPT. Each scored 3."""
        dns_replay("tls_rpt_invalid")
        result = check_tls_rpt(f"{case}.example.com")
        assert result.present is False
        assert result.score == 0
        assert any(said in issue for issue in result.issues)

    def test_rua_is_read_as_a_tag_not_as_the_last_rua_in_the_text(self, dns_replay):
        """rua=https://x.example/?rua=1; was read as rua='1', from the 'rua=' inside the URI."""
        dns_replay("tls_rpt_invalid")
        result = check_tls_rpt("rua-in-url.example.com")
        assert result.rua == "https://x.example/?rua=1"
        assert result.score == 3


# ─── DNS lookup failures ────────────────────────────────────────────────────

class TestDNSLookupFailure:
    """A lookup that got no answer (timeout, SERVFAIL) is not a record that is missing."""

    def test_dmarc_timeout_does_not_call_the_domain_spoofable(self, dns_replay):
        """A DNS timeout is not an NXDOMAIN: 'No DMARC record — spoofable' cannot be concluded from it."""
        dns_replay(silent=["_dmarc.example.com TXT"])
        result = check_dmarc("example.com")
        assert not any("spoofable" in issue for issue in result.issues)

    def test_spf_servfail_does_not_report_spf_missing(self, dns_replay):
        """SERVFAIL (NoNameservers) is not "no SPF record": the check stays not verified.

        dnssec-failed.org is signed wrong on purpose, so a validating resolver
        answers SERVFAIL for it: the answer recorded from 1.1.1.1.
        """
        dns_replay("dnssec_failed_org")
        result = check_spf("dnssec-failed.org")
        assert result.error
        assert not any("No SPF record" in issue for issue in result.issues)

    def test_dkim_timeout_on_one_selector_does_not_stop_the_others(self, dns_replay):
        """A selector that times out does not hide the key published under the next one."""
        dns_replay("archlinux_org", silent=["s1._domainkey.archlinux.org TXT"])
        result = check_dkim("archlinux.org", selectors=["s1", "dkim-ed25519"])
        assert result.present is True
        assert result.selector == "dkim-ed25519"
        assert not result.error

    def test_dkim_timeout_on_every_selector_does_not_report_dkim_missing(self, dns_replay):
        dns_replay(silent=["s1._domainkey.example.com TXT", "s2._domainkey.example.com TXT"])
        result = check_dkim("example.com", selectors=["s1", "s2"])
        assert result.error
        assert not any("No DKIM record" in issue for issue in result.issues)


# ─── Domain existence ────────────────────────────────────────────────────────

class TestDomainExists:

    def test_domain_without_tld_returns_false(self):
        result = domain_exists("apple")
        assert result is False

    def test_fqdn_with_trailing_dot_exists(self, dns_replay):
        """'example.com.' is a valid FQDN: with a positive DNS answer the domain exists."""
        dns_replay("example_com")
        assert domain_exists("example.com.") is True

    # A user reported asufc.sanita.fvg.it (Azienda sanitaria universitaria
    # Friuli Centrale) as "not existing, score 0/100": over a slow resolver the
    # A lookup timed out, domain_exists read the timeout as "no such domain",
    # and the check went on to offer asufc.com. One A query is enough to tell:
    # NXDOMAIN is about the name, whatever the type asked for.

    def test_a_name_with_an_address_exists(self, dns_replay):
        server = dns_replay("asufc_sanita_fvg_it_exists")
        assert domain_exists("asufc.sanita.fvg.it") is True
        assert server.queries == ["asufc.sanita.fvg.it. A"]

    def test_a_name_without_an_address_exists(self, dns_replay):
        """sanita.fvg.it has MX and TXT and no A: NOERROR with no answer is a
        name that exists, not one that does not."""
        server = dns_replay("asufc_sanita_fvg_it_exists")
        assert domain_exists("sanita.fvg.it") is True
        assert server.queries == ["sanita.fvg.it. A"]

    def test_a_name_that_does_not_exist(self, dns_replay):
        server = dns_replay("asufc_sanita_fvg_it_exists")
        assert domain_exists("mailradar-nxdomain-test.sanita.fvg.it") is False
        assert server.queries == ["mailradar-nxdomain-test.sanita.fvg.it. A"]

    def test_a_lookup_that_gets_no_answer_says_nothing_about_the_name(self, dns_replay):
        dns_replay("asufc_sanita_fvg_it_exists", silent=["asufc.sanita.fvg.it A"])
        with pytest.raises(DNSLookupError, match="asufc.sanita.fvg.it"):
            domain_exists("asufc.sanita.fvg.it")


def _long_domain(length: int) -> str:
    """A valid name under example.com, `length` characters long (labels of at most 63)."""
    labels, left = [], length - len(".example.com")
    while left > 0:
        size = min(63, left - 1 if left > 63 else left)
        labels.append("a" * size)
        left -= size + 1
    domain = ".".join(labels) + ".example.com"
    assert len(domain) == length
    return domain


class TestInvalidNames:
    """dnspython raises LabelTooLong, NameTooLong and IDNAException as DNSException: they
    became DNSLookupError, "DNS lookup failed", and the CLI said to try again or use
    another resolver, for a name no resolver can ever answer about."""

    @pytest.mark.parametrize("name,reason", [
        ("a" * 64 + ".example.com", "63 octets"),
        (".".join(["a" * 63] * 4) + ".example.com", "255 octets"),
        ("☃☃.example.com", "IDNA"),
    ])
    def test_domain_exists_says_the_name_is_not_valid(self, dns_replay, name, reason):
        from mailradar.checker import InvalidDomainError

        server = dns_replay()
        with pytest.raises(InvalidDomainError, match=reason) as raised:
            domain_exists(name)
        assert "not a valid domain name" in str(raised.value)
        assert "failed" not in str(raised.value)
        assert server.queries == []

    def test_a_check_on_a_name_that_is_not_valid_says_so(self, dns_replay):
        server = dns_replay()
        result = check_dmarc("a" * 64 + ".example.com")
        assert "not a valid domain name" in result.error
        assert not any("failed" in issue for issue in result.issues)
        assert server.queries == []

    def test_dkim_under_a_domain_too_long_for_any_selector(self, dns_replay):
        """240 characters: every <selector>._domainkey.<domain> passes 255 octets, so no key
        can be published there. That is an answer, not a lookup to try again for ever."""
        server = dns_replay()
        result = check_dkim(_long_domain(240))
        assert result.error == ""
        assert result.present is False
        assert any("No DKIM selector can be checked" in issue for issue in result.issues)
        assert server.queries == []

    def test_dmarc_of_a_domain_too_long_for_its_own_record_is_the_organizational_one(self, dns_replay):
        """_dmarc.<domain> cannot exist at 247 characters; example.com's record still applies."""
        dns_replay("example_com")
        result = check_dmarc(_long_domain(247))
        assert result.error == ""
        assert result.found_at == "example.com"
        assert result.policy == "reject"


class TestDomainVariants:

    def test_a_subdomain_gets_no_variants(self, dns_replay):
        """Keeping the first label and changing the rest turned the health
        authority's asufc.sanita.fvg.it into asufc.com, somebody else's domain."""
        server = dns_replay()
        assert find_domain_variants("mailradar-nxdomain-test.sanita.fvg.it") == []
        assert server.queries == []

    def test_a_variant_the_dns_does_not_answer_for_is_left_out(self, dns_replay):
        """asufc.com and asufc.co.uk exist (recorded); asufc.eu gets no answer:
        it cannot be offered, and the others still are."""
        dns_replay("asufc_variants", silent=["asufc.eu A"])
        assert find_domain_variants("asufc.it") == ["asufc.com", "asufc.co.uk"]


# ─── Full analysis ───────────────────────────────────────────────────────────

class TestAnalyzeDomain:

    def test_analyze_domain_excellent(self, dns_replay, http_replay):
        # startpage.com as recorded on 2026-10-07: DMARC p=reject with strict
        # alignment and both report addresses, SPF -all after its includes,
        # a 2048-bit DKIM key under `google`, no GPG key on any keyserver.
        # The 33 selectors recorded on 2026-10-09 add s1 (2048-bit) and s2, a
        # 1024-bit SendGrid key a receiver would verify a signature with: the
        # weakest published key is the posture, and it costs the GOOD grade.
        dns_replay("startpage_com", "startpage_com_dkim_selectors")
        http_replay("startpage_com", "startpage_com_keyservers_index")
        report = analyze_domain("startpage.com")

        assert report.domain == "startpage.com"
        assert report.dmarc.policy == "reject"
        assert report.spf.all_mechanism == "-all"
        assert report.dkim.keys == {"google": "2048-bit RSA", "s1": "2048-bit RSA", "s2": "1024-bit RSA"}
        assert (report.dkim.selector, report.dkim.key_bits) == ("s2", 1024)
        assert report.total_score == 74
        assert report.grade == "MODERATE"

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

    def test_domain_is_normalized_once_for_every_check(self, dns_replay, http_replay):
        """'Example.COM.' is analysed as 'example.com' by every check, GPG and the MTA-STS URL included."""
        dns_replay("example_com", "example_com_mta_sts", "example_com_dkim_more_selectors")
        proxy = http_replay("example_com", "example_com_mta_sts_404", "keyservers_example_com")
        report = analyze_domain("Example.COM.")
        assert report.domain == "example.com"
        # The keyservers are asked about security@example.com and nothing else:
        # that first contact already has a key on keyserver.ubuntu.com (recorded)
        assert [r for r in proxy.requests if r.startswith("GET ")] == [
            "GET https://mta-sts.example.com/.well-known/mta-sts.txt",
            "GET https://keys.openpgp.org/vks/v1/by-email/security@example.com",
            "GET https://keyserver.ubuntu.com/pks/lookup?op=index&search=security%40example.com&options=mr",
            "GET https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3BB547F4A09EDE1C40981268526A5BBFE98ED6E7&options=mr",
        ]
        assert report.gpg.uid == "security@example.com"

    def test_bimi_beside_a_dmarc_policy_that_does_not_enforce_earns_nothing(self, dns_replay, http_replay):
        """Mail clients show a BIMI logo only under DMARC quarantine or reject: with p=none
        the logo and its VMC are never displayed, and they scored 10 of 10 with no issue."""
        dns_replay("example_com", "example_com_dkim_more_selectors", "bimi_without_enforcement")
        http_replay("example_com", "keyservers_example_com", "bimi_logo")
        report = analyze_domain("example.com")
        assert report.dmarc.policy == "none"
        assert (report.bimi.vmc_present, report.bimi.svg_valid) == (True, True)
        assert report.bimi.score == 0
        assert any("quarantine or reject" in issue for issue in report.bimi.issues)

    def test_bimi_beside_dmarc_reject_keeps_its_points(self, dns_replay, http_replay):
        dns_replay("example_com", "example_com_dkim_more_selectors", "bimi_example_com")
        http_replay("example_com", "keyservers_example_com", "bimi_logo")
        report = analyze_domain("example.com")
        assert report.dmarc.policy == "reject"
        assert report.bimi.score == 10
        assert not any("quarantine or reject" in issue for issue in report.bimi.issues)

    def test_scoring_boundaries(self):
        """Test score boundary conditions."""
        result = DMARCResult()
        result.score = 0
        assert result.score == 0

        result.score = 50
        assert result.score == 50


# ─── Malformed / hostile DNS records ────────────────────────────────────────

class TestMalformedRecords:

    def test_non_utf8_txt_does_not_crash(self):
        rdata = MagicMock()
        rdata.strings = [b"v=spf1 \xff\xfe -all"]
        with patch('mailradar.checker.dns.resolver.resolve', return_value=[rdata]):
            result = check_spf("example.com")
        assert result.present is True
        assert result.all_mechanism == "-all"

    @pytest.mark.parametrize("pct", ["50%", "abc", "", "150", "-1"])
    def test_dmarc_invalid_pct_does_not_crash(self, pct):
        txt = f"v=DMARC1; p=reject; pct={pct}"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.present is True
        assert result.pct == 100
        assert any("Invalid DMARC pct" in i for i in result.issues)

    def test_dmarc_valid_pct_parsed(self):
        txt = "v=DMARC1; p=reject; pct=25"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.pct == 25
        assert not any("Invalid DMARC pct" in i for i in result.issues)

    def test_bimi_url_with_equals_not_truncated(self):
        txt = "v=BIMI1; l=https://example.com/logo.svg?v=2; a=https://example.com/vmc.pem"
        resp = MagicMock(status_code=200)
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
             patch('mailradar.checker.httpx.get', return_value=resp):
            result = check_bimi("example.com")
        assert result.svg_url == "https://example.com/logo.svg?v=2"


# ─── Score normalization ────────────────────────────────────────────────────

from mailradar.checker import MAX_RAW_SCORE, MAX_SCORES


def _mock_checks(**scores):
    """Patch every check_* to return a verified result with the given score.

    `error=""` says so: a MagicMock's own `error` is a truthy MagicMock, which
    reads as a lookup that got no answer and leaves the analysis without a score.
    `policy="reject"`: BIMI's points count only beside a DMARC policy that enforces.
    """
    from contextlib import ExitStack
    stack = ExitStack()
    for check in MAX_SCORES:
        target = "mailradar.gpg.lookup_gpg" if check == "gpg" else f"mailradar.checker.check_{check}"
        stack.enter_context(patch(
            target, return_value=MagicMock(score=scores.get(check, 0), issues=[], error="",
                                           present=True, policy="reject")
        ))
    return stack


class TestScoreNormalization:

    def test_max_scores_match_real_checks(self):
        """MAX_SCORES must reflect what a perfect configuration actually earns."""
        import base64

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        der = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key() \
            .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        dkim_2048 = f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"
        records = {
            "_dmarc.example.com": (
                "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; "
                "rua=mailto:a@example.com; ruf=mailto:f@example.com"
            ),
            "example.com": "v=spf1 -all",
            "default._domainkey.example.com": dkim_2048,
            "default._bimi.example.com": "v=BIMI1; l=https://example.com/l.svg; a=https://example.com/vmc.pem",
            "_mta-sts.example.com": "v=STSv1; id=1",
            "_smtp._tls.example.com": "v=TLSRPTv1; rua=mailto:tls@example.com",
        }

        def resolve(name, rtype):
            if name in records:
                return make_txt_answer([records[name]])
            raise dns.resolver.NXDOMAIN

        http = MagicMock(status_code=200, text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n")
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=resolve), \
             patch('mailradar.checker.httpx.get', return_value=http):
            assert check_dmarc("example.com").score == MAX_SCORES["dmarc"]
            assert check_spf("example.com").score == MAX_SCORES["spf"]
            assert check_dkim("example.com").score == MAX_SCORES["dkim"]
            assert check_bimi("example.com").score == MAX_SCORES["bimi"]
            assert check_mta_sts("example.com").score == MAX_SCORES["mta_sts"]
            assert check_tls_rpt("example.com").score == MAX_SCORES["tls_rpt"]

    def test_perfect_configuration_scores_exactly_100(self):
        with _mock_checks(**MAX_SCORES):
            report = analyze_domain("example.com")
        assert report.total_score == 100
        assert report.grade == "EXCELLENT"

    def test_nothing_configured_scores_0(self):
        with _mock_checks():
            report = analyze_domain("example.com")
        assert report.total_score == 0
        assert report.grade == "CRITICAL"

    def test_score_is_normalized(self):
        # Only DMARC perfect: 50 raw points out of MAX_RAW_SCORE
        with _mock_checks(dmarc=50):
            report = analyze_domain("example.com")
        assert report.total_score == round(50 * 100 / MAX_RAW_SCORE)

    def test_score_never_exceeds_100(self):
        with _mock_checks(**{k: v * 2 for k, v in MAX_SCORES.items()}):
            report = analyze_domain("example.com")
        assert report.total_score == 100


class TestNoScoreWithoutMeasure:
    """A check whose DNS lookup got no answer leaves the analysis without a score.

    Reported behind a company resolver: asufc.sanita.fvg.it came out 0/100
    CRITICAL. The resolver did not answer for the records, every check ended
    "not verified" and was counted as 0 points, so the total read as a
    measured bottom of the scale. From outside, the same domain scores 19.
    "Bad" and "could not tell" are different answers: the score is None and
    the grade N/A, and the report names what was not verified.
    """

    def test_an_unanswered_lookup_leaves_no_score(self, dns_replay, http_replay):
        dns_replay("example_com", "example_com_mta_sts", "example_com_dkim_more_selectors",
                   silent=["_dmarc.example.com TXT"])
        http_replay("example_com", "example_com_mta_sts_404", "keyservers_example_com")
        report = analyze_domain("example.com")
        assert report.dmarc.error
        assert report.total_score is None
        assert report.grade == "N/A"
        assert report.unverified == ["DMARC"]

    def test_every_check_unanswered_is_not_critical(self, dns_replay, http_replay):
        dns_replay("example_com", silent=[
            "_dmarc.example.com TXT", "example.com TXT", "_mta-sts.example.com TXT",
            "_smtp._tls.example.com TXT", "default._bimi.example.com TXT",
            *(f"{s}._domainkey.example.com TXT" for s in DKIM_SELECTORS),
        ])
        http_replay("example_com", "example_com_mta_sts_404", "keyservers_example_com")
        report = analyze_domain("example.com")
        assert report.total_score is None
        assert report.grade != "CRITICAL"
        assert report.unverified == ["DMARC", "SPF", "DKIM", "BIMI", "MTA-STS", "TLS-RPT"]

    def test_an_unanswered_policy_fetch_leaves_no_score(self, dns_replay, http_replay):
        """The same holds for HTTP: _mta-sts present and the policy fetch getting no answer
        (ConnectTimeout, a reset) graded MTA-STS 0 with "policy file not accessible"."""
        dns_replay("example_com", "example_com_mta_sts", "example_com_dkim_more_selectors")
        http_replay("example_com", "example_com_mta_sts_unreachable", "keyservers_example_com")
        report = analyze_domain("example.com")
        assert report.unverified == ["MTA-STS"]
        assert report.total_score is None
        assert not any("not accessible" in issue for issue in report.mta_sts.issues)

    def test_a_keyserver_that_does_not_answer_still_leaves_a_score(self, dns_replay, http_replay):
        """GPG is the exception, as for `report` and `send`: keys.openpgp.org allows one
        lookup a minute, and a batch would otherwise be all N/A. Its 5 points are the
        only ones a keyserver can withhold, and the check says it was not verified."""
        dns_replay("example_com", "example_com_dkim_more_selectors")
        http_replay("example_com", "keys_openpgp_org_example_com_contacts", "keyserver_ubuntu_example_com_no_answer")
        report = analyze_domain("example.com")
        assert report.gpg.error
        assert isinstance(report.total_score, int)
        assert report.unverified == []


class TestDKIMSelectors:
    """check_dkim against the DNS of real domains, recorded on 2026-10-09 (tests/replay.py)."""

    def test_proton_me_signs_under_the_protonmail_selectors(self, dns_replay):
        """proton.me publishes 2048-bit keys under protonmail and protonmail2 (recorded). None of the 17
        selectors tried until 2026-10-09 was one of them: `check proton.me` said "No DKIM record found with
        common selectors" and the law check cited GDPR art. 32 for a key that exists."""
        dns_replay("proton_me")
        result = check_dkim("proton.me")
        assert result.present is True
        assert result.selector == "protonmail"
        assert result.key_bits == 2048
        assert result.score == 15

    def test_the_weakest_published_key_is_the_posture_and_every_key_is_named(self, dns_replay):
        """polimi.it publishes a 1024-bit key under selector1 and a 2048-bit one under selector2 (recorded).
        A receiver verifies a signature made with either, so the weaker key is what the score measures;
        the issue names both, so the reader knows the 2048-bit one is already there."""
        dns_replay("polimi_it")
        result = check_dkim("polimi.it")
        assert result.present is True
        assert result.key_bits == 1024
        assert result.selector == "selector1"
        assert result.score == 10
        issue = next(issue for issue in result.issues if "1024" in issue)
        assert "selector1" in issue and "selector2" in issue and "2048" in issue

    def test_a_key_not_found_under_common_selectors_is_not_declared_absent(self, dns_replay):
        """amazon.it publishes none of the 33 common selectors (recorded) and signs its mail all the same,
        under selectors of its own: DNS cannot prove DKIM absent, and the issue must not say it is."""
        dns_replay("amazon_it")
        result = check_dkim("amazon.it")
        assert result.present is False
        assert result.score == 0
        issue = result.issues[0]
        assert "33 common selectors" in issue
        assert "custom selector" in issue
        assert "No DKIM record found" not in issue


class TestSPFRedirectWording:

    def test_the_all_verdict_names_the_redirect_it_comes_from(self, dns_replay):
        """gmail.com: "v=spf1 redirect=_spf.google.com", and the ~all is _spf.google.com's (recorded). The issue
        said "SPF uses ~all" under a record that shows no ~all at all."""
        dns_replay("gmail_com")
        result = check_spf("gmail.com")
        issue = next(issue for issue in result.issues if "~all" in issue)
        assert "redirect=_spf.google.com" in issue
