"""
Tests for MailRadar checker module.
Uses mocks to avoid real DNS queries in CI.
"""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mailradar.checker import (
    DMARCResult,
    SPFResult,
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
    organizational_domain,
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
        """RFC 7489 §6.4 (ABNF): "reject" is a case-insensitive literal, p=REJECT is p=reject."""
        txt = (
            "v=DMARC1; p=REJECT; pct=100; adkim=S; aspf=S; "
            "rua=mailto:a@example.com; ruf=mailto:b@example.com"
        )
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.policy.lower() == "reject"
        assert result.score == 50

    def test_multiple_dmarc_records_apply_no_policy(self):
        """RFC 7489 §6.6.3: with more than one DMARC record, policy discovery ends with no policy."""
        txts = ["v=DMARC1; p=reject", "v=DMARC1; p=none"]
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer(txts)):
            result = check_dmarc("example.com")
        assert result.score == 0
        assert any("multiple" in issue.lower() for issue in result.issues)

    def test_dmarc_version_tag_allows_spaces_around_equals(self):
        """RFC 7489 §6.4: dmarc-version = "v" *WSP "=" *WSP "DMARC1", so 'v = DMARC1' is valid."""
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer(["v = DMARC1; p=reject"])):
            result = check_dmarc("example.com")
        assert result.present is True
        assert result.policy == "reject"

    def test_empty_rua_does_not_count_as_reports_configured(self):
        """RFC 7489 §6.4: rua needs at least one URI; an empty 'rua=' turns no aggregate reports on."""
        txt = "v=DMARC1; p=reject; rua=; ruf= "
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_dmarc("example.com")
        assert result.rua is False
        assert result.ruf is False


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

    def test_climbs_to_organizational_domain(self):
        """asufc.sanita.fvg.it with no record of its own -> policy from sanita.fvg.it,
        where the real one is published (_dmarc.fvg.it is NXDOMAIN, checked 2026-10-07)."""
        zone = {"_dmarc.sanita.fvg.it": ["v=DMARC1; p=reject; rua=mailto:r@sanita.fvg.it"]}
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("asufc.sanita.fvg.it")
        assert result.present is True
        assert result.policy == "reject"
        assert result.found_at == "sanita.fvg.it"
        assert result.inherited is True
        assert queried == [
            "_dmarc.asufc.sanita.fvg.it",
            "_dmarc.sanita.fvg.it",
        ]
        assert any("sanita.fvg.it" in issue for issue in result.issues)

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

# What `include:spf.example.com` finds at that name
SPF_INCLUDED = "v=spf1 ip4:192.0.2.0/24 -all"


class TestCheckSPF:

    def test_spf_hardfail(self):
        txt = "v=spf1 include:spf.example.com -all"
        # Only the names asked about answer: a mock giving every name this record
        # makes the include include itself, a loop that is a permerror (RFC 7208 §4.6.4)
        zone = {"example.com": [txt], "spf.example.com": [SPF_INCLUDED]}
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)):
            result = check_spf("example.com")
        assert result.present is True
        assert result.all_mechanism == "-all"
        assert result.permissive is False
        assert result.score == 20
        assert result.issues == []

    def test_spf_softfail(self):
        txt = "v=spf1 include:spf.example.com ~all"
        # Only the names asked about answer: a mock giving every name this record
        # makes the include include itself, a loop that is a permerror (RFC 7208 §4.6.4)
        zone = {"example.com": [txt], "spf.example.com": [SPF_INCLUDED]}
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)):
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

    def test_bare_all_is_plus_all(self):
        """RFC 7208 §4.6.2: 'all' with no qualifier is '+all', a pass for anyone."""
        result = check_spf_in({"example.com": ["v=spf1 mx all"]})
        assert result.permissive is True
        assert result.score == 0

    def test_dash_all_inside_a_host_name_is_not_a_hardfail(self):
        """'-all' inside 'include:spf-all.example.net' is not the all mechanism: the final ~all is."""
        result = check_spf_in({"example.com": ["v=spf1 include:spf-all.example.net ~all"]})
        assert result.all_mechanism == "~all"
        assert result.score == 10

    def test_mechanism_names_are_case_insensitive(self):
        """RFC 7208 §4.6.1: mechanism names are case-insensitive, '-ALL' is a hardfail."""
        result = check_spf_in({"example.com": ["v=spf1 mx -ALL"]})
        assert result.all_mechanism == "-all"
        assert result.score == 20

    def test_redirect_follows_the_target_record(self):
        """RFC 7208 §6.1: with redirect= the target's record decides (gmail.com uses redirect alone)."""
        result = check_spf_in({
            "example.com": ["v=spf1 redirect=_spf.example.net"],
            "_spf.example.net": ["v=spf1 ip4:192.0.2.0/24 -all"],
        })
        assert result.all_mechanism == "-all"
        assert result.score == 20

    def test_redirect_to_a_name_without_spf_is_a_permerror(self):
        """RFC 7208 §6.1: if the redirect= domain has no SPF record, the result is a permerror."""
        result = check_spf_in({"example.com": ["v=spf1 redirect=_spf.example.net"]})
        assert result.permerror is True
        assert result.score == 0

    def test_no_all_and_no_redirect_is_neutral_and_reported(self):
        """RFC 7208 §4.7: with neither 'all' nor 'redirect=' the default result is neutral, and is said."""
        result = check_spf_in({"example.com": ["v=spf1 mx"]})
        assert result.permissive is True
        assert any("neutral" in issue.lower() for issue in result.issues)

    def test_multiple_spf_records_are_a_permerror(self):
        """RFC 7208 §4.5: more than one v=spf1 record on the same name is a permerror, no full score."""
        result = check_spf_in({"example.com": ["v=spf1 -all", "v=spf1 include:x.example.net -all"]})
        assert result.score == 0
        assert any("multiple" in issue.lower() or "permerror" in issue.lower() for issue in result.issues)

    def test_more_than_10_dns_lookups_is_a_permerror(self):
        """RFC 7208 §4.6.4: more than 10 mechanisms that need a DNS lookup is a permerror."""
        includes = " ".join(f"include:i{n}.example.net" for n in range(1, 12))
        zone = {"example.com": [f"v=spf1 {includes} -all"]}
        zone.update({f"i{n}.example.net": ["v=spf1 ip4:192.0.2.1 -all"] for n in range(1, 12)})
        result = check_spf_in(zone)
        assert result.score < 20
        assert any("lookup" in issue.lower() for issue in result.issues)

    def test_exactly_10_dns_lookups_is_still_valid(self):
        """The RFC 7208 §4.6.4 boundary: the limit is "more than 10", 10 lookups (nested ones included) pass."""
        includes = " ".join(f"include:i{n}.example.net" for n in range(1, 9))
        zone = {"example.com": [f"v=spf1 mx {includes} -all"],
                "i8.example.net": ["v=spf1 a -all"]}
        zone.update({f"i{n}.example.net": ["v=spf1 ip4:192.0.2.1 -all"] for n in range(1, 8)})
        result = check_spf_in(zone)
        assert result.permerror is False
        assert result.score == 20

    def test_include_loop_is_a_permerror(self):
        """An include that comes back to itself runs out of lookups: a permerror, not a 20-point hardfail."""
        result = check_spf_in({"example.com": ["v=spf1 include:example.com -all"]})
        assert result.permerror is True
        assert result.score == 0

    def test_plus_all_does_not_raise_the_plus_a_or_plus_mx_warning(self):
        """'+all' holds the substring '+a': it must not raise the '+a or +mx' warning."""
        result = check_spf_in({"example.com": ["v=spf1 ip4:192.0.2.1 +all"]})
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


def check_spf_in(zone: dict[str, list[str]]):
    """check_spf("example.com") against a DNS where only the names in `zone` answer."""
    with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)):
        return check_spf("example.com")


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

    def test_dkim_1024(self):
        # Chiave 1024-bit simulata — lunghezza base64 corta
        key = (
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7fmTaeGQi0HcKC1r+aVWwlPSKMjLFiUiCnkp2xGXh8Bk0r9qeMJkCwOUv1gaSfBRb"
            "UbvHyC0lBhWEFQJO6qqc+9k7rWMmXEZ0g6DfnQaTHGY2rNtVbZ6BKzHpFGi7XHJ8GS5yzZ7pGilWmqX/zYvKqxEJoKPX3nAsTbxjwIDA"
            "QAB"
        )
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

    def test_ed25519_key_is_not_weak(self):
        """RFC 8463: an Ed25519 key (32 raw bytes) is strong, not a 512-bit RSA key."""
        result = check_dkim_record(f"v=DKIM1; k=ed25519; p={ED25519_KEY}")
        assert result.present is True
        assert not any("weak" in issue.lower() for issue in result.issues)
        assert result.score == 15

    def test_malformed_ed25519_key_does_not_get_the_full_score(self):
        result = check_dkim_record("v=DKIM1; k=ed25519; p=AAAA")
        assert result.score < 15
        assert result.issues

    def test_empty_p_is_a_revoked_key_not_a_weak_one(self):
        """RFC 6376 §3.6.1: an empty 'p=' means the key is revoked (it was a known limitation in the README)."""
        result = check_dkim_record("v=DKIM1; k=rsa; p=")
        assert not any("weak" in issue.lower() for issue in result.issues)
        assert any("revok" in issue.lower() for issue in result.issues)

    def test_revoked_selector_does_not_hide_the_active_key(self):
        """Rotation: the old, revoked selector does not count when another one has the active key."""
        zone = {"s1._domainkey.example.com": ["v=DKIM1; p="],
                "s2._domainkey.example.com": [f"v=DKIM1; k=ed25519; p={ED25519_KEY}"]}
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)):
            result = check_dkim("example.com", selectors=["s1", "s2"])
        assert result.selector == "s2"
        assert not any("revok" in issue.lower() for issue in result.issues)


# A valid Ed25519 public key as DKIM publishes it (RFC 8463): 32 raw bytes, base64
ED25519_KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="


def check_dkim_record(record: str):
    """check_dkim on example.com with `record` published under the selector `default`."""
    zone = {"default._domainkey.example.com": [record]}
    with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)):
        return check_dkim("example.com", selectors=["default"])


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

    def test_bimi_does_not_fetch_a_url_that_is_not_https(self):
        """BIMI requires https for l=; an http URL into the internal network must not be fetched (SSRF)."""
        txt = "v=BIMI1; l=http://127.0.0.1:8080/admin; a="
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
             patch('mailradar.checker.httpx.get', return_value=MagicMock(status_code=200)) as get:
            result = check_bimi("example.com")
        get.assert_not_called()
        assert result.svg_valid is False

    def test_bimi_does_not_fetch_https_from_an_internal_ip_literal(self):
        """Even over https, a loopback, private or link-local IP literal is not contacted."""
        for url in ("https://127.0.0.1/logo.svg", "https://[::1]/logo.svg", "https://10.0.0.5/l.svg",
                    "https://169.254.169.254/latest/meta-data/"):
            txt = f"v=BIMI1; l={url}; a="
            with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])), \
                 patch('mailradar.checker.httpx.get', return_value=MagicMock(status_code=200)) as get:
                result = check_bimi("example.com")
            get.assert_not_called()
            assert result.svg_valid is False, url

    def test_bimi_declination_record_scores_nothing(self):
        """BIMI: 'v=BIMI1; l=; a=;' declines explicitly, it is not a 3-point BIMI without a VMC."""
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer(["v=BIMI1; l=; a=;"])):
            result = check_bimi("example.com")
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

    def test_mta_sts_unreachable_policy_raises_an_issue(self):
        """_mta-sts record present but the policy answers HTTP 404: MTA-STS does not work, and is said."""
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer(["v=STSv1; id=20260101"])), \
             patch('mailradar.checker.httpx.get', return_value=MagicMock(status_code=404, text="")):
            result = check_mta_sts("example.com")
        assert result.issues, "no issue raised with the policy file answering 404"

    def test_mta_sts_mode_none_is_not_an_unknown_mode(self):
        """RFC 8461 §5: 'none' is a valid mode (the policy withdrawn), not 'mode unknown'."""
        policy = MagicMock(status_code=200, text="version: STSv1\nmode: none\nmax_age: 86400\n")
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer(["v=STSv1; id=20260101"])), \
             patch('mailradar.checker.httpx.get', return_value=policy):
            result = check_mta_sts("example.com")
        assert result.mode == "none"
        assert result.score == 0
        assert not any("unknown" in issue for issue in result.issues)
        assert any("none" in issue for issue in result.issues)


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


# ─── DNS lookup failures ────────────────────────────────────────────────────

class TestDNSLookupFailure:
    """A lookup that got no answer (timeout, SERVFAIL) is not a record that is missing."""

    def test_dmarc_timeout_does_not_call_the_domain_spoofable(self):
        """A DNS timeout is not an NXDOMAIN: 'No DMARC record — spoofable' cannot be concluded from it."""
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.exception.Timeout()):
            result = check_dmarc("example.com")
        assert not any("spoofable" in issue for issue in result.issues)

    def test_spf_servfail_does_not_report_spf_missing(self):
        """SERVFAIL (NoNameservers) is not "no SPF record": the check stays not verified."""
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.resolver.NoNameservers()):
            result = check_spf("example.com")
        assert result.error
        assert not any("No SPF record" in issue for issue in result.issues)

    def test_dkim_timeout_on_one_selector_does_not_stop_the_others(self):
        """A selector that times out does not hide the key published under the next one."""
        answer = make_zone_resolver({"s2._domainkey.example.com": [f"v=DKIM1; k=ed25519; p={ED25519_KEY}"]})

        def resolve(name, rdtype="TXT", *args, **kwargs):
            if str(name).startswith("s1."):
                raise dns.exception.Timeout()
            return answer(name, rdtype)

        with patch('mailradar.checker.dns.resolver.resolve', side_effect=resolve):
            result = check_dkim("example.com", selectors=["s1", "s2"])
        assert result.present is True
        assert result.selector == "s2"
        assert not result.error

    def test_dkim_timeout_on_every_selector_does_not_report_dkim_missing(self):
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=dns.exception.Timeout()):
            result = check_dkim("example.com", selectors=["s1", "s2"])
        assert result.error
        assert not any("No DKIM record" in issue for issue in result.issues)


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

    def test_fqdn_with_trailing_dot_exists(self):
        """'example.com.' is a valid FQDN: with a positive DNS answer the domain exists."""
        with patch('mailradar.checker.dns.resolver.resolve', return_value=[MagicMock()]):
            assert domain_exists("example.com.") is True


# ─── Full analysis ───────────────────────────────────────────────────────────

class TestAnalyzeDomain:

    def test_analyze_domain_excellent(self):
        dmarc_txt = (
            "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com"
        )
        spf_txt = "v=spf1 include:spf.example.com -all"
        dkim_key = (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6E"
            "YQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvx"
            "DKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38"
            "/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
        )
        dkim_txt = f"v=DKIM1; t=s; p={dkim_key}"

        def mock_resolve(name, rtype):
            if "_dmarc" in name:
                return make_txt_answer([dmarc_txt])
            elif "_domainkey" in name:
                return make_txt_answer([dkim_txt])
            elif "_mta-sts" in name or "_smtp._tls" in name or "default._bimi" in name:
                raise dns.resolver.NXDOMAIN
            elif name == "spf.example.com":
                # The included record, not spf_txt again: that would be an include loop
                return make_txt_answer([SPF_INCLUDED])
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

    def test_domain_is_normalized_once_for_every_check(self):
        """'Example.COM.' is analysed as 'example.com' by every check, GPG and the MTA-STS URL included."""
        from mailradar.gpg import GPGResult
        zone = {"_mta-sts.example.com": ["v=STSv1; id=1"]}
        with patch('mailradar.checker.dns.resolver.resolve', side_effect=make_zone_resolver(zone)), \
             patch('mailradar.checker.httpx.get', return_value=MagicMock(status_code=404)) as get, \
             patch('mailradar.gpg.lookup_gpg', return_value=GPGResult()) as gpg:
            report = analyze_domain("Example.COM.")
        assert report.domain == "example.com"
        gpg.assert_called_once_with("example.com")
        assert get.call_args.args[0] == "https://mta-sts.example.com/.well-known/mta-sts.txt"

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
    """Patch every check_* to return a result with the given score."""
    from contextlib import ExitStack
    stack = ExitStack()
    for check in MAX_SCORES:
        target = "mailradar.gpg.lookup_gpg" if check == "gpg" else f"mailradar.checker.check_{check}"
        stack.enter_context(patch(
            target, return_value=MagicMock(score=scores.get(check, 0), issues=[])
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

        http = MagicMock(status_code=200, text="version: STSv1\nmode: enforce\n")
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
