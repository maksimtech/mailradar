"""
Tests for MailRadar checker module.
Uses mocks to avoid real DNS queries in CI.
"""
import pytest
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.exception
from mailradar.checker import (
    check_dmarc, check_spf, check_dkim, check_bimi,
    check_mta_sts, check_tls_rpt, analyze_domain,
    domain_exists, find_domain_variants,
    organizational_domain, dmarc_lookup_chain,
    DMARCResult, SPFResult, DKIMResult
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
        txt = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com; fo=1"
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


# ─── DMARC tree walk — RFC 7489 §6.6.3 ──────────────────────────────────────

def make_zone_resolver(zone: dict[str, list[str]], queried: list[str] = None):
    """Resolver mock: solo i nomi presenti in `zone` rispondono, gli altri
    sollevano NXDOMAIN. Ogni nome interrogato viene registrato in `queried`."""
    def resolve(name, rdtype="TXT", *args, **kwargs):
        key = str(name).rstrip(".")
        if queried is not None:
            queried.append(key)
        if key in zone:
            return make_txt_answer(zone[key])
        raise dns.resolver.NXDOMAIN
    return resolve


class TestOrganizationalDomain:

    @pytest.mark.parametrize("domain,expected", [
        ("asufc.sanita.fvg.it", "fvg.it"),
        ("sanita.fvg.it", "fvg.it"),
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


class TestDMARCLookupChain:

    def test_chain_multilevel_it_domain(self):
        assert dmarc_lookup_chain("asufc.sanita.fvg.it") == [
            "asufc.sanita.fvg.it",
            "sanita.fvg.it",
            "fvg.it",
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
        ("mail.example.co.uk", "co.uk"),
        ("mail.example.co.uk", "uk"),
        ("sub.domain.com", "com"),
    ])
    def test_chain_never_reaches_the_public_suffix(self, domain, forbidden):
        assert forbidden not in dmarc_lookup_chain(domain)


class TestCheckDMARCTreeWalk:

    def test_climbs_to_organizational_domain(self):
        """asufc.sanita.fvg.it senza record proprio → policy da fvg.it."""
        zone = {"_dmarc.fvg.it": ["v=DMARC1; p=reject; rua=mailto:r@fvg.it"]}
        queried = []
        with patch('mailradar.checker.dns.resolver.resolve',
                   side_effect=make_zone_resolver(zone, queried)):
            result = check_dmarc("asufc.sanita.fvg.it")
        assert result.present is True
        assert result.policy == "reject"
        assert result.found_at == "fvg.it"
        assert result.inherited is True
        assert queried == [
            "_dmarc.asufc.sanita.fvg.it",
            "_dmarc.sanita.fvg.it",
            "_dmarc.fvg.it",
        ]
        assert any("fvg.it" in issue for issue in result.issues)

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

    def test_spf_hardfail(self):
        txt = "v=spf1 include:spf.example.com -all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
            result = check_spf("example.com")
        assert result.present is True
        assert result.all_mechanism == "-all"
        assert result.permissive is False
        assert result.score == 20
        assert result.issues == []

    def test_spf_softfail(self):
        txt = "v=spf1 include:spf.example.com ~all"
        with patch('mailradar.checker.dns.resolver.resolve', return_value=make_txt_answer([txt])):
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


# ─── DKIM ───────────────────────────────────────────────────────────────────

class TestCheckDKIM:

    def test_dkim_2048(self):
        # Chiave RSA 2048-bit reale (troncata per il test)
        key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6EYQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvxDKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
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
        key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7fmTaeGQi0HcKC1r+aVWwlPSKMjLFiUiCnkp2xGXh8Bk0r9qeMJkCwOUv1gaSfBRbUbvHyC0lBhWEFQJO6qqc+9k7rWMmXEZ0g6DfnQaTHGY2rNtVbZ6BKzHpFGi7XHJ8GS5yzZ7pGilWmqX/zYvKqxEJoKPX3nAsTbxjwIDAQAB"
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


# ─── Full analysis ───────────────────────────────────────────────────────────

class TestAnalyzeDomain:

    def test_analyze_domain_excellent(self):
        dmarc_txt = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com"
        spf_txt = "v=spf1 include:spf.example.com -all"
        dkim_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6EYQRvy+c9jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvxDKb7QzNaUUuO79SBMMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38/DBWGjbykiN8iFrlwYwGanrH25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
        dkim_txt = f"v=DKIM1; t=s; p={dkim_key}"

        def mock_resolve(name, rtype):
            if "_dmarc" in name:
                return make_txt_answer([dmarc_txt])
            elif "_domainkey" in name:
                return make_txt_answer([dkim_txt])
            elif "_mta-sts" in name:
                raise dns.resolver.NXDOMAIN
            elif "_smtp._tls" in name:
                raise dns.resolver.NXDOMAIN
            elif "default._bimi" in name:
                raise dns.resolver.NXDOMAIN
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

from mailradar.checker import MAX_SCORES, MAX_RAW_SCORE


def _mock_checks(**scores):
    """Patch every check_* to return a result with the given score."""
    from contextlib import ExitStack
    stack = ExitStack()
    for check in MAX_SCORES:
        if check == "gpg":
            target = "mailradar.gpg.lookup_gpg"
        else:
            target = f"mailradar.checker.check_{check}"
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
            "_dmarc.example.com": "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:a@example.com; ruf=mailto:f@example.com",
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
