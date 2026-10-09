"""CodSpeed benchmarks for MailRadar checker."""
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from mailradar.checker import (
    SPFResult,
    _apply_spf_verdict,
    _is_spf,
    _spf_all,
    _spf_terms,
    analyze_domain,
    check_dkim,
    check_dmarc,
)
from tests.replay import recorded_txt


class _TXT:
    """One TXT rdata as dnspython hands it over: the `strings` attribute is all
    _query_txt reads. A plain object, so the benchmark times mailradar and not
    the construction of a MagicMock per answer."""

    __slots__ = ("strings",)

    def __init__(self, text: str):
        self.strings = [text.encode()]


def make_txt_answer(strings):
    return [_TXT(s) for s in strings]


DMARC_TXT = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com"
SPF_TXT = "v=spf1 include:spf.example.com -all"
DKIM_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwGFMFCN431WpLoJNLzE1qfqj2jjXsKiMps8Nafya4wg3jmchjT2qlejmUW6EYQRvy+c9"
    "jHskfk6+eIFpeLcFnBg/X3AMVbxazFqatYDoRY08/eCOPF5LzpBgcclDac6Nx+kuaFEN8e0oujGWd66H+v9Q8URN2h21cSvxDKb7QzNaUUuO79SB"
    "MMQdZE0sG3KHwKnFihc3FWRqPrxx5t9y8F0RKMDG2psAlWdE6U4yMcwNqpVLpFappxFls0EjjXnebOkmvNqXlp38/DBWGjbykiN8iFrlwYwGanrH"
    "25EZ/DpWQuucBR+7zlKNiAz8H1QSFqz+jwcW/MNXwTnNClI6XwIDAQAB"
)
DKIM_TXT = f"v=DKIM1; t=s; p={DKIM_KEY}"


@pytest.mark.codspeed
def test_bench_dmarc(benchmark):
    with patch('mailradar.checker.dns.resolver.resolve',
               return_value=make_txt_answer([DMARC_TXT])):
        benchmark(check_dmarc, "example.com")


@pytest.mark.codspeed
def test_bench_spf(benchmark):
    # The evaluation of qwant.com's record as recorded (tests/fixtures/dns/
    # qwant_com.json): terms, `all` and verdict. The DNS walk stays out on
    # purpose: through the replay server it would time UDP round-trips to
    # 127.0.0.1, not this code
    (record,) = [r for r in recorded_txt("qwant_com", "qwant.com") if _is_spf(r)]

    def evaluate() -> SPFResult:
        result = SPFResult(present=True, raw=record)
        terms = _spf_terms(record)
        result.all_mechanism = _spf_all(terms)
        _apply_spf_verdict(result, terms)
        return result

    assert benchmark(evaluate).all_mechanism == "-all"


@pytest.mark.codspeed
def test_bench_dkim(benchmark):
    def mock_resolve(name, rtype):
        if "_domainkey" in name:
            return make_txt_answer([DKIM_TXT])
        raise dns.resolver.NXDOMAIN

    with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve):
        benchmark(check_dkim, "example.com", selectors=["default"])


@pytest.mark.codspeed
def test_bench_full_analysis(benchmark):
    mock_gpg = MagicMock()
    mock_gpg.found = False
    mock_gpg.score = 0
    mock_gpg.issues = []

    def mock_resolve(name, rtype):
        if "_dmarc" in name:
            return make_txt_answer([DMARC_TXT])
        elif name == "selector1._domainkey.example.com":
            # One published selector, as a real domain has; the other 32 of
            # DKIM_SELECTORS are NXDOMAIN, which is what check_dkim meets in the field
            return make_txt_answer([DKIM_TXT])
        elif name.startswith("example.com"):
            return make_txt_answer([SPF_TXT])
        raise dns.resolver.NXDOMAIN

    with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve), \
         patch('mailradar.gpg.lookup_gpg', return_value=mock_gpg):
        benchmark(analyze_domain, "example.com")
