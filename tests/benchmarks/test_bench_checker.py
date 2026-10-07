"""CodSpeed benchmarks for MailRadar checker."""
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from mailradar.checker import analyze_domain, check_dkim, check_dmarc, check_spf


def make_txt_answer(strings):
    answers = []
    for s in strings:
        rdata = MagicMock()
        rdata.strings = [s.encode()]
        answers.append(rdata)
    return answers


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
def test_bench_spf(benchmark, dns_replay):
    # qwant.com as recorded (tests/fixtures/dns/qwant_com.json): one record
    # with one include, each name answered once from 127.0.0.1. Giving every
    # name the same record would time an include loop up to the 10-lookup
    # limit instead
    dns_replay("qwant_com")
    benchmark(check_spf, "qwant.com")


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
        elif "_domainkey" in name:
            return make_txt_answer([DKIM_TXT])
        elif name.startswith("example.com"):
            return make_txt_answer([SPF_TXT])
        raise dns.resolver.NXDOMAIN

    with patch('mailradar.checker.dns.resolver.resolve', side_effect=mock_resolve), \
         patch('mailradar.gpg.lookup_gpg', return_value=mock_gpg):
        benchmark(analyze_domain, "example.com")
