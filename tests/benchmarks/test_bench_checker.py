"""CodSpeed benchmarks for MailRadar checker."""
import pytest
from mailradar.checker import check_dmarc, check_spf, check_dkim, analyze_domain


@pytest.mark.benchmark
def test_bench_dmarc(benchmark):
    benchmark(check_dmarc, "maksimtech.com")


@pytest.mark.benchmark  
def test_bench_spf(benchmark):
    benchmark(check_spf, "maksimtech.com")


@pytest.mark.benchmark
def test_bench_dkim(benchmark):
    benchmark(check_dkim, "maksimtech.com")


@pytest.mark.benchmark
def test_bench_full_analysis(benchmark):
    benchmark(analyze_domain, "maksimtech.com")
