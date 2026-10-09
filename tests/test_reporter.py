"""Tests for report generation."""
from mailradar.checker import (
    BIMIResult,
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    SPFResult,
    TLSRPTResult,
)
from mailradar.reporter import generate_report


def make_report(domain="example.com", score=85, grade="GOOD") -> DomainReport:
    report = DomainReport()
    report.domain = domain
    report.total_score = score
    report.grade = grade
    report.dmarc = DMARCResult(present=True, policy="reject", pct=100,
                                adkim="s", aspf="s", rua=True, ruf=True,
                                raw="v=DMARC1; p=reject", score=50, issues=[])
    report.spf = SPFResult(present=True, all_mechanism="-all",
                           permissive=False, raw="v=spf1 -all", score=20, issues=[])
    report.dkim = DKIMResult(present=True, selector="default",
                             key_bits=2048, score=15, issues=[])
    report.bimi = BIMIResult(present=False, score=0,
                             issues=["No BIMI record configured"])
    report.mta_sts = MTASTSResult(present=False, score=0,
                                   issues=["No MTA-STS configured"])
    report.tls_rpt = TLSRPTResult(present=False, score=0,
                                   issues=["No TLS-RPT configured"])
    report.gpg = GPGResult(found=False, score=0,
                           issues=["No GPG public key found"])
    return report


class TestGenerateReport:

    def test_generate_report_italian(self):
        report = make_report()
        text = generate_report(report, lang="it",
                               sender_name="Test User",
                               sender_role="Analyst",
                               sender_org="TestOrg")
        assert "example.com" in text
        assert "Test User" in text
        assert "DMARC" in text

    def test_generate_report_english(self):
        report = make_report()
        text = generate_report(report, lang="en",
                               sender_name="Test User",
                               sender_role="Analyst",
                               sender_org="TestOrg")
        assert "example.com" in text
        assert "Test User" in text
        assert "DMARC" in text

    def test_generate_report_with_issues(self):
        report = make_report(score=35, grade="POOR")
        report.dmarc = DMARCResult(present=False, score=0,
                                    issues=["No DMARC record found — domain is spoofable"])
        text = generate_report(report, lang="it")
        assert "example.com" in text

    def test_generate_report_fallback_to_english(self):
        """Unknown language falls back to English."""
        report = make_report()
        text = generate_report(report, lang="xx")
        assert "example.com" in text
        assert "DMARC" in text


def _section(text: str, start: str) -> str:
    """The paragraph of `text` that begins with `start`."""
    tail = text.split(start, 1)[1]
    return tail.split("\n\n", 1)[0]


def _mta_sts_in_testing() -> DomainReport:
    report = make_report()
    report.mta_sts = MTASTSResult(present=True, mode="testing", score=2,
                                  issues=["MTA-STS in testing mode — upgrade to enforce"])
    return report


class TestMTASTSSection:
    """The report sent to the owner must not say 'Not configured' for a policy in testing mode."""

    def test_english_report_does_not_say_not_configured(self):
        text = generate_report(_mta_sts_in_testing(), lang="en")
        assert "Not configured" not in _section(text, "MTA-STS —")

    def test_italian_report_does_not_say_not_configured(self):
        text = generate_report(_mta_sts_in_testing(), lang="it")
        assert "Non configurato" not in _section(text, "MTA-STS —")


def _analysed(domain: str) -> DomainReport:
    """A report whose DMARC, SPF and DKIM are the checks' results on the DNS the test replays (no GPG, no HTTP)."""
    from mailradar.checker import check_dkim, check_dmarc, check_spf
    report = make_report(domain=domain)
    report.dmarc = check_dmarc(domain)
    report.spf = check_spf(domain)
    report.dkim = check_dkim(domain)
    return report


class TestReportSaysWhatWasFound:
    """The letter goes to the domain's owner: real DNS, recorded on 2026-10-09 (tests/replay.py)."""

    def test_no_spoofing_paragraph_for_a_domain_with_p_reject(self, dns_replay):
        """inps.it publishes p=reject (recorded); the letter told it that anyone can impersonate @inps.it."""
        dns_replay("inps_it")
        report = _analysed("inps.it")
        assert "p=none" not in generate_report(report, lang="it").split("RILEVANZA GDPR")[1]
        assert "p=none" not in generate_report(report, lang="en").split("GDPR RELEVANCE")[1]

    def test_spoofing_paragraph_stays_for_p_none(self, dns_replay):
        """pec.poste.it inherits p=none from poste.it (recorded)."""
        dns_replay("pec_poste_it", "pec_poste_it_dkim_selectors")
        report = _analysed("pec.poste.it")
        assert "p=none" in generate_report(report, lang="it").split("RILEVANZA GDPR")[1]
        assert "p=none" in generate_report(report, lang="en").split("GDPR RELEVANCE")[1]

    def test_dkim_not_found_is_not_written_as_not_configured(self, dns_replay):
        """amazon.it signs under selectors of its own (recorded): none of the 33 common ones answers."""
        dns_replay("amazon_it")
        report = _analysed("amazon.it")
        assert "Non configurato" not in _section(generate_report(report, lang="it"), "DKIM —")
        assert "Not configured" not in _section(generate_report(report, lang="en"), "DKIM —")
        assert "33" in _section(generate_report(report, lang="en"), "DKIM —")

    def test_every_dkim_key_found_is_named(self, dns_replay):
        """inps.it: 1024-bit under selector1, 2048-bit under selector2 (recorded)."""
        dns_replay("inps_it")
        report = _analysed("inps.it")
        for lang in ("it", "en"):
            section = _section(generate_report(report, lang=lang), "DKIM —")
            assert "selector1" in section and "1024" in section
            assert "selector2" in section and "2048" in section

    def test_no_run_of_blank_lines(self, dns_replay):
        """Template blocks left two to five empty lines between sections."""
        dns_replay("inps_it")
        report = _analysed("inps.it")
        for lang in ("it", "en"):
            assert "\n\n\n" not in generate_report(report, lang=lang)
