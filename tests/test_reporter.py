"""Tests for report generation."""
import pytest

from mailradar.checker import (
    BIMIResult,
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    MXResult,
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

    def test_an_unknown_language_is_refused(self):
        """It fell back to English, and the caller saved the letter as _xx.txt."""
        with pytest.raises(ValueError, match="it, en"):
            generate_report(make_report(), lang="xx")

    def test_a_missing_template_is_an_error_not_another_language(self, tmp_path, monkeypatch):
        """`except Exception` sent whatever went wrong with the Italian template to the English one."""
        import shutil

        from jinja2 import TemplateNotFound

        from mailradar import reporter
        shutil.copy(reporter.TEMPLATES_DIR / "report_en.j2", tmp_path / "report_en.j2")
        monkeypatch.setattr(reporter, "TEMPLATES_DIR", tmp_path)
        with pytest.raises(TemplateNotFound):
            generate_report(make_report(), lang="it")

    def test_the_language_is_read_whatever_its_case(self):
        assert generate_report(make_report(), lang="IT") == generate_report(make_report(), lang="it")


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


# ─── What the letter claims ──────────────────────────────────────────────────

GDPR_GAP = {"it": "lacuna documentabile", "en": "documentable gap"}


def _clean() -> DomainReport:
    """Nothing the letter calls a problem: strict DMARC, SPF -all, a 2048-bit key; BIMI, MTA-STS, TLS-RPT absent."""
    return make_report(score=90, grade="EXCELLENT")


class TestLetterClaims:

    def test_a_clean_domain_is_not_told_it_has_an_article_32_gap(self):
        """Owner's decision: the art. 32 paragraph only in a letter that lists actual problems."""
        for lang, gap in GDPR_GAP.items():
            assert gap not in generate_report(_clean(), lang=lang)

    def test_a_domain_with_a_problem_still_is(self):
        report = make_report(score=35, grade="POOR")
        report.dmarc = DMARCResult(present=False, issues=["No DMARC record found — domain is spoofable"])
        for lang, gap in GDPR_GAP.items():
            assert gap in generate_report(report, lang=lang)

    def test_softfail_under_reject_is_no_article_32_gap(self):
        """mailradar#141: with DMARC p=reject on every message, ~all is a choice
        (RFC 7489 §10.1), not a gap in security of processing. The issue itself
        stays in the letter until the January scoring change (#154)."""
        from mailradar.checker import SPFResult

        report = _clean()
        report.spf = SPFResult(present=True, all_mechanism="~all", permissive=True, score=10,
                               raw="v=spf1 include:_spf.example.net ~all",
                               issues=["SPF uses ~all (softfail) — consider -all (hardfail)"])
        report.dmarc = DMARCResult(present=True, policy="reject", pct=100, score=50,
                                   raw="v=DMARC1; p=reject")
        for lang, gap in GDPR_GAP.items():
            letter = generate_report(report, lang=lang)
            assert gap not in letter
            assert "~all" in letter

    def test_softfail_where_dmarc_does_not_enforce_still_is(self):
        from mailradar.checker import SPFResult

        report = _clean()
        report.spf = SPFResult(present=True, all_mechanism="~all", permissive=True, score=10,
                               issues=["SPF uses ~all (softfail) — consider -all (hardfail)"])
        report.dmarc = DMARCResult(present=True, policy="none", score=10, raw="v=DMARC1; p=none")
        for lang, gap in GDPR_GAP.items():
            assert gap in generate_report(report, lang=lang)

    def test_no_published_pgp_key_is_no_article_32_gap(self):
        """make_report has no GPG key: on its own that is a suggestion, not a gap."""
        report = _clean()
        assert not report.gpg.found
        for lang, gap in GDPR_GAP.items():
            assert gap not in generate_report(report, lang=lang)

    def test_a_malformed_ed25519_key_is_not_told_to_upgrade_to_rsa(self, dns_replay):
        """dkim_ed25519_malformed.json (derived): k=ed25519 with three bytes for a key."""
        from mailradar.checker import check_dkim
        dns_replay("dkim_ed25519_malformed")
        report = make_report()
        report.dkim = check_dkim("archlinux.org", selectors=["dkim-ed25519"])
        en = _section(generate_report(report, lang="en"), "DKIM —")
        it = _section(generate_report(report, lang="it"), "DKIM —")
        assert "RSA" not in en.split("Recommended:")[1].split("\n")[0]
        assert "RSA" not in it.split("Raccomandato:")[1].split("\n")[0]
        assert "malformed" in en.lower()
        assert "malformata" in it.lower()

    def test_a_declined_bimi_is_not_called_an_error_nor_corrected(self, dns_replay):
        """icloud.com publishes `v=BIMI1; l=; a=;` (recorded): how a domain says it does not take part."""
        from mailradar.checker import check_bimi
        dns_replay("icloud_com")
        report = make_report(domain="icloud.com")
        report.bimi = check_bimi("icloud.com")
        for lang, error in (("en", "with errors"), ("it", "con errori")):
            section = _section(generate_report(report, lang=lang), "BIMI/VMC —")
            assert error not in section
            assert "l=https://" not in section
            assert "v=BIMI1; l=; a=;" in section

    def test_an_incomplete_analysis_has_no_score_of_none(self):
        report = make_report(score=None, grade="N/A")
        for lang in ("it", "en"):
            assert "None/100" not in generate_report(report, lang=lang)


class TestSPFNotes:
    """SPFResult.notes: findings that are not problems (a range from an inner address, a redundant range,
    10 lookups of 10). Listed in the letter, never turning the section into "Action required"."""

    NOTE = "SPF ip4:192.0.2.98/27 is written from an address inside the range — it authorises all of 192.0.2.96/27"

    def _report(self) -> DomainReport:
        report = make_report()
        report.spf = SPFResult(present=True, all_mechanism="-all", raw="v=spf1 ip4:192.0.2.98/27 -all", score=20,
                               issues=[], notes=[self.NOTE])
        return report

    def test_a_note_is_written_under_spf(self):
        for lang, label in (("en", "Note:"), ("it", "Nota:")):
            section = _section(generate_report(self._report(), lang=lang), "SPF —")
            assert f"{label} {self.NOTE}" in section

    def test_a_note_does_not_make_the_section_an_action(self):
        en = generate_report(self._report(), lang="en")
        it = generate_report(self._report(), lang="it")
        assert _section(en, "SPF —").startswith(" ✅ Properly configured")
        assert _section(it, "SPF —").startswith(" ✅ Configurato correttamente")

    def test_a_note_is_not_an_article_32_gap(self):
        for lang, gap in GDPR_GAP.items():
            assert gap not in generate_report(self._report(), lang=lang)


class TestMXInTheLetter:
    """MXResult (#125): `check` printed the MX note and issue, the letter did not (#112).
    A null MX on a domain that sends mail is an issue (RFC 7505 §4.1, §4.2); no MX on such a
    domain is a note (RFC 5321 §5.1). Neither is scored, and neither is an article 32 gap."""

    NOTE = ("example.com sends mail but publishes no MX — replies and bounces go to its A/AAAA address, "
            "if any (RFC 5321 §5.1 implicit MX), and some spam filters score a From domain without MX")
    ISSUE = ("example.com publishes a null MX (it accepts no mail) yet sends mail — receivers may reject "
             "mail from it with 550 5.7.27, and no reply or bounce can reach it (RFC 7505 §4.1, §4.2)")

    def _with(self, mx: MXResult) -> DomainReport:
        report = make_report()
        report.mx = mx
        return report

    def test_a_null_mx_on_a_sending_domain_is_an_action_with_its_reason(self):
        report = self._with(MXResult(null=True, issues=[self.ISSUE]))
        for lang, head, reason in (("en", " ⚠️  Action required", "Reason:"),
                                   ("it", " ⚠️  Attenzione richiesta", "Motivo:")):
            section = _section(generate_report(report, lang=lang), "MX —")
            assert section.startswith(head), section
            assert f"{reason} {self.ISSUE}" in section
            assert "0 ." in section

    def test_no_mx_on_a_sending_domain_is_a_note_not_an_action(self):
        report = self._with(MXResult(notes=[self.NOTE]))
        for lang, label in (("en", "Note:"), ("it", "Nota:")):
            section = _section(generate_report(report, lang=lang), "MX —")
            assert section.startswith(" ℹ️"), section
            assert f"{label} {self.NOTE}" in section

    def test_nothing_is_said_when_there_is_nothing_to_say(self):
        """An MX present, a domain that sends nothing, or a lookup with no answer: no MX section."""
        for mx in (MXResult(hosts=["mx1.example.com."]), MXResult(), MXResult(error="timeout")):
            for lang in ("en", "it"):
                assert "MX —" not in generate_report(self._with(mx), lang=lang)

    def test_mx_is_not_an_article_32_gap(self):
        """Owner's decision: the art. 32 paragraph is for DMARC, SPF and DKIM problems."""
        for mx in (MXResult(null=True, issues=[self.ISSUE]), MXResult(notes=[self.NOTE])):
            for lang, gap in GDPR_GAP.items():
                assert gap not in generate_report(self._with(mx), lang=lang)
