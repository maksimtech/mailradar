"""
MX records of the analysed domain: where replies and bounces go.

Not scored. A domain that sends mail and publishes no MX gets a note: with no
MX, mail to it goes to its own address (RFC 5321 §5.1, implicit MX), and spam
filters score a From domain without one. A domain that sends mail and
publishes a null MX gets an issue: RFC 7505 §4.2 says such a domain SHOULD NOT
publish one, and §4.1 gives receivers a code to reject its mail with.
A domain that sends no mail (`v=spf1 -all`, no DKIM key) gets nothing.
"""

from mailradar import cli
from mailradar.checker import MAX_SCORES, DKIMResult, DomainReport, MXResult, SPFResult, _mx_findings, check_mx
from tests.test_cli_table import _lines

SENDS = SPFResult(present=True, raw="v=spf1 include:amazonses.com -all", score=20)
SENDS_NOTHING = SPFResult(present=True, raw="v=spf1 -all", score=20)


class TestCheckMX:
    def test_no_mx_is_no_hosts_and_not_null(self, dns_replay):
        dns_replay("mx_kinds")
        assert check_mx("no-mx.example.com") == MXResult()

    def test_a_null_mx_is_recognised(self, dns_replay):
        dns_replay("mx_kinds")
        result = check_mx("null-mx.example.com")
        assert (result.null, result.hosts, result.error) == (True, [], "")

    def test_hosts_come_in_preference_order(self, dns_replay):
        dns_replay("mx_kinds")
        result = check_mx("with-mx.example.com")
        assert result.hosts == ["mx1.example.com.", "mx2.example.com."]
        assert not result.null

    def test_an_unanswered_lookup_is_not_no_mx(self, dns_replay):
        dns_replay("mx_kinds", silent=["no-mx.example.com MX"])
        result = check_mx("no-mx.example.com")
        assert result.error
        assert (result.hosts, result.null) == ([], False)


class TestFindings:
    def test_a_sending_domain_without_mx_gets_a_note(self):
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult())
        _mx_findings(report)
        assert report.mx.issues == []
        [note] = report.mx.notes
        assert "publishes no MX" in note and "RFC 5321 §5.1" in note

    def test_dkim_alone_makes_a_domain_a_sender(self):
        report = DomainReport(domain="example.com", dkim=DKIMResult(present=True, key_bits=2048), mx=MXResult())
        _mx_findings(report)
        assert len(report.mx.notes) == 1

    def test_a_sending_domain_with_a_null_mx_gets_an_issue(self):
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult(null=True))
        _mx_findings(report)
        assert report.mx.notes == []
        [issue] = report.mx.issues
        assert "null MX" in issue and "550 5.7.27" in issue and "RFC 7505" in issue

    def test_a_domain_that_sends_nothing_gets_nothing(self):
        for mx in (MXResult(), MXResult(null=True)):
            report = DomainReport(domain="example.com", spf=SENDS_NOTHING, mx=mx)
            _mx_findings(report)
            assert (report.mx.issues, report.mx.notes) == ([], [])

    def test_no_spf_and_no_dkim_gets_nothing(self):
        report = DomainReport(domain="example.com", mx=MXResult())
        _mx_findings(report)
        assert (report.mx.issues, report.mx.notes) == ([], [])

    def test_a_domain_with_mx_gets_nothing(self):
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult(hosts=["mx1.example.com."]))
        _mx_findings(report)
        assert (report.mx.issues, report.mx.notes) == ([], [])

    def test_an_unanswered_lookup_gets_nothing(self):
        """Not measured is not "no MX"."""
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult(error="timeout"))
        _mx_findings(report)
        assert (report.mx.issues, report.mx.notes) == ([], [])

    def test_no_points_either_way(self):
        assert "mx" not in MAX_SCORES


class TestPrinted:
    def test_the_note_is_printed_with_the_notes(self, monkeypatch):
        note = "example.com sends mail but publishes no MX"
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult(notes=[note]))
        out = "\n".join(_lines(report, monkeypatch))
        assert "Issues found" not in out
        assert "Notes" in out and note in out

    def test_the_issue_is_printed_with_the_issues(self, monkeypatch):
        issue = "example.com publishes a null MX (it accepts no mail) yet sends mail"
        report = DomainReport(domain="example.com", spf=SENDS, mx=MXResult(null=True, issues=[issue]))
        out = "\n".join(_lines(report, monkeypatch))
        assert "Issues found" in out and issue in out

    def test_a_failed_mx_lookup_is_not_among_the_unverified_checks(self):
        report = DomainReport(domain="example.com", mx=MXResult(error="timeout"))
        assert report.unverified == []
        assert cli._unverified(report) == []
