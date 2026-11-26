"""DANE for inbound SMTP (RFC 7672), and what the transport finding may say about it (mailradar#149).

`check infomaniak.com` reported "MTA-STS missing: TLS not mandatory on delivery"
and cited GDPR art. 32(1)(a), for a domain whose MX publishes a DNSSEC-secure
TLSA record: for every sender that implements DANE (Postfix, Exim, Microsoft
365 outbound) TLS is mandatory and the certificate is checked against DNS.

The scope agreed for 7 December (comment on #149, 2026-11-22):

- every MX with a TLSA record whose answer carries AD: the finding drops art.
  32 and a note says for whom TLS is mandatory, and that senders without DANE
  (Gmail among them) still need MTA-STS;
- a TLSA record without AD: the finding stays, and says the record is published
  but not validated, so senders ignore it. Dropping art. 32 for it would be a
  false reassurance, the opposite mistake;
- the score does not change. Which resolver to trust for AD, and points for
  DANE, are #155.

The answers were recorded from 1.1.1.1 with the AD bit asked for
(tests/fixtures/dns/dane_*.json); the replay server returns their flags as
recorded.
"""
from __future__ import annotations

from mailradar.checker import (
    DANEResult,
    DKIMResult,
    DMARCResult,
    DomainReport,
    GPGResult,
    MTASTSResult,
    MXResult,
    SPFResult,
    check_dane,
)
from mailradar.law_checker import findings_of, notes_of

INFOMANIAK_MX = MXResult(hosts=["mta-gw.infomaniak.ch."])
GMAIL_MX = MXResult(hosts=[
    "gmail-smtp-in.l.google.com.", "alt1.gmail-smtp-in.l.google.com.", "alt2.gmail-smtp-in.l.google.com.",
    "alt3.gmail-smtp-in.l.google.com.", "alt4.gmail-smtp-in.l.google.com.",
])


# ─── the lookup ─────────────────────────────────────────────────────────────

def test_a_dnssec_secure_tlsa_record_is_validated(dns_replay):
    dns_replay("dane_infomaniak_com")
    dane = check_dane(INFOMANIAK_MX)
    assert dane.validated == ["mta-gw.infomaniak.ch."]
    assert dane.every_mx_validated


def test_a_tlsa_record_without_ad_is_published_but_not_validated(dns_replay):
    dns_replay("dane_infomaniak_com_not_validated")
    dane = check_dane(INFOMANIAK_MX)
    assert dane.unvalidated == ["mta-gw.infomaniak.ch."] and dane.validated == []
    assert not dane.every_mx_validated


def test_mx_without_tlsa_are_missing(dns_replay):
    dns_replay("dane_gmail_com")
    dane = check_dane(GMAIL_MX)
    assert sorted(dane.missing) == sorted(GMAIL_MX.hosts)
    assert not dane.every_mx_validated


def test_nothing_is_asked_without_mx_hosts(dns_replay):
    """A null MX, no MX, or an MX lookup that failed: the replay server has
    nothing recorded, so any question would fail the test."""
    dns_replay()
    for mx in (MXResult(null=True), MXResult(), MXResult(error="DNS lookup for example.com MX failed: Timeout")):
        assert check_dane(mx) == DANEResult()


def test_a_lookup_that_gets_no_answer_says_nothing_either_way(dns_replay):
    dns_replay(silent=["_25._tcp.mta-gw.infomaniak.ch. TLSA"])
    dane = check_dane(INFOMANIAK_MX)
    assert dane.error and not dane.every_mx_validated


# ─── what the transport finding says ────────────────────────────────────────

def _report(mta_sts: MTASTSResult, dane: DANEResult) -> DomainReport:
    return DomainReport(
        domain="example.com",
        dmarc=DMARCResult(present=True, policy="reject"),
        spf=SPFResult(present=True, all_mechanism="-all"),
        dkim=DKIMResult(present=True, selector="s1", key_bits=2048),
        mta_sts=mta_sts,
        gpg=GPGResult(found=True),
        dane=dane,
    )


NO_MTA_STS = MTASTSResult(present=False)
TESTING = MTASTSResult(present=True, mode="testing")


def test_validated_dane_on_every_mx_drops_article_32():
    report = _report(NO_MTA_STS, DANEResult(validated=["mta-gw.infomaniak.ch."]))
    assert "cleartext" not in findings_of(report)
    note = next(n for n in notes_of(report) if "DANE" in n)
    assert "mandatory for senders that implement DANE" in note
    assert "MTA-STS" in note and "Gmail" in note


def test_validated_dane_also_covers_mta_sts_in_testing_mode():
    report = _report(TESTING, DANEResult(validated=["mta-gw.infomaniak.ch."]))
    assert "cleartext_testing" not in findings_of(report)


def test_tlsa_without_ad_keeps_the_finding_and_says_why():
    report = _report(NO_MTA_STS, DANEResult(unvalidated=["mta-gw.infomaniak.ch."]))
    evidence = findings_of(report)["cleartext"]
    assert evidence[0] == "MTA-STS missing: TLS not mandatory on delivery"
    assert any("TLSA published but not validated" in e and "senders ignore it" in e for e in evidence)
    assert not any("DANE" in n for n in notes_of(report))


def test_dane_on_some_mx_only_keeps_the_finding():
    report = _report(NO_MTA_STS, DANEResult(validated=["mx1.example.com."], missing=["mx2.example.com."]))
    evidence = findings_of(report)["cleartext"]
    assert any("1 of 2 MX" in e for e in evidence), evidence


def test_no_dane_and_no_mta_sts_is_today_s_finding():
    report = _report(NO_MTA_STS, DANEResult(missing=["mx.example.com."]))
    assert findings_of(report)["cleartext"] == ["MTA-STS missing: TLS not mandatory on delivery"]


def test_the_score_does_not_change(dns_replay):
    """Points for DANE are #155: the scored checks are the same as before."""
    from mailradar.checker import MAX_SCORES

    assert "dane" not in MAX_SCORES


def test_the_questions_go_through_the_resolve_every_check_uses(monkeypatch):
    """The first version asked through a resolver of its own, which the doubles
    of `dns.resolver.resolve` in the tests and the benchmarks did not reach:
    test_bench_full_analysis measured a real TLSA lookup on the network
    (CodSpeed, 5.1 → 9.2 ms, on this pull request). AD is set while the
    questions are asked, and the default resolver's flags are put back."""
    import dns.flags
    import dns.resolver

    default = dns.resolver.get_default_resolver()
    before = default.flags
    asked = []

    def resolve(name, rdtype):
        asked.append((name, rdtype, bool(dns.resolver.get_default_resolver().flags & dns.flags.AD)))
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    dane = check_dane(INFOMANIAK_MX)

    assert asked == [("_25._tcp.mta-gw.infomaniak.ch.", "TLSA", True)]
    assert dane.missing == ["mta-gw.infomaniak.ch."]
    assert default.flags == before
