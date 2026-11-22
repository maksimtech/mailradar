"""A private resolver that returns no TXT record may be showing an internal view.

Run on a network whose resolver serves an internal view of the organisation's
own domain (split-horizon DNS), `check` used to ask that resolver, get no SPF,
DMARC or DKIM, grade the domain 0/100 and cite GDPR art. 32 for records that
exist on the public Internet (#150, seen on 2026-11-20).

A private resolver is also the common case (127.0.0.53 on Ubuntu, the home
router), so its silence alone proves nothing: a domain that really has no
record would lose its CRITICAL. When a private resolver returns no SPF, no
DMARC and no DKIM, the public resolver (1.1.1.1) is asked about SPF and DMARC:

- it has them: an internal view. No grade, no provisions, a warning with both facts;
- it has none: the records are missing for everyone. Graded as before, with a
  note that the public resolver was asked, since that sent the name to Cloudflare;
- it does not answer (outgoing DNS blocked, typically at work): no grade, no
  provisions, and the warning says it could not compare.

Both resolvers are injected: `system_resolver_addresses` and `public_txt`.
conftest.py pins the first to the public resolver the fixtures were recorded
through and makes the second fail any test that reaches it unasked.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.nameserver
import dns.resolver
import pytest
from typer.testing import CliRunner

from mailradar import checker
from mailradar.checker import analyze_domain, resolver_is_private
from mailradar.checker import public_txt as real_public_txt
from mailradar.checker import system_resolver_addresses as read_system_resolvers
from mailradar.cli import app
from mailradar.gpg import GPGResult
from mailradar.law_checker import findings_of

# `read_system_resolvers` and `real_public_txt` are the real functions, bound
# before conftest's autouse fixtures replace them in `checker`.


@pytest.mark.parametrize("addresses", [
    ["127.0.0.53"],          # systemd-resolved's stub
    ["192.168.178.1"],       # a home router
    ["10.0.0.2", "172.16.0.53"],
    ["fd00::53"],            # RFC 4193 unique local
    ["::1"],
])
def test_a_resolver_on_a_private_or_local_address_is_private(addresses):
    assert resolver_is_private(addresses) is True


@pytest.mark.parametrize("addresses", [
    ["1.1.1.1"],
    ["2606:4700:4700::1111"],
    ["192.168.1.1", "9.9.9.9"],   # a public one among them: not only the internal view
    [],
    ["https://dns.example/dns-query"],  # not an address at all
])
def test_a_public_mixed_or_unknown_resolver_is_not_private(addresses):
    assert resolver_is_private(addresses) is False


def test_the_system_resolver_addresses_are_read_as_text(monkeypatch):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver("192.168.178.1", 53), "10.0.0.2"]
    monkeypatch.setattr(dns.resolver, "default_resolver", resolver)
    assert read_system_resolvers() == ["192.168.178.1", "10.0.0.2"]


# ─── the analysis ───────────────────────────────────────────────────────────

PUBLIC_RECORDS = {
    "example.com": ["v=spf1 include:_spf.example.net -all"],
    "_dmarc.example.com": ["v=DMARC1; p=reject"],
}


def _no_gpg():
    """No key on any keyserver: a real result, since the report prints its fields."""
    return GPGResult()


def _resolve_from(records):
    def resolve(name, rtype):
        name = str(name).rstrip(".").lower()
        if rtype == "TXT" and name in records:
            answer = MagicMock()
            answer.__iter__ = lambda self: iter([MagicMock(strings=[r.encode()]) for r in records[name]])
            return answer
        raise dns.resolver.NoAnswer
    return resolve


def _public(records):
    """A stand-in for public_txt that knows `records`, and counts what it was asked."""
    asked = []

    def public_txt(name):
        asked.append(name)
        return records.get(name, [])
    public_txt.asked = asked
    return public_txt


def _public_unreachable(name):
    raise dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])


def _analyze(resolver, local_records, public):
    with patch.object(checker, "system_resolver_addresses", return_value=[resolver]), \
         patch.object(checker, "public_txt", public), \
         patch("mailradar.checker.dns.resolver.resolve", side_effect=_resolve_from(local_records)), \
         patch("mailradar.gpg.lookup_gpg", return_value=_no_gpg()):
        return analyze_domain("example.com")


def test_an_internal_view_confirmed_by_the_public_resolver_gives_no_grade_and_no_provisions():
    report = _analyze("192.168.178.1", {}, _public(PUBLIC_RECORDS))

    assert report.total_score is None
    assert report.grade == "N/A"
    assert "192.168.178.1" in report.split_horizon
    assert "1.1.1.1 returns SPF and DMARC" in report.split_horizon
    assert "internal (split-horizon) view" in report.split_horizon
    assert findings_of(report) == {}
    for check in ("DMARC", "SPF", "DKIM"):
        assert check in report.unverified


def test_records_missing_for_the_public_resolver_too_are_graded_as_missing():
    """The domain really has none: CRITICAL and the provisions, as before #150."""
    public = _public({})
    report = _analyze("127.0.0.53", {}, public)

    assert report.split_horizon == ""
    assert report.total_score == 0
    assert report.grade == "CRITICAL"
    assert "dmarc_missing" in findings_of(report)
    assert public.asked == ["example.com", "_dmarc.example.com"]
    # Asking sent the name to Cloudflare: the output says it was asked
    assert "1.1.1.1 was asked" in report.public_view


def test_a_public_resolver_that_does_not_answer_leaves_the_analysis_incomplete():
    """Outgoing DNS blocked, typically at work: no grade, and the warning says it could not compare."""
    report = _analyze("10.0.0.2", {}, _public_unreachable)

    assert report.total_score is None
    assert "could not be asked to compare (LifetimeTimeout)" in report.split_horizon
    assert "may be an internal (split-horizon) view" in report.split_horizon
    assert findings_of(report) == {}


def test_the_warning_does_not_offer_an_option_that_does_not_exist_yet():
    """--resolver is #156, for January: until then the advice is a network."""
    for public in (_public(PUBLIC_RECORDS), _public_unreachable):
        report = _analyze("127.0.0.53", {}, public)
        assert "--resolver" not in report.split_horizon
        assert "network that uses a public resolver" in report.split_horizon


def test_a_private_resolver_that_returns_the_records_asks_nobody_else():
    public = _public(PUBLIC_RECORDS)
    report = _analyze("192.168.178.1", PUBLIC_RECORDS, public)

    assert public.asked == []
    assert (report.split_horizon, report.public_view) == ("", "")
    assert report.dmarc.policy == "reject"


def test_a_public_system_resolver_with_no_txt_asks_nobody_else():
    """Today's behaviour, unchanged: through a public resolver, missing is missing."""
    public = _public(PUBLIC_RECORDS)
    report = _analyze("1.1.1.1", {}, public)

    assert public.asked == []
    assert report.grade == "CRITICAL"


def test_a_lookup_that_failed_is_not_mistaken_for_a_missing_record():
    """A timeout is already 'not verified' for its own reason: nothing to compare."""
    def resolve(name, rtype):
        raise dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])

    public = _public(PUBLIC_RECORDS)
    with patch.object(checker, "system_resolver_addresses", return_value=["192.168.178.1"]), \
         patch.object(checker, "public_txt", public), \
         patch("mailradar.checker.dns.resolver.resolve", side_effect=resolve), \
         patch("mailradar.gpg.lookup_gpg", return_value=_no_gpg()):
        report = analyze_domain("example.com")

    assert public.asked == []
    assert report.split_horizon == ""
    assert report.total_score is None


def test_the_public_resolver_is_asked_and_nobody_else(monkeypatch):
    """public_txt goes to 1.1.1.1 with a resolver of its own, never the system's."""
    used = []

    def resolve(self, name, rtype):
        used.append((list(self.nameservers), name, rtype))
        raise dns.resolver.NoAnswer

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    assert checker.PUBLIC_RESOLVER == "1.1.1.1"
    assert real_public_txt("example.com") == []
    assert used == [(["1.1.1.1"], "example.com", "TXT")]


# ─── the command ────────────────────────────────────────────────────────────

def test_check_prints_the_warning_and_exits_3():
    with patch.object(checker, "system_resolver_addresses", return_value=["192.168.178.1"]), \
         patch.object(checker, "public_txt", _public(PUBLIC_RECORDS)), \
         patch("mailradar.checker.dns.resolver.resolve", side_effect=_resolve_from({})), \
         patch("mailradar.gpg.lookup_gpg", return_value=_no_gpg()):
        result = CliRunner().invoke(app, ["check", "example.com"])

    assert result.exit_code == 3, result.output
    out = " ".join(result.output.split())
    assert "N/A" in out
    assert "internal (split-horizon) view" in out
    assert "CRITICAL" not in out
    # Found live on 2026-11-22: the table said "DNS lookup failed" for lookups
    # that were answered, by an internal view. The label must hold whether the
    # public resolver confirmed the internal view or could not be asked.
    assert "DNS lookup failed" not in out
    assert "Not verified: private resolver, see above" in out


def test_check_says_the_public_resolver_was_asked():
    with patch.object(checker, "system_resolver_addresses", return_value=["192.168.178.1"]), \
         patch.object(checker, "public_txt", _public({})), \
         patch("mailradar.checker.dns.resolver.resolve", side_effect=_resolve_from({})), \
         patch("mailradar.gpg.lookup_gpg", return_value=_no_gpg()):
        result = CliRunner().invoke(app, ["check", "example.com"])

    assert result.exit_code == 2, result.output   # CRITICAL, as before
    assert "1.1.1.1 was asked" in " ".join(result.output.split())
