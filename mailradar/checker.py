"""
MailRadar — DNS record checker for email security posture analysis.
"""

import contextlib
import functools
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

import dns.exception
import dns.name
import dns.resolver
import httpx

# The one GPGResult: lookup_gpg returns this, and it carries `fingerprint`,
# which the copy that used to live here did not.
from mailradar.gpg import GPGResult


@dataclass
class DMARCResult:
    present: bool = False
    policy: str = "none"
    # The domain the record was actually found on (RFC 7489 §6.6.3)
    found_at: str = ""
    # True when the record belongs to a parent domain rather than the one asked
    # about
    inherited: bool = False
    sp: str = ""
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    rua: bool = False
    ruf: bool = False
    raw: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class SPFResult:
    present: bool = False
    all_mechanism: str = ""
    permissive: bool = False
    # RFC 7208 §2.6.7: the record cannot be evaluated, receivers apply no SPF
    permerror: bool = False
    # DNS lookups the evaluation needs (§4.6.4), past the limit when permerror
    # says so; None when they were not counted, which is not 0
    lookups: int | None = None
    # True when an include: or redirect= target holds a macro (%{d}): it is
    # counted, not followed, so `lookups` is a lower bound, "at least N"
    lookups_partial: bool = False
    raw: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DKIMResult:
    present: bool = False
    # The selector of the weakest key found: the score measures it, a
    # receiver verifies a signature made with any published key
    selector: str = ""
    # 0 when the key is malformed: p= missing, or no key of the type declared
    key_bits: int = 0
    # The k= tag: "rsa" (the default) or "ed25519" (RFC 8463); any other value
    # is a type no verifier knows, and its key_bits is 0
    key_type: str = "rsa"
    raw: str = ""
    # Every active key found, selector -> "2048-bit RSA" / "Ed25519"
    keys: dict[str, str] = field(default_factory=dict)
    # How many selectors were asked for: "not found" is relative to them
    tried: int = 0
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class BIMIResult:
    present: bool = False
    svg_url: str = ""
    vmc_url: str = ""
    svg_valid: bool = False
    vmc_present: bool = False
    raw: str = ""
    score: int = 0
    # Set when a DNS lookup failed or the logo fetch got no answer: the check
    # then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class MTASTSResult:
    # A valid _mta-sts record announces a policy (RFC 8461 §3.1)
    present: bool = False
    # Set only from a valid policy file (RFC 8461 §3.2)
    mode: str = ""
    score: int = 0
    # Set when a DNS lookup failed or the policy fetch got no answer: the
    # check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    # One valid v=TLSRPTv1 record, with a usable rua (RFC 8460 §3)
    present: bool = False
    rua: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class MXResult:
    """The domain's MX records. Not scored: it says where replies and bounces go.

    `hosts` empty and `null` False, with no `error`, is a domain that publishes
    no MX at all. A failed lookup sets `error` and says nothing either way.
    """
    hosts: list[str] = field(default_factory=list)
    # RFC 7505 §3: a single MX of preference 0 with exchange "." — the domain
    # declares that it accepts no mail
    null: bool = False
    error: str = ""
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DomainReport:
    domain: str = ""
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    spf: SPFResult = field(default_factory=SPFResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    bimi: BIMIResult = field(default_factory=BIMIResult)
    mta_sts: MTASTSResult = field(default_factory=MTASTSResult)
    tls_rpt: TLSRPTResult = field(default_factory=TLSRPTResult)
    gpg: GPGResult = field(default_factory=GPGResult)
    # Not among the scored checks (MAX_SCORES) nor in `unverified`
    mx: MXResult = field(default_factory=MXResult)
    # None, with grade "N/A", when a DNS lookup or an HTTP request got no
    # answer: a check that was not verified scored 0, and the total read as a
    # measured bottom of scale.
    total_score: int | None = 0
    grade: str = "F"
    # Why the analysis may describe an internal view of the domain, not what
    # other mail servers see; empty when there is no reason to think so (#150)
    split_horizon: str = ""
    # That the public resolver was asked to compare, and found nothing either
    public_view: str = ""

    @property
    def unverified(self) -> list[str]:
        """The checks whose DNS lookup or HTTP request got no answer (timeout, SERVFAIL, reset), in report order.

        A domain that is not a valid name leaves every check here, with the
        reason in its `error`. GPG is not among them: a keyserver that rate-limits withholds at most its
        5 points and says so in its own issue, as `report` and `send` already treat it.
        """
        checks = (("DMARC", self.dmarc), ("SPF", self.spf), ("DKIM", self.dkim),
                  ("BIMI", self.bimi), ("MTA-STS", self.mta_sts), ("TLS-RPT", self.tls_rpt))
        return [name for name, check in checks if check.error]


def domain_exists(domain: str) -> bool:
    """
    Check if a domain exists in DNS.
    A valid domain must have at least one dot (e.g. apple.com not just apple).
    """
    # A fully qualified name ends in a dot: example.com. is example.com
    domain = domain.removesuffix(".")

    # At least one dot: without a TLD it is not a domain
    if "." not in domain:
        return False

    # Deve avere almeno 2 parti (nome + TLD)
    parts = domain.split(".")
    if len(parts) < 2 or any(len(p) == 0 for p in parts):
        return False

    # One A query is enough: NXDOMAIN is about the name, whatever the type
    # asked for, and NOERROR with no answer (sanita.fvg.it: MX and TXT, no A)
    # is a name that exists. A timeout or a SERVFAIL says nothing about the
    # name: read as "no such domain", it sent the user to another domain.
    # A name DNS cannot hold is neither: InvalidDomainError says which.
    _require_valid_name(domain)
    try:
        dns.resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except dns.exception.DNSException as e:
        raise DNSLookupError(f"DNS lookup for {domain} failed: {type(e).__name__}") from e
    return True


def variant_base(domain: str) -> str | None:
    """The name to try other TLDs with: 'apple' for 'apple' or 'apple.con'.

    Only a bare name or name.tld has one. A subdomain's first label is not the
    organisation: asufc.sanita.fvg.it became asufc.com, somebody else's domain.
    """
    parts = domain.removesuffix(".").split(".")
    return parts[0] if len(parts) <= 2 else None


def find_domain_variants(domain: str) -> list[str]:
    """
    Given a domain input, find all existing TLD variants.
    e.g. 'apple' -> ['apple.com', 'apple.it', 'apple.eu', ...]
    """
    base = variant_base(domain)
    if base is None:
        return []

    # TLD comuni da provare
    tlds = [
        "com", "it", "eu", "org", "net", "io",
        "co.uk", "de", "fr", "es", "nl", "ch",
        "gov.it", "edu", "info", "biz",
    ]

    found = []
    for tld in tlds:
        candidate = f"{base}.{tld}"
        try:
            if domain_exists(candidate):
                found.append(candidate)
        except DNSLookupError:
            # Not known to exist: it cannot be offered
            continue

    return found


# The Public Suffix List, both sections, as published at
# https://publicsuffix.org/list/public_suffix_list.dat (the VERSION line in the
# file says which). The list is Mozilla's, under MPL-2.0, and its header says
# so: keep it. It replaced a hand-picked subset of two-label suffixes that
# lacked co.at and hundreds of others, and so queried them as though they were
# a domain's parent. Suffixes are added every few weeks, so refresh the copy
# periodically, before a release at the latest: download
# https://publicsuffix.org/list/public_suffix_list.dat over this file, as it
# is, and run the suite.
_PUBLIC_SUFFIX_LIST = Path(__file__).parent / "public_suffix_list.dat"


@functools.cache
def _public_suffix_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """The PSL as (rules, wildcard rules without `*.`, exceptions without `!`)."""
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for line in _PUBLIC_SUFFIX_LIST.read_text(encoding="utf-8").splitlines():
        rule = line.strip().lower()
        if not rule or rule.startswith("//"):
            continue
        if not rule.isascii():
            # Listed in Unicode, met in DNS as punycode: 公司.cn is xn--55qx5d.cn
            with contextlib.suppress(UnicodeError):
                _add_rule(rule.encode("idna").decode("ascii"), rules, wildcards, exceptions)
        _add_rule(rule, rules, wildcards, exceptions)
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def _add_rule(rule: str, rules: set[str], wildcards: set[str], exceptions: set[str]) -> None:
    """File one PSL rule under its kind."""
    if rule.startswith("!"):
        exceptions.add(rule[1:])
    elif rule.startswith("*."):
        wildcards.add(rule[2:])
    else:
        rules.add(rule)


def _public_suffix_depth(labels: list[str]) -> int:
    """Quante label finali di `labels` sono il suffisso pubblico (algoritmo PSL)."""
    rules, wildcards, exceptions = _public_suffix_rules()
    # From the longest candidate down: the first rule that matches is the
    # longest, and an exception beats the wildcard it carves out of
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        if name in exceptions:
            return len(labels) - i - 1
        if name in rules or ".".join(labels[i + 1:]) in wildcards:
            return len(labels) - i
    # The implicit rule `*`: an unlisted TLD is a public suffix
    return 1


def _labels(domain: str) -> list[str]:
    """A domain as lower-case labels, with no trailing dot."""
    labels = domain.strip(" \t\r\n.").lower().split(".")
    # Empty labels (a double dot) are rare, so the comprehension runs only when
    # there is one to drop.
    return [label for label in labels if label] if "" in labels else labels


def _org_depth(labels: list[str]) -> int:
    """Quante label compongono il dominio organizzativo di `labels`."""
    return min(len(labels), _public_suffix_depth(labels) + 1)


def organizational_domain(domain: str) -> str:
    """
    RFC 7489 §3.2 — dominio organizzativo: il nome registrabile
    immediatamente sotto il suffisso pubblico.

    asufc.sanita.fvg.it -> sanita.fvg.it   (fvg.it is on the PSL)
    mail.example.co.uk  -> example.co.uk
    sub.domain.com      -> domain.com
    """
    labels = _labels(domain)
    return ".".join(labels[len(labels) - _org_depth(labels):])


def dmarc_lookup_chain(domain: str) -> list[str]:
    """
    RFC 7489 §6.6.3 — the names whose `_dmarc` record DMARC policy discovery
    asks for: the domain itself and, if it is not one, its organizational
    domain. Nothing in between: a record on a.example.com is not the policy
    of sub.a.example.com. The public suffix itself is never queried: a record
    published on `it` or `co.uk` is not the domain's policy.

    asufc.sanita.fvg.it -> [asufc.sanita.fvg.it, sanita.fvg.it]
    sub.a.example.com   -> [sub.a.example.com, example.com]
    """
    labels = _labels(domain)
    if not labels:
        return []
    chain = [".".join(labels)]
    organizational = ".".join(labels[len(labels) - _org_depth(labels):])
    if organizational != chain[0]:
        chain.append(organizational)
    return chain


class DNSLookupError(Exception):
    """A lookup that got no answer (timeout, SERVFAIL): not the same as no record."""


class InvalidDomainError(DNSLookupError):
    """A name DNS cannot hold: a label past 63 octets, a name past 255, invalid IDNA.

    No resolver is asked and none would help: trying again changes nothing. A
    DNSLookupError still, so that whoever catches one does not crash on it.
    """


class HTTPFetchError(Exception):
    """An HTTP request that got no answer (timeout, reset, refused): not the same as an HTTP error status.

    It says something about the network the scan runs from, not about the
    domain, so the check that made it is not verified, as for DNS.
    """


def _require_valid_name(name: str) -> None:
    """Raise InvalidDomainError if `name` cannot be a DNS name.

    dnspython raises the same errors from inside resolve(), as DNSException
    subclasses: caught there, they read as a lookup that failed.

    A plain ASCII name with no escapes is judged on its lengths alone, which is
    all dnspython checks in it: labels of 1 to 63 octets, 253 characters at most
    (255 octets on the wire). This runs before every query, and parsing each
    name doubled the cost of an analysis whose DNS answers were already there.
    Every other name goes to dns.name.from_text, which also says why it fails.
    """
    text = name[:-1] if name.endswith(".") else name
    if (text and text.isascii() and "\\" not in text and len(text) <= 253
            and all(0 < len(label) <= 63 for label in text.split("."))):
        return
    try:
        dns.name.from_text(name)
    except dns.name.LabelTooLong:
        reason = "a label is longer than 63 octets"
    except dns.name.NameTooLong:
        reason = "it is longer than 255 octets"
    except dns.name.IDNAException as e:
        reason = f"it is not valid IDNA ({e.kwargs.get('idna_exception') or e})"
    except dns.exception.DNSException as e:
        # An empty label, a bad escape
        reason = str(e).rstrip(".").lower() or type(e).__name__
    else:
        return
    raise InvalidDomainError(f"{name} is not a valid domain name: {reason}")


def _query_txt(name: str) -> list[str]:
    """Query TXT records for a given name."""
    _require_valid_name(name)
    try:
        answers = dns.resolver.resolve(name, "TXT")
        # Join a record's multiple strings (DKIM keys are split across them)
        # errors="replace": a TXT record that is not UTF-8 must not end the analysis
        return [b"".join(rdata.strings).decode("utf-8", errors="replace")
                for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        # Read as "no record", a resolver timeout put "No DMARC record found —
        # domain is spoofable" into the report sent to the domain's owner
        raise DNSLookupError(f"DNS lookup for {name} failed: {type(e).__name__}") from e


_Result = TypeVar("_Result")


def _unless_dns_fails(
    check: str, result_type: Callable[..., _Result]
) -> Callable[[Callable[..., _Result]], Callable[..., _Result]]:
    """A check_* whose DNS lookup or HTTP request gets no answer returns a result marked as not verified.

    So does one asked about a domain that is not a valid name, with the reason.
    When the domain is valid and only the name the check asks about is too long
    (_mta-sts.<domain> past 255 octets), no record can be published there:
    that is an answer, and is scored as one.
    """
    def decorate(run: Callable[..., _Result]) -> Callable[..., _Result]:
        @functools.wraps(run)
        def wrapper(*args, **kwargs) -> _Result:
            try:
                _require_valid_name(kwargs.get("domain", args[0] if args else ""))
            except InvalidDomainError as e:
                return result_type(error=str(e), issues=[f"{check} not verified — {e}"])
            try:
                return run(*args, **kwargs)
            except InvalidDomainError as e:
                return result_type(issues=[f"No {check} record can be published for this domain — {e}"])
            except (DNSLookupError, HTTPFetchError) as e:
                return result_type(error=str(e), issues=[f"{check} not verified — {e}"])
        return wrapper
    return decorate


def _parse_tags(record: str) -> dict[str, str]:
    """Parse a `k=v; k=v` tag list (DMARC, BIMI). Values may contain '='."""
    tags = {}
    for t in record.split(";"):
        if "=" in t:
            key, value = t.split("=", 1)
            tags[key.strip()] = value.strip()
    return tags


def _parse_pct(value: str) -> int | None:
    """Parse DMARC pct — returns None if not an integer in 0-100."""
    try:
        pct = int(value)
    except ValueError:
        return None
    return pct if 0 <= pct <= 100 else None


_DMARC_POLICIES = ("none", "quarantine", "reject")
# RFC 7489 §6.4: dmarc-uri is a URI (RFC 3986: a scheme, then ':'), with an
# optional size limit after '!'
_DMARC_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^!\s]+(![0-9]+[kmgtKMGT]?)?")


def _dmarc_uris(result: DMARCResult, tag: str, value: str) -> bool:
    """Whether rua= or ruf= names at least one URI; an entry that is none is an issue.

    `rua=dmarc@example.com` is an address, not a mailto: URI, and turns no
    reports on.
    """
    entries = [entry.strip() for entry in value.split(",") if entry.strip()]
    for entry in entries:
        if not _DMARC_URI.fullmatch(entry):
            result.issues.append(
                f"DMARC {tag} entry {entry!r} is not a URI — write it as mailto:{entry.removeprefix('mailto:')}"
                if "@" in entry else f"DMARC {tag} entry {entry!r} is not a URI — no reports are sent there"
            )
    return any(_DMARC_URI.fullmatch(entry) for entry in entries)


def _apply_dmarc_record(result: DMARCResult, record: str) -> None:
    """Popola e valuta un DMARCResult a partire dal record trovato."""
    result.present = True
    result.raw = record

    # RFC 7489 §6.4: tag names and these values are case-insensitive literals,
    # p=REJECT is p=reject
    tags = {key.lower(): value for key, value in _parse_tags(record).items()}

    # An empty rua= or ruf= names nobody to send reports to (RFC 7489 §6.4)
    result.rua = _dmarc_uris(result, "rua", tags.get("rua", ""))
    result.ruf = _dmarc_uris(result, "ruf", tags.get("ruf", ""))

    # RFC 7489 §6.6.3: with no valid p, or an sp that is not valid, the record
    # acts as p=none if its rua names a valid URI; otherwise no DMARC applies
    policy = tags.get("p", "").lower()
    sp = tags.get("sp", "").lower()
    invalid = []
    if "p" not in tags:
        invalid.append("no p= tag")
    elif policy not in _DMARC_POLICIES:
        invalid.append(f"p={tags['p']}")
    if "sp" in tags and sp not in _DMARC_POLICIES:
        invalid.append(f"sp={tags['sp']}")
    if invalid:
        if not result.rua:
            result.present = False
            result.issues.append(
                f"Invalid DMARC record ({', '.join(invalid)}) and no valid rua — receivers apply "
                "no DMARC policy (RFC 7489 §6.6.3)"
            )
            return
        result.issues.append(
            f"Invalid DMARC record ({', '.join(invalid)}) — receivers act as if it said p=none (RFC 7489 §6.6.3)"
        )
        policy, sp = "none", ""

    result.policy = policy
    result.sp = sp
    # RFC 7489 §6.3: per un sottodominio vale `sp`, se presente sul padre
    if result.inherited and result.sp:
        result.policy = result.sp
        result.issues.append(
            f"Subdomain policy sp={result.sp} inherited from {result.found_at}"
        )

    pct = _parse_pct(tags.get("pct", "100"))
    if pct is None:
        # RFC 7489 §6.3: an invalid value means the default applies (100)
        result.issues.append(f"Invalid DMARC pct value: {tags['pct']!r}")
        pct = 100
    result.pct = pct
    result.adkim = tags.get("adkim", "r").lower()
    result.aspf = tags.get("aspf", "r").lower()

    # Scoring
    if result.policy == "reject":
        result.score += 30
    elif result.policy == "quarantine":
        result.score += 15
        result.issues.append("DMARC policy is quarantine — upgrade to reject")
    else:
        result.issues.append("DMARC policy is none — no protection active")

    if result.pct == 100:
        result.score += 5
    else:
        result.issues.append(f"pct={result.pct} — not applied to 100% of emails")

    if result.adkim == "s":
        result.score += 5
    else:
        result.issues.append("adkim=r (relaxed) — consider strict alignment")

    if result.aspf == "s":
        result.score += 5
    else:
        result.issues.append("aspf=r (relaxed) — consider strict alignment")

    if result.rua:
        result.score += 3
    else:
        result.issues.append("No rua configured — aggregate reports disabled")

    if result.ruf:
        result.score += 2
    else:
        result.issues.append("No ruf configured — forensic reports disabled")


def _is_dmarc(record: str) -> bool:
    """RFC 7489 §6.4: the first tag is v=DMARC1, spaces allowed around '='."""
    key, _, value = record.split(";", 1)[0].partition("=")
    return key.strip().lower() == "v" and value.strip() == "DMARC1"


def _dmarc_records(name: str) -> list[str]:
    """I record TXT di `name` che sono record DMARC."""
    return [record for record in _query_txt(name) if _is_dmarc(record)]


@_unless_dns_fails("DMARC", DMARCResult)
def check_dmarc(domain: str) -> DMARCResult:
    """
    The DMARC record that applies to `domain`, found as RFC 7489 §6.6.3
    says: `_dmarc.<domain>` first and, if it has none, `_dmarc.<organizational
    domain>` (from the Public Suffix List), with no name in between.
    """
    result = DMARCResult()
    chain = dmarc_lookup_chain(domain)
    requested = chain[0] if chain else ""

    for candidate in chain:
        try:
            records = _dmarc_records(f"_dmarc.{candidate}")
        except InvalidDomainError:
            # _dmarc.<domain> past 255 octets holds no record; the
            # organizational domain's still applies
            continue
        if not records:
            continue

        # RFC 7489 §6.6.3: more than one record ends policy discovery and no
        # DMARC is applied, neither of them nor a parent's
        if len(records) > 1:
            result.found_at = candidate
            result.issues.append(
                f"Multiple DMARC records ({len(records)}) on _dmarc.{candidate} — "
                "receivers apply no DMARC policy"
            )
            return result

        record = records[0]
        result.found_at = candidate
        result.inherited = candidate != requested
        if result.inherited:
            result.issues.append(
                f"No DMARC record on {requested} — policy inherited "
                f"from its organizational domain {candidate}"
            )
        _apply_dmarc_record(result, record)
        break

    # A record that applies no policy has already said so
    if not result.present and not result.found_at:
        result.issues.append("No DMARC record found — domain is spoofable")

    return result


# One SPF term: an optional qualifier, the mechanism or modifier name, and
# whatever follows it (":domain", "/cidr", "=value").
_SPF_TERM = re.compile(r"([+\-~?]?)([a-z][a-z0-9_.-]*)(.*)", re.IGNORECASE)


def _is_spf(record: str) -> bool:
    """RFC 7208 §4.5: `v=spf1` alone or followed by a space, in any case."""
    return record.lower().split()[:1] == ["v=spf1"]


def _spf_terms(record: str) -> list[tuple[str, str, str]]:
    """
    The terms after `v=spf1`, as (qualifier, name, rest). Whole terms, not
    substrings: `include:spf-all.example.net` holds no `-all`, and `+all` no
    `+a`. Names are lower-cased, RFC 7208 §4.6.1 makes them case-insensitive.
    """
    terms = []
    for term in record.split()[1:]:
        match = _SPF_TERM.fullmatch(term)
        if match:
            qualifier, name, rest = match.groups()
            terms.append((qualifier, name.lower(), rest))
    return terms


def _spf_all(terms: list[tuple[str, str, str]]) -> str:
    """The `all` mechanism with its qualifier, or "" if there is none."""
    for qualifier, name, rest in terms:
        if name == "all" and not rest:
            # RFC 7208 §4.6.2: no qualifier means "+", so a bare `all` lets
            # every server pass
            return f"{qualifier or '+'}all"
    return ""


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# RFC 7208 §4.6.4: the terms that cost a DNS query, and how many of them one
# evaluation may make, nested include: and redirect= counted in
_SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
SPF_MAX_LOOKUPS = 10


def _spf_macro(target: str) -> bool:
    """`target` holds a macro (RFC 7208 §7): the name depends on the message,
    so it cannot be looked up here."""
    return "%" in target


def _spf_redirect(terms: list[tuple[str, str, str]]) -> str:
    """The target of `redirect=` as written, macro or not; "" when there is
    none, or when the record has `all`, which makes redirect= ignored (§6.1)."""
    if _spf_all(terms):
        return ""
    for _, name, rest in terms:
        if name == "redirect" and rest.startswith("="):
            return rest[1:]
    return ""


def _spf_record_of(name: str) -> str | None:
    """The one SPF record of `name`; None if it has none, or more than one."""
    records = [record for record in _query_txt(name) if _is_spf(record)]
    return records[0] if len(records) == 1 else None


# RFC 7208 §5.6: an ip4-network is four qnum, none with a leading zero; the
# prefix length after it has no leading zero either, and none at all means
# the single address
_SPF_QNUM = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_SPF_IP4 = re.compile(rf"{_SPF_QNUM}(?:\.{_SPF_QNUM}){{3}}")
_SPF_CIDR = re.compile(r"(?P<address>[^/]+)(?:/(?P<length>0|[1-9][0-9]{0,2}))?")


def _spf_network(name: str, rest: str) -> tuple[str, IPNetwork] | None:
    """`ip4:`/`ip6:` as (the value as written, the network it covers).

    RFC 7208 §5.6 compares only the first prefix-length bits, so a value
    written from an inner address covers the whole network around it:
    `strict=False` is the receiver's reading. None for any other term, and
    for a value the ABNF of §5.6 does not allow: ip_network also takes a
    netmask, a hostmask, `/027` and a zone id (`2001:db8::1%eth0`), which a
    receiver answers with a permerror.
    """
    if name not in ("ip4", "ip6") or not rest.startswith(":"):
        return None
    value = rest[1:]
    match = _SPF_CIDR.fullmatch(value)
    if not match:
        return None
    address, length = match["address"], match["length"]
    if name == "ip4":
        if not _SPF_IP4.fullmatch(address):
            return None
        maximum = 32
    else:
        # RFC 4291 §2.2 text, which has no zone id
        if "%" in address:
            return None
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            return None
        maximum = 128
    if length is not None and int(length) > maximum:
        return None
    prefix = maximum if length is None else int(length)
    return value, ipaddress.ip_network(f"{address}/{prefix}", strict=False)


_SPF_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
# RFC 7208 §6: a modifier is `name=value`, with no qualifier
_SPF_MODIFIER = re.compile(r"([a-z][a-z0-9_.-]*)=(.*)", re.IGNORECASE)
# `a` and `mx`: an optional domain, then the dual-cidr-length of §5.3
_SPF_A_MX = re.compile(
    r"(?::[^/]+)?(?:/(?P<ip4>0|[1-9][0-9]?))?(?://(?P<ip6>0|[1-9][0-9]{0,2}))?"
)


def _spf_mechanism_valid(name: str, rest: str) -> bool:
    """What follows a known mechanism's name is what RFC 7208 §5 allows.

    The domain-spec is only required to be there: macros are not expanded,
    and a domain this cannot judge is not called an error.
    """
    if name == "all":
        return not rest
    if name in ("include", "exists"):
        return rest.startswith(":") and len(rest) > 1
    if name == "ptr":
        return not rest or (rest.startswith(":") and len(rest) > 1)
    if name in ("a", "mx"):
        match = _SPF_A_MX.fullmatch(rest)
        if match is None:
            return False
        return int(match["ip4"] or 0) <= 32 and int(match["ip6"] or 0) <= 128
    return _spf_network(name, rest) is not None


def _spf_syntax_errors(record: str) -> list[tuple[str, str]]:
    """
    The terms of `record` that RFC 7208 §4.6.1 and §6 do not allow, as (term,
    what is wrong). Any one of them makes the whole record a permerror (§4.6):
    receivers do not skip a bad term and read the rest. A modifier with an
    unknown name is allowed (§6) and is not one of them.
    """
    errors = []
    seen: dict[str, str] = {}
    for term in record.split()[1:]:
        modifier = _SPF_MODIFIER.fullmatch(term)
        if modifier:
            name = modifier[1].lower()
            if name in ("redirect", "exp"):
                if not modifier[2]:
                    errors.append((term, "names no domain"))
                elif name in seen:
                    errors.append((term, f"repeats {seen[name]}: {name}= may appear only once"))
                seen.setdefault(name, term)
            continue
        match = _SPF_TERM.fullmatch(term)
        if not match:
            errors.append((term, "is not an SPF term"))
            continue
        name, rest = match[2].lower(), match[3]
        if name not in _SPF_MECHANISMS:
            if rest.startswith("="):
                errors.append((term, "puts a qualifier on a modifier"))
            else:
                hint = " (a typo of all?)" if name.startswith("al") else ""
                errors.append((term, f"is not an SPF mechanism{hint}"))
        elif not _spf_mechanism_valid(name, rest):
            errors.append((term, f"is not valid {name} syntax (RFC 7208 §5)"))
    return errors


@dataclass
class _SPFRange:
    """A pass range in a record the domain's record pulls in, which the
    evaluation reaches for the addresses it covers."""
    # The domain's own term that leads to it (include:x, redirect=x), and the
    # names in between, outermost first: the owner can act only on the first
    term: str
    through: tuple[str, ...]
    network: IPNetwork
    # Ranges that fail, softfail or are neutral, tested before this one on its
    # path: an address inside one of them never reaches it
    denied: tuple[IPNetwork, ...]


@dataclass
class _SPFWalk:
    """What following the domain's include: and redirect= finds, in one pass
    that asks for each record once."""
    lookups: int = 0
    # The include:/redirect= terms whose target holds a macro: counted, not
    # followed, so `lookups` is a lower bound
    unexpanded: list[str] = field(default_factory=list)
    ranges: list[_SPFRange] = field(default_factory=list)
    # Permerrors in the records pulled in (RFC 7208 §5.2, §6.1)
    errors: list[str] = field(default_factory=list)
    records: dict[str, str | None] = field(default_factory=dict)

    @property
    def over_limit(self) -> bool:
        return self.lookups > SPF_MAX_LOOKUPS

    def record_of(self, name: str) -> str | None:
        if name not in self.records:
            self.records[name] = _spf_record_of(name)
        return self.records[name]


def _spf_walk(terms: list[tuple[str, str, str]]) -> _SPFWalk:
    """
    DNS lookups the evaluation of the domain's record needs, including those
    of the records it pulls in; the permerrors in those records; and the
    ranges they authorise for the domain. The walk stops as soon as the limit
    is passed, which is also what ends an include loop.

    The records are fetched here for the count already, so comparing their
    ranges with the domain's own costs no query of its own.
    """
    walk = _SPFWalk()
    _spf_visit(walk, terms, "", (), (), True)
    return walk


def _spf_visit(walk: _SPFWalk, terms: list[tuple[str, str, str]], top_term: str,
               through: tuple[str, ...], denied: tuple[IPNetwork, ...], authorising: bool) -> None:
    """
    One record's terms in evaluation order: the first mechanism that matches
    decides, nothing after `all` is tested (RFC 7208 §4.6.2, §5.1), and
    redirect= comes after every mechanism (§6.1).

    `top_term` is the domain's own term that leads here, "" in the domain's
    record. A pass range here authorises for the domain only while
    `authorising` holds: every include on the path passes, and nothing tested
    before it may match with another result. `?include:`, `~include:` and
    `-include:` match with their own qualifier (§5.2), so nothing below them
    authorises; a `-exists:` or `~a` may match any address first. When in
    doubt nothing is collected: a "redundant" note must hold for every
    address of the range. Ranges with another result are kept in `denied`,
    and only exclude the addresses they cover.
    """
    denied_here = list(denied)
    for qualifier, name, rest in terms:
        passes = qualifier in ("", "+")
        if name == "all":
            authorising = False
            continue
        if name in ("ip4", "ip6"):
            found = _spf_network(name, rest)
            if found and authorising:
                if not passes:
                    denied_here.append(found[1])
                elif top_term:
                    walk.ranges.append(_SPFRange(top_term, through, found[1], tuple(denied_here)))
            continue
        if name not in _SPF_LOOKUP_TERMS or name == "redirect":
            continue
        walk.lookups += 1
        if walk.over_limit:
            return
        if name == "include":
            _spf_follow(walk, f"include:{rest[1:]}", rest[1:], top_term, through, tuple(denied_here),
                        authorising and passes)
            if walk.over_limit:
                return
        if not passes:
            authorising = False
    redirect = _spf_redirect(terms)
    if redirect:
        walk.lookups += 1
        if walk.over_limit:
            return
        _spf_follow(walk, f"redirect={redirect}", redirect, top_term, through, tuple(denied_here), authorising)


def _spf_follow(walk: _SPFWalk, term: str, target: str, top_term: str, through: tuple[str, ...],
                denied: tuple[IPNetwork, ...], authorising: bool) -> None:
    """The record `term` (include:x or redirect=x) pulls in from `target`, visited."""
    if _spf_macro(target):
        walk.unexpanded.append(term)
        return
    where = term
    if top_term:
        where += f" (in {top_term}" + "".join(f", through {hop}" for hop in through) + ")"
    record = walk.record_of(target)
    if record is None:
        walk.errors.append(f"SPF {where} has no single SPF record — permerror, receivers apply no SPF")
        return
    syntax_errors = _spf_syntax_errors(record)
    if syntax_errors:
        walk.errors.extend(
            f"SPF {where} pulls in the term {bad}, which {wrong} — permerror, receivers apply no SPF"
            for bad, wrong in syntax_errors
        )
        return
    if top_term:
        _spf_visit(walk, _spf_terms(record), top_term, (*through, target), denied, authorising)
    else:
        _spf_visit(walk, _spf_terms(record), term, (), denied, authorising)


def _within(inner: IPNetwork, outer: IPNetwork) -> bool:
    """`inner` lies inside `outer`; never across address families."""
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def _overlaps(one: IPNetwork, other: IPNetwork) -> bool:
    """`one` and `other` share an address; never across address families."""
    if isinstance(one, ipaddress.IPv4Network) and isinstance(other, ipaddress.IPv4Network):
        return one.overlaps(other)
    if isinstance(one, ipaddress.IPv6Network) and isinstance(other, ipaddress.IPv6Network):
        return one.overlaps(other)
    return False


def _spf_range_notes(terms: list[tuple[str, str, str]], ranges: list[_SPFRange]) -> list[str]:
    """What the record's own ranges say beyond what they authorise.

    A range written from an inner address (qnap.com: ip4:113.196.74.98/27)
    covers the whole block, whatever was meant; a range a record it pulls
    in already authorises is listed twice. Neither changes the verdict: these
    are notes, not issues.
    """
    notes = []
    tested = True
    for qualifier, name, rest in terms:
        if name == "all":
            # Nothing after `all` is tested: no range there repeats anything
            tested = False
            continue
        found = _spf_network(name, rest)
        if not found:
            continue
        value, network = found
        # The address written against the network's first: comparing the text
        # would report 2001:DB8::/64, which is aligned and only spelled otherwise
        written = ipaddress.ip_address(value.split("/")[0])
        if "/" in value and written != network.network_address:
            size = (f"{network.num_addresses} addresses" if network.version == 4
                    else f"a /{network.prefixlen}")
            # What the qualifier does to the whole range (RFC 7208 §4.6.2):
            # "authorises" under -ip4: said the opposite of what the record does
            does = {
                "-": f"denies (fail) all of {network} ({size})",
                "~": f"softfails all of {network} ({size})",
                "?": f"marks all of {network} ({size}) neutral",
            }.get(qualifier, f"authorises all of {network} ({size})")
            notes.append(
                f"SPF {qualifier}{name}:{value} is written from an address inside the range — "
                f"it {does}, not {value.split('/')[0]} alone"
            )
        if not tested or qualifier not in ("", "+"):
            continue
        for nested in ranges:
            if _within(network, nested.network) and not any(
                _overlaps(network, other) for other in nested.denied
            ):
                path = "".join(f", through {hop}" for hop in nested.through)
                notes.append(
                    f"SPF {qualifier}{name}:{value} is already authorised by "
                    f"{nested.term} ({nested.network}{path}) — redundant"
                )
                break
    return notes


@_unless_dns_fails("SPF", SPFResult)
def check_spf(domain: str) -> SPFResult:
    result = SPFResult()
    records = [record for record in _query_txt(domain) if _is_spf(record)]

    if not records:
        result.issues.append("No SPF record found")
        return result

    result.present = True
    result.raw = records[0]

    # RFC 7208 §4.5: more than one record is a permerror, not "the first one"
    if len(records) > 1:
        result.permerror = True
        result.issues.append(
            f"Multiple SPF records ({len(records)}) — permerror, receivers apply no SPF"
        )
        return result

    terms = _spf_terms(records[0])
    result.all_mechanism = _spf_all(terms)

    syntax_errors = _spf_syntax_errors(records[0])
    if syntax_errors:
        result.permerror = True
        result.issues.extend(
            f"SPF term {term} {wrong} — permerror, receivers apply no SPF"
            for term, wrong in syntax_errors
        )
        return result

    walk = _spf_walk(terms)
    result.lookups = walk.lookups
    result.lookups_partial = bool(walk.unexpanded)
    if walk.over_limit:
        result.permerror = True
        result.issues.append(
            f"SPF needs more than {SPF_MAX_LOOKUPS} DNS lookups — permerror, receivers apply no SPF"
        )
        return result
    # An include: or redirect= whose target has no single SPF record, or one
    # with a syntax error (RFC 7208 §5.2, §6.1)
    if walk.errors:
        result.permerror = True
        result.issues.extend(walk.errors)
        return result

    # RFC 7208 §6.1: with no `all`, redirect= hands the verdict to another
    # record, which the walk has fetched. The chain is finite: a loop would
    # have failed the count above.
    redirected = terms
    via = ""
    unexpanded = ""
    open_ranges: list[str] = []
    while not result.all_mechanism and (target := _spf_redirect(redirected)):
        if _spf_macro(target):
            unexpanded = f"redirect={target}"
            break
        redirected = _spf_terms(walk.records.get(target) or "")
        result.all_mechanism = _spf_all(redirected)
        # The verdict is the target's: the record shown has no `all` of its own
        via = f" via redirect={target}"
        open_ranges += [f"{term}{via}" for term in _spf_open_ranges(redirected)]

    _apply_spf_verdict(result, terms, via, unexpanded, tuple(open_ranges))
    result.notes.extend(_spf_range_notes(terms, walk.ranges))
    if walk.unexpanded:
        result.notes.append(
            f"SPF needs at least {result.lookups} of {SPF_MAX_LOOKUPS} DNS lookups — macros are "
            f"not expanded, so the lookups behind {', '.join(walk.unexpanded)} are not counted"
        )
    elif result.lookups == SPF_MAX_LOOKUPS:
        result.notes.append(
            f"SPF needs {SPF_MAX_LOOKUPS} of {SPF_MAX_LOOKUPS} DNS lookups — at the limit, "
            "one more include, a or mx makes it a permerror"
        )
    return result


def _spf_open_ranges(terms: list[tuple[str, str, str]]) -> list[str]:
    """The pass ranges with prefix length 0 that the evaluation reaches: they
    cover every address of their family (RFC 7208 §5.6), so any server
    passes, as with +all. One after `all` is never tested."""
    found = []
    for qualifier, name, rest in terms:
        if name == "all":
            break
        # Only a pass term written with /0 can be one: checked on the text first,
        # since parsing every ip4:/ip6: term made the evaluation four times slower
        # (CodSpeed, test_bench_spf, 176 → 688 µs on qwant.com's six ranges)
        if qualifier not in ("", "+") or not rest.endswith("/0"):
            continue
        network = _spf_network(name, rest)
        if network and network[1].prefixlen == 0:
            found.append(f"{qualifier}{name}:{network[0]}")
    return found


def _apply_spf_verdict(result: SPFResult, terms: list[tuple[str, str, str]], via: str = "",
                       unexpanded: str = "", open_ranges: tuple[str, ...] = ()) -> None:
    """
    Score and annotate `result` from its `all` mechanism and the record's
    `terms`. No DNS: the lookups, which may change `all_mechanism` through
    redirect=, are check_spf's and have already been made; `via` names the
    redirect= the `all` came from, if it did, and `unexpanded` the redirect=
    with a macro the verdict was handed to, which could not be followed.
    `open_ranges` are the /0 ranges of the records redirect= led to; the
    record's own are read from `terms`.
    """
    if result.all_mechanism == "-all":
        result.permissive = False
        result.score += 20
    elif result.all_mechanism == "~all":
        result.permissive = True
        result.issues.append(f"SPF uses ~all (softfail){via} — consider -all (hardfail)")
        result.score += 10
    elif result.all_mechanism == "+all":
        result.permissive = True
        result.issues.append(f"SPF uses +all{via} — any server can send as this domain!")
        result.score += 0
    elif result.all_mechanism == "?all":
        result.permissive = True
        result.issues.append(f"SPF uses ?all (neutral){via} — no enforcement")
        result.score += 5
    elif unexpanded:
        # RFC 7208 §6.1: the redirect= applies, and the result is its target's;
        # "no all mechanism, neutral" described a record without one
        result.permissive = True
        result.issues.append(
            f"SPF hands its verdict to {unexpanded}{via}, a macro MailRadar does not expand — "
            "the result is not checked"
        )
    else:
        # RFC 7208 §4.7: no `all` and no redirect= ends in neutral
        result.permissive = True
        result.issues.append("SPF has no all mechanism — the default result is neutral, no enforcement")

    # ip4:0.0.0.0/0 under -all passes every IPv4 server: it is +all, and
    # scored 20
    if result.all_mechanism != "+all":
        for term in (*_spf_open_ranges(terms), *open_ranges):
            family = "IPv4" if "ip4:" in term else "IPv6"
            result.permissive = True
            result.score = 0
            result.issues.append(
                f"SPF {term} passes every {family} address, as +all does — "
                "any server can send as this domain!"
            )


def _ed25519_bits(key: str) -> int:
    """256 for a valid Ed25519 public key (32 raw bytes, not DER), 0 otherwise."""
    import base64
    import binascii

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True))
    except (ValueError, binascii.Error):
        return 0
    return 256


def _rsa_bits(key_part: str) -> int:
    """The modulus size of an RSA public key in DER, 0 if `key_part` is not one.

    SubjectPublicKeyInfo, which nearly everyone publishes, or the bare PKCS#1
    RSAPublicKey that RFC 6376 §3.6.1 names; load_der_public_key reads both.
    The length of the text says nothing: a 2048-bit key cut at 255 characters
    read as 1024-bit, and 400 'A' as 2048-bit.
    """
    import base64

    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    try:
        # Missing padding is common and harmless; any other character is not base64
        der = base64.b64decode(key_part + "=" * (-len(key_part) % 4), validate=True)
        pub = load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm):
        return 0
    return pub.key_size if isinstance(pub, RSAPublicKey) else 0


# The selectors check_dkim asks about when none is given. A selector is the
# sender's choice and DNS has no way to list them, so this is the set the
# common providers use: Google, Microsoft 365 (selector1/2), Proton
# (protonmail*), Fastmail (fm*), Amazon SES, Zendesk, Mailchimp/Mandrill (k*),
# SendGrid (s*), Mimecast, Campaign Monitor (cm), Postmark (pm). A key under
# none of them is "not found", never "absent": Amazon, Proofpoint and others
# sign under selectors of their own.
DKIM_SELECTORS = [
    "default", "mail", "email", "dkim", "google",
    "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "protonmail", "protonmail2", "protonmail3", "pm", "fm1", "fm2", "fm3",
    "amazonses", "zendesk1", "zendesk2",
    "mimecast", "mandrill", "sendgrid", "mailchimp", "cm", "dkim1", "dkim2", "smtp",
    "20230601", "20240101", "20250324",
]


# A DKIM selector is one or more DNS labels (RFC 6376 §3.1); anything else in
# s= is not a name a key can be published under
_DKIM_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"
_DKIM_SELECTOR = re.compile(rf"{_DKIM_LABEL}(?:\.{_DKIM_LABEL})*")


def dkim_selectors_in(message: bytes, domain: str) -> list[str]:
    """The selectors (s=) of the DKIM-Signature headers of `message` signed for `domain` (d=), in order.

    Common selectors miss most of what bulk senders use: Amazon SES signs with
    a random 32-letter selector, and a received message names it in clear.
    Signatures for another domain (the sending service's own) are left out:
    they say nothing about `domain`'s keys. RFC 6376 §3.5: d= and s= are tags
    of the header's tag list; folding whitespace may sit anywhere in it.
    """
    import email.parser
    import email.policy

    headers = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(message)
    domain = domain.removesuffix(".").lower()
    found: list[str] = []
    for value in headers.get_all("DKIM-Signature") or []:
        tags = {key: re.sub(r"\s+", "", tag) for key, tag in _parse_tags(re.sub(r"\s+", " ", str(value))).items()}
        if tags.get("d", "").removesuffix(".").lower() != domain:
            continue
        selector = tags.get("s", "")
        if _DKIM_SELECTOR.fullmatch(selector) and selector not in found:
            found.append(selector)
    return found


@dataclass(frozen=True)
class _DKIMKey:
    """What a DKIM key record publishes, as far as scoring goes."""
    # k= in lower case: "rsa" (the default), "ed25519" (RFC 8463), or a type
    # neither RFC defines
    key_type: str
    # 0 when p= is no key of that type
    bits: int
    # Why no signature can be verified with it; "" when one can
    problem: str
    # t=y (RFC 6376 §3.6.1): the domain is testing DKIM
    testing: bool


# The tags of a DKIM key record (RFC 6376 §3.6.1), v= aside
_DKIM_TAGS = frozenset({"g", "h", "k", "n", "p", "s", "t"})


def _is_dkim(record: str) -> bool:
    """A DKIM key record: v=DKIM1 as its first tag, or no v= and DKIM's own tags.

    RFC 6376 §3.6.1: v= is optional, must come first and be DKIM1. A DMARC
    record holds 'p=' and was read as a 512-bit key.
    """
    tags = _parse_tags(record)
    if "v" in tags:
        return next(iter(tags)) == "v" and tags["v"] == "DKIM1"
    return bool(_DKIM_TAGS & tags.keys())


@functools.lru_cache(maxsize=256)
def _dkim_key(record: str) -> _DKIMKey | None:
    """The key a DKIM key record publishes; None when p= is empty (RFC 6376 §3.6.1: revoked).

    Cached by record: the DER parse is the costly part, and the same key is
    often published under several selectors (each a CNAME to the provider's).
    """
    tags = _parse_tags(record)
    key_type = tags.get("k", "rsa").lower()
    testing = "y" in (flag.strip() for flag in tags.get("t", "").split(":"))
    if "p" not in tags:
        # p= is required; only an empty one means revoked
        return _DKIMKey(key_type, 0, "no p= tag", testing)
    key_part = "".join(tags["p"].split())
    if not key_part:
        return None
    if key_type == "ed25519":
        bits = _ed25519_bits(key_part)
        return _DKIMKey(key_type, bits, "" if bits else "p= is not a 32-byte Ed25519 key", testing)
    if key_type == "rsa":
        bits = _rsa_bits(key_part)
        return _DKIMKey(key_type, bits, "" if bits else "p= does not decode as an RSA public key", testing)
    return _DKIMKey(key_type, 0, f"k={key_type} is a key type neither RFC 6376 nor RFC 8463 defines", testing)


def _describe_key(key: _DKIMKey) -> str:
    if key.problem:
        name = {"rsa": "RSA key", "ed25519": "Ed25519 key"}.get(key.key_type, f"key (k={key.key_type})")
        description = f"malformed {name}"
    else:
        description = "Ed25519" if key.key_type == "ed25519" else f"{key.bits}-bit RSA"
    return f"{description} (testing, t=y)" if key.testing else description


def dkim_unusable(dkim: DKIMResult) -> bool:
    """The key the DKIM result rests on gives no signature a receiver counts:
    malformed (no length), of a type no verifier knows, or only in testing mode
    (RFC 6376 §3.6.1). From what the check found, not from the score, whose 0
    is also the default of a result nobody scored."""
    if not dkim.present:
        return False
    return (not dkim.key_bits or dkim.key_type not in ("rsa", "ed25519")
            or "(testing, t=y)" in dkim.keys.get(dkim.selector, ""))


# Why an RSA DKIM key under 2048 bits is an issue, in the words of the rules it breaks.
# RFC 8301 §3.2, the rule written for DKIM: signers must use RSA keys of at least
# 1024 bits and should use at least 2048; verifiers must not consider valid a
# signature made with a key under 1024 bits (RFC 6376 §3.9: it fails for good).
# https://www.rfc-editor.org/rfc/rfc8301.html#section-3.2
# NIST SP 800-131A Rev. 2 (2019), §3: RSA signature generation with
# less than 112 bits of security strength (a modulus under 2048 bits) is disallowed.
# https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
# Why it matters for DKIM in particular: the public key sits in DNS for anyone to
# take, is rarely rotated, and whoever factors it signs mail that passes DKIM and
# DMARC. RSA-1024 has not been factored in public; a 2026 estimate from the GPU
# factorings of RSA-260 and RSA-896 puts it near 1,000 GPU-years
# (https://dmarcdkim.com/blog/cracking-a-1024-bit-dkim-key, an extrapolation by a
# DMARC vendor, cited for context and not as a measurement).
_RSA_SIGNING_RULE = "NIST SP 800-131A Rev. 2 disallows RSA under 2048 bits for new signatures"
_DKIM_SIGNER_RULE = "RFC 8301 §3.2 asks DKIM signers for at least 2048 bits"
_DKIM_VERIFIER_RULE = "RFC 8301 §3.2: verifiers must not accept signatures made with it"


def _key_strength(key: _DKIMKey) -> int:
    """A rank for 'weakest key': a valid Ed25519 key is as strong as RSA 2048 (RFC 8463), a malformed one is nothing."""
    if key.problem:
        return 0
    return 2048 if key.key_type == "ed25519" else key.bits


@_unless_dns_fails("DKIM", DKIMResult)
def check_dkim(domain: str, selectors: list[str] | None = None) -> DKIMResult:
    """
    The DKIM keys published under `selectors` (the common ones by default).
    Every selector is asked for, because a receiver verifies a signature made
    with any published key: the weakest one is the posture, and the result
    names them all.
    """
    result = DKIMResult()
    selectors_to_try = selectors or DKIM_SELECTORS
    result.tried = len(selectors_to_try)
    failed: DNSLookupError | None = None
    revoked: list[str] = []
    keys: list[tuple[str, _DKIMKey, str]] = []  # selector, key, record

    too_long: list[str] = []

    for selector in selectors_to_try:
        try:
            records = _query_txt(f"{selector}._domainkey.{domain}")
        except InvalidDomainError:
            # Past 255 octets: no key can be published under that name
            too_long.append(selector)
            continue
        except DNSLookupError as e:
            # One selector that fails says nothing about the next one
            failed = failed or e
            continue
        for record in records:
            if _is_dkim(record):
                key = _dkim_key(record)
                if key is None:
                    # After a rotation the active key is on another selector
                    revoked.append(selector)
                else:
                    keys.append((selector, key, record))
                break

    if keys:
        # The weakest key a signature can be verified with is the posture. A
        # malformed key verifies nothing, and a key in testing mode makes its
        # mail count as unsigned (RFC 6376 §3.6.1): neither lets anyone forge
        # a signature that counts, so each decides only when no other does.
        working = [entry for entry in keys if not entry[1].problem]
        signing = [entry for entry in working if not entry[1].testing]
        selector, key, record = min(signing or working or keys, key=lambda entry: _key_strength(entry[1]))
        bits = key.bits
        result.present = True
        result.selector = selector
        result.key_type = key.key_type
        result.key_bits = bits
        result.raw = record
        result.keys = {name: _describe_key(published) for name, published, _ in keys}
        others = ", ".join(f"{name} {description}" for name, description in result.keys.items())
        found = f" (keys found: {others})" if len(result.keys) > 1 else ""

        for name, published, _ in keys:
            if published.problem:
                result.issues.append(
                    f"DKIM key under {name} is malformed ({published.problem}) — signatures cannot be verified"
                )
            elif published.testing:
                result.issues.append(
                    f"DKIM key under {name} is in testing mode (t=y) — receivers treat its signatures "
                    "as unsigned (RFC 6376 §3.6.1)"
                )

        if not signing:
            # Nothing a receiver would count as signed: no points
            pass
        elif key.key_type == "ed25519":
            # RFC 8463: 256 bits of elliptic curve, stronger than RSA 2048
            result.score += 15
        elif bits >= 2048:
            result.score += 15
        elif bits >= 1024:
            result.score += 10
            result.issues.append(f"DKIM key under {selector} is 1024-bit — {_DKIM_SIGNER_RULE}, and "
                                 f"{_RSA_SIGNING_RULE}: upgrade to 2048-bit{found}")
        else:
            result.score += 3
            result.issues.append(f"DKIM key under {selector} is a weak {bits}-bit RSA key — {_DKIM_VERIFIER_RULE}, "
                                 f"and {_RSA_SIGNING_RULE}: upgrade to 2048-bit immediately{found}")
        return result

    if failed:
        raise failed
    if len(too_long) == result.tried:
        result.issues.append(
            f"No DKIM selector can be checked — <selector>._domainkey.{domain} is longer than 255 octets "
            "for every selector, so no DKIM key can be published under this domain"
        )
    elif revoked:
        # Some domains revoke every name at once (example.com answers p= for
        # all of them): the first is enough to say it
        result.selector = revoked[0]
        more = f" and {len(revoked) - 1} more" if len(revoked) > 1 else ""
        result.issues.append(
            f"DKIM key revoked (empty p=) on selector {revoked[0]}{more} — no active key found"
        )
    else:
        result.issues.append(
            f"No DKIM key found under {result.tried} common selectors — a custom selector cannot be ruled out: "
            "check the s= tag of a received message's DKIM-Signature header"
        )

    return result


def _well_formed(url: str) -> bool:
    """A URL with a scheme and a host that urllib can take apart, port included.

    It comes from the analysed domain's DNS: urlsplit raises ValueError on
    https://[::1/logo.svg, and .port on a port past 65535, and either ended the
    whole analysis.
    """
    try:
        parts = urlsplit(url)
        # Read for its check alone: it raises on a port that is no number in range
        _ = parts.port
    except ValueError:
        return False
    return bool(parts.scheme and parts.hostname)


# One part of an IPv4 address as inet_aton reads it: hex (0x), octal (a
# leading 0) or decimal
_INET_ATON_PART = re.compile(r"0[xX][0-9a-fA-F]*|[0-9]+")


def _inet_aton(host: str) -> ipaddress.IPv4Address | None:
    """The address glibc's inet_aton reads in `host`, or None if it reads none.

    getaddrinfo asks it before any DNS, so on Linux (the Docker image)
    https://127.1/, https://2130706433/ and https://0x7f000001/ reach
    127.0.0.1; ipaddress accepts only the dotted-quad form. One to four parts:
    the last fills the bytes the others leave.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_INET_ATON_PART.fullmatch(part) for part in parts):
        return None
    values = []
    for part in parts:
        if part[:2].lower() == "0x":
            values.append(int(part[2:] or "0", 16))
        elif part.startswith("0") and len(part) > 1:
            if not set(part) <= set("01234567"):
                return None
            values.append(int(part, 8))
        else:
            values.append(int(part))
    *head, last = values
    if any(value > 255 for value in head) or last >= 256 ** (4 - len(head)):
        return None
    number = last
    for position, value in enumerate(head):
        number |= value << (8 * (3 - position))
    return ipaddress.IPv4Address(number)


def _fetchable(url: str) -> bool:
    """
    An https URL that does not name a private, loopback or link-local address.
    BIMI requires https, and l= comes from the analysed domain's DNS, so from a
    third party: fetching anything it says would let it point this tool at
    http://127.0.0.1:8080/admin on the network it runs from.
    """
    if not _well_formed(url):
        return False
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme.lower() != "https":
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    # A host made of numbers alone is an IPv4 literal to getaddrinfo, in
    # whatever form, or nothing at all: no top-level domain is numeric. The
    # trailing dot of a fully qualified name does not make it a name.
    labels = host.removesuffix(".").split(".")
    if all(_INET_ATON_PART.fullmatch(label) for label in labels):
        address = _inet_aton(".".join(labels))
        return address is not None and address.is_global
    # A host name. What it resolves to is not checked here.
    return True


def _has_address(host: str) -> bool:
    """Whether DNS gives `host` an address; an IP literal has one. DNSLookupError if DNS does not answer."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        _require_valid_name(host)
    except InvalidDomainError:
        return False
    for rdtype in ("A", "AAAA"):
        try:
            dns.resolver.resolve(host, rdtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as e:
            raise DNSLookupError(f"DNS lookup for {host} failed: {type(e).__name__}") from e
    return False


def _unanswered(url: str, error: httpx.TransportError) -> HTTPFetchError | None:
    """What a GET of `url` that got no answer means for the check.

    An HTTPFetchError, to leave the check not verified, unless the connection
    failed because DNS has no address for the host: then no server exists to
    answer, which is the domain's doing (mta-sts.<domain> never set up), and
    None says to report it as a finding.
    """
    host = urlsplit(url).hostname or ""
    if isinstance(error, httpx.ConnectError) and not _has_address(host):
        return None
    return HTTPFetchError(f"GET {url} got no answer from {host}: {type(error).__name__}")


@_unless_dns_fails("BIMI", BIMIResult)
def check_bimi(domain: str) -> BIMIResult:
    result = BIMIResult()
    records = _query_txt(f"default._bimi.{domain}")

    for record in records:
        if record.startswith("v=BIMI1"):
            result.present = True
            result.raw = record

            tags = _parse_tags(record)

            result.svg_url = tags.get("l", "")
            result.vmc_url = tags.get("a", "")

            # `v=BIMI1; l=; a=;` is how a domain says it does not take part
            if not result.svg_url and not result.vmc_url:
                result.issues.append("BIMI declined by the domain (empty l= and a=)")
                break

            # The VMC is not fetched, but a= has to name one that could be
            if result.vmc_url and not _well_formed(result.vmc_url):
                result.issues.append(f"BIMI VMC URL is malformed ({result.vmc_url!r}) — no VMC")
            elif result.vmc_url and urlsplit(result.vmc_url).scheme.lower() != "https":
                result.issues.append("BIMI VMC URL is not an https:// URL — no VMC")
            else:
                result.vmc_present = bool(result.vmc_url)

            # Validate SVG
            if result.svg_url and not _well_formed(result.svg_url):
                result.issues.append(f"BIMI logo URL is malformed ({result.svg_url!r}) — not fetched")
            elif result.svg_url and not _fetchable(result.svg_url):
                result.issues.append("BIMI logo URL is not a public https:// URL — not fetched")
            elif result.svg_url:
                try:
                    resp = httpx.get(result.svg_url, timeout=5)
                    result.svg_valid = resp.status_code == 200
                    if not result.svg_valid:
                        result.issues.append(f"BIMI SVG not accessible: HTTP {resp.status_code}")
                except httpx.InvalidURL:
                    # urllib took it apart, httpx does not: 0177.0.0.1, a host with a space
                    result.issues.append(f"BIMI logo URL is malformed ({result.svg_url!r}) — not fetched")
                except httpx.TransportError as e:
                    unanswered = _unanswered(result.svg_url, e)
                    if unanswered:
                        raise unanswered from e
                    result.issues.append(
                        f"BIMI logo host {urlsplit(result.svg_url).hostname} does not exist in DNS — "
                        "the logo cannot be fetched"
                    )
                except httpx.HTTPError as e:
                    # An answer that could not be read (a body that does not decode)
                    result.issues.append(f"BIMI SVG not accessible: {type(e).__name__}")

            if result.vmc_present:
                result.score += 8
            else:
                result.issues.append("BIMI present but no VMC — logo not verified by CA")
                result.score += 3

            if result.svg_valid:
                result.score += 2

            break

    if not result.present:
        result.issues.append("No BIMI record configured")

    return result


# RFC 8461 §3.1: the record begins with v=STSv1, then ';' (spaces around it
# allowed) or nothing more
_STS_RECORD = re.compile(r"v=STSv1[ \t]*(;|$)")
_STS_ID = re.compile(r"[A-Za-z0-9]{1,32}")
# §3.2: max_age is 1 to 10 digits, at most 31557600 seconds (about a year)
_STS_MAX_AGE = re.compile(r"[0-9]{1,10}")
_STS_MAX_AGE_LIMIT = 31557600


def _mta_sts_policy(text: str) -> tuple[str, list[str]]:
    """The mode of an MTA-STS policy file and what makes it invalid (RFC 8461 §3.2).

    `key: value` lines ending in CRLF or LF; mx may repeat, unknown keys are
    ignored. A policy needs version STSv1, a mode, max_age, and at least one
    mx in enforce or testing mode: senders discard one that lacks any of them.
    """
    fields: dict[str, str] = {}
    mx: list[str] = []
    for line in text.splitlines():
        key, colon, value = line.partition(":")
        if not colon:
            continue
        key, value = key.strip(), value.strip()
        if key == "mx":
            mx.append(value)
        else:
            fields.setdefault(key, value)

    problems = []
    version = fields.get("version")
    if version is None:
        problems.append("no version: STSv1")
    elif version != "STSv1":
        problems.append(f"version: {version} is not STSv1")
    mode = fields.get("mode", "")
    if not mode:
        problems.append("no mode")
    elif mode not in ("enforce", "testing", "none"):
        problems.append(f"mode: {mode} is not enforce, testing or none")
    max_age = fields.get("max_age")
    if max_age is None:
        problems.append("no max_age")
    elif not _STS_MAX_AGE.fullmatch(max_age) or int(max_age) > _STS_MAX_AGE_LIMIT:
        problems.append(f"max_age: {max_age} is not a number of seconds up to {_STS_MAX_AGE_LIMIT}")
    if mode in ("enforce", "testing") and not any(mx):
        problems.append(f"no mx, which mode {mode} requires")
    return mode, problems


@_unless_dns_fails("MTA-STS", MTASTSResult)
def check_mta_sts(domain: str) -> MTASTSResult:
    result = MTASTSResult()
    name = f"_mta-sts.{domain}"
    records = _query_txt(name)

    # RFC 8461 §3.1: records that do not begin with v=STSv1 are discarded, and
    # with none or several left, or one that is invalid, senders look for no
    # policy: there is nothing to fetch
    announced = [record for record in records if _STS_RECORD.match(record)]
    if not announced:
        if any("v=STSv1" in record for record in records):
            result.issues.append(
                f"MTA-STS record on {name} does not begin with v=STSv1 — senders ignore it (RFC 8461 §3.1)"
            )
        else:
            result.issues.append("No MTA-STS configured")
        return result
    if len(announced) > 1:
        result.issues.append(
            f"Multiple MTA-STS records ({len(announced)}) on {name} — senders apply no policy (RFC 8461 §3.1)"
        )
        return result
    if not _STS_ID.fullmatch(_parse_tags(announced[0]).get("id", "")):
        result.issues.append(
            f"MTA-STS record on {name} has no valid id= (1 to 32 letters and digits) — "
            "senders apply no policy (RFC 8461 §3.1)"
        )
        return result

    result.present = True
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = httpx.get(url, timeout=5)
    except httpx.TransportError as e:
        unanswered = _unanswered(url, e)
        if unanswered:
            raise unanswered from e
        result.issues.append(
            f"MTA-STS policy host mta-sts.{domain} does not exist in DNS — senders find no policy"
        )
        return result
    except httpx.HTTPError as e:
        # An answer that could not be read (a body that does not decode)
        result.issues.append(f"MTA-STS policy file not accessible: {type(e).__name__}")
        return result

    if resp.status_code != 200:
        # The TXT record alone does nothing: senders need the policy
        result.issues.append(f"MTA-STS policy file not accessible: HTTP {resp.status_code}")
        return result

    mode, problems = _mta_sts_policy(resp.text)
    if problems:
        result.issues.append(
            f"MTA-STS policy is invalid — {'; '.join(problems)}: senders apply no policy (RFC 8461 §3.2)"
        )
    elif mode == "enforce":
        result.mode = mode
        result.score += 5
    elif mode == "testing":
        result.mode = mode
        result.score += 2
        result.issues.append("MTA-STS in testing mode — upgrade to enforce")
    else:
        # RFC 8461 §5: a valid mode, the one that withdraws the policy
        result.mode = mode
        result.issues.append("MTA-STS mode none — policy disabled, upgrade to enforce")

    return result


# RFC 8460 §3: the record begins with v=TLSRPTv1, then ';' or nothing more;
# rua lists URIs, separated by commas, and only mailto: and https: are defined
_TLSRPT_RECORD = re.compile(r"v=TLSRPTv1[ \t]*(;|$)")
_TLSRPT_URI = re.compile(r"(mailto|https):\S+", re.IGNORECASE)


@_unless_dns_fails("TLS-RPT", TLSRPTResult)
def check_tls_rpt(domain: str) -> TLSRPTResult:
    result = TLSRPTResult()
    name = f"_smtp._tls.{domain}"
    # RFC 8460 §3: records that do not begin with v=TLSRPTv1 are discarded,
    # and with any number left but one senders assume there is no TLS-RPT
    records = [record for record in _query_txt(name) if _TLSRPT_RECORD.match(record)]

    if not records:
        result.issues.append("No TLS-RPT configured")
        return result
    if len(records) > 1:
        result.issues.append(
            f"Multiple TLS-RPT records ({len(records)}) on {name} — senders assume the domain "
            "has no TLS-RPT (RFC 8460 §3)"
        )
        return result

    # The rua tag, not the text after the last 'rua=': a URI can hold one
    result.rua = _parse_tags(records[0]).get("rua", "")
    uris = [uri.strip() for uri in result.rua.split(",") if uri.strip()]
    if not uris:
        result.issues.append(f"TLS-RPT record on {name} has no rua — it names nobody to send reports to (RFC 8460 §3)")
        return result
    invalid = [uri for uri in uris if not _TLSRPT_URI.fullmatch(uri)]
    if len(invalid) == len(uris):
        result.issues.append(
            f"TLS-RPT rua={result.rua} is not a mailto: or https: URI — no reports can be sent (RFC 8460 §3)"
        )
        return result
    for uri in invalid:
        result.issues.append(f"TLS-RPT rua entry {uri!r} is not a mailto: or https: URI — no reports go there")

    result.present = True
    result.score += 3
    return result


# The highest raw score each check can reach. They sum to more than 100, so
# analyze_domain normalises the total onto a 0-100 scale.
MAX_SCORES = {
    "dmarc": 50,    # reject 30 + pct 5 + adkim 5 + aspf 5 + rua 3 + ruf 2
    "spf": 20,      # -all
    "dkim": 15,     # >= 2048 bit
    "bimi": 10,     # VMC 8 + SVG 2
    "mta_sts": 5,   # enforce
    "tls_rpt": 3,
    "gpg": 5,
}
MAX_RAW_SCORE = sum(MAX_SCORES.values())


def check_mx(domain: str) -> MXResult:
    """The MX records of `domain`, and whether they are a null MX (RFC 7505)."""
    result = MXResult()
    try:
        _require_valid_name(domain)
        answers = dns.resolver.resolve(domain, "MX")
    except InvalidDomainError as e:
        result.error = str(e)
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return result
    except dns.exception.DNSException as e:
        # Not measured, which is not "no MX": the report says nothing about it
        result.error = f"DNS lookup for {domain} MX failed: {type(e).__name__}"
        return result
    records = sorted((rdata.preference, rdata.exchange.to_text()) for rdata in answers)
    result.null = records == [(0, ".")]
    if not result.null:
        result.hosts = [exchange for _, exchange in records]
    return result


def _spf_authorises_senders(spf: SPFResult) -> bool:
    """True when the SPF record names a sender: any term but `all` and `exp=`.

    `v=spf1 -all` is how a domain that sends no mail says so (RFC 7505 §4.2).
    """
    if not spf.present:
        return False
    terms = spf.raw.split()[1:]
    return any(term.lstrip("+-~?").split(":")[0].split("/")[0].split("=")[0].lower() not in ("all", "exp")
               for term in terms)


def _mx_findings(report: DomainReport) -> None:
    """What the MX records mean for a domain that sends mail. No points either way.

    A domain sends mail when its SPF record names a sender or it publishes a
    DKIM key. For one that does not, a missing or null MX is what it should be.
    """
    mx = report.mx
    if mx.error or mx.hosts:
        return
    if not (_spf_authorises_senders(report.spf) or report.dkim.present):
        return
    domain = report.domain
    if mx.null:
        # RFC 7505 §4.2: a domain used as envelope sender or From SHOULD NOT
        # publish a null MX; §4.1: a receiver that rejects mail for it uses
        # 550 5.7.27. https://www.rfc-editor.org/rfc/rfc7505.html
        mx.issues.append(
            f"{domain} publishes a null MX (it accepts no mail) yet sends mail — receivers may reject "
            "mail from it with 550 5.7.27, and no reply or bounce can reach it (RFC 7505 §4.1, §4.2)"
        )
        return
    # RFC 5321 §5.1: with no MX, the domain's own address is used as an
    # implicit MX of preference 0. https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1
    # Spam filters score a From domain without MX: Infomaniak's rspamd added
    # MIME_FROM_MX_NONE (+4.45) to a message seen on 2026-11-19 (context, one
    # receiver, not a measurement of all of them).
    mx.notes.append(
        f"{domain} sends mail but publishes no MX — replies and bounces go to its A/AAAA address, if any "
        "(RFC 5321 §5.1 implicit MX), and some spam filters score a From domain without MX"
    )


def _bimi_under_dmarc(bimi: BIMIResult, dmarc: DMARCResult) -> None:
    """Withhold BIMI's points when DMARC does not enforce.

    Mail clients display a BIMI logo only for mail under a DMARC policy of
    quarantine or reject (the policy that applies to the domain, sp= included):
    with p=none, or no DMARC, the logo and its VMC are never shown. A DMARC
    check that was not verified says nothing either way, and leaves no total.
    """
    if not bimi.score or dmarc.error:
        return
    if dmarc.present and dmarc.policy in ("quarantine", "reject"):
        return
    policy = f"p={dmarc.policy}" if dmarc.present else "absent"
    bimi.issues.append(
        f"BIMI logo is never displayed: DMARC policy is {policy}, and mail clients show BIMI "
        "only under quarantine or reject — no BIMI points until DMARC enforces"
    )
    bimi.score = 0


def system_resolver_addresses() -> list[str]:
    """The addresses of the resolvers dnspython asks, as text.

    A separate function so the tests can say which resolver answered: the
    machine running the suite must not decide whether a view looks internal.
    """
    servers = dns.resolver.get_default_resolver().nameservers
    return [str(getattr(server, "address", server)) for server in servers]


def resolver_is_private(addresses: list[str]) -> bool:
    """Whether every resolver is on a private or local address (RFC 1918, RFC 4193, loopback, link-local).

    One public resolver among them means answers may come from the public view,
    and something that is not an address (a DoH URL) says nothing either way.
    """
    if not addresses:
        return False
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_private:
                return False
        except ValueError:
            return False
    return True


# The checks that read TXT records, in report order: the ones an internal view
# without TXT records leaves empty
_TXT_CHECKS = (("DMARC", "dmarc"), ("SPF", "spf"), ("DKIM", "dkim"),
               ("BIMI", "bimi"), ("MTA-STS", "mta_sts"), ("TLS-RPT", "tls_rpt"))


# The public resolver asked to compare when a private one returns nothing
# (Cloudflare's, which the DNS fixtures were recorded through). Asking it sends
# the domain's name to Cloudflare: the README and the output say so.
PUBLIC_RESOLVER = "1.1.1.1"


def public_txt(name: str) -> list[str]:
    """The TXT strings `name` has through PUBLIC_RESOLVER, joined per record as _query_txt joins them.

    [] when the name has none; a DNSException when the resolver did not answer
    (a network that blocks outgoing DNS, typically at work).
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [PUBLIC_RESOLVER]
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answers]


def _public_view(domain: str) -> list[str]:
    """Which of SPF and DMARC the public resolver sees for `domain`; raises when it does not answer."""
    seen = []
    if any(r.lower().startswith("v=spf1") for r in public_txt(domain)):
        seen.append("SPF")
    if any(r.lower().startswith("v=dmarc1") for r in public_txt(f"_dmarc.{domain}")):
        seen.append("DMARC")
    return seen


def _suspect_split_horizon(report: DomainReport, resolvers: list[str]) -> None:
    """Compare with the public view when a private resolver returned no TXT record at all (#150).

    An internal (split-horizon) view often holds only the hosts the network
    needs: no SPF, no DMARC, no DKIM, while the public view has them. Graded,
    that read 0/100 with GDPR art. 32 for records that exist.

    A private resolver is also the common case (127.0.0.53 on Ubuntu, a home
    router), so its silence alone proves nothing. The public resolver decides:
    - it sees SPF or DMARC: an internal view, and every TXT check that found
      nothing becomes "not verified", which takes away the grade and the
      provisions through the path a failed lookup already follows;
    - it sees neither: the records are really missing, graded as before, with
      a note that the public resolver was asked;
    - it does not answer: the same as an internal view, said as a doubt.
    """
    if not resolver_is_private(resolvers):
        return
    core = (report.dmarc, report.spf, report.dkim)
    if any(check.present or check.error for check in core):
        return
    where = ", ".join(resolvers)
    domain = report.domain
    try:
        seen = _public_view(domain)
    except dns.exception.DNSException as e:
        report.split_horizon = (
            f"Your resolver ({where}) is on a private network and returned no TXT record for {domain}, "
            f"and the public resolver {PUBLIC_RESOLVER} could not be asked to compare "
            f"({type(e).__name__}): this may be an internal (split-horizon) view of the domain, not "
            "what other mail servers see. Run the check again from a network that uses a public resolver."
        )
        reason = (f"no TXT record from the private resolver {where}, and no answer from "
                  f"{PUBLIC_RESOLVER} to compare: possibly an internal (split-horizon) view")
    else:
        if not seen:
            report.public_view = (
                f"Your resolver ({where}) is on a private network and returned no TXT record for "
                f"{domain}; the public resolver {PUBLIC_RESOLVER} was asked and has no SPF or DMARC "
                "for it either, so the records are missing for every mail server."
            )
            return
        report.split_horizon = (
            f"Your resolver ({where}) is on a private network and returned no TXT record for {domain}, "
            f"but the public resolver {PUBLIC_RESOLVER} returns {' and '.join(seen)} for it: this is an "
            "internal (split-horizon) view of the domain, not what other mail servers see. Run the "
            "check again from a network that uses a public resolver."
        )
        reason = (f"no TXT record from the private resolver {where}, while {PUBLIC_RESOLVER} "
                  f"returns {' and '.join(seen)}: an internal (split-horizon) view")
    for name, attr in _TXT_CHECKS:
        result = getattr(report, attr)
        if not result.present and not result.error:
            setattr(report, attr, type(result)(error=reason, issues=[f"{name} not verified — {reason}"]))


def analyze_domain(domain: str, dkim_selectors: list[str] | None = None) -> DomainReport:
    """Run full email security analysis on a domain.

    `dkim_selectors` are asked for first, then the common ones: the selectors a
    received message names (dkim_selectors_in), which no list of common ones has.
    """
    # Once, here: `Example.COM.` otherwise reached the keyservers as
    # security@Example.COM. and MTA-STS as https://mta-sts.Example.COM./
    domain = ".".join(_labels(domain))
    report = DomainReport(domain=domain)

    report.dmarc = check_dmarc(domain)
    report.spf = check_spf(domain)
    extra = [selector for selector in dkim_selectors or [] if selector not in DKIM_SELECTORS]
    report.dkim = check_dkim(domain, extra + DKIM_SELECTORS if extra else None)
    report.bimi = check_bimi(domain)
    # The one check whose worth depends on another's result
    _bimi_under_dmarc(report.bimi, report.dmarc)
    report.mta_sts = check_mta_sts(domain)
    report.tls_rpt = check_tls_rpt(domain)
    report.mx = check_mx(domain)
    _mx_findings(report)

    # GPG lookup
    from mailradar.gpg import lookup_gpg
    report.gpg = lookup_gpg(domain)

    _suspect_split_horizon(report, system_resolver_addresses())

    if report.unverified:
        # Nothing to grade: "could not tell" is not "bad"
        report.total_score = None
        report.grade = "N/A"
        return report

    raw_score = sum(getattr(report, check).score for check in MAX_SCORES)
    report.total_score = min(100, round(raw_score * 100 / MAX_RAW_SCORE))

    if report.total_score >= 90:
        report.grade = "EXCELLENT"
    elif report.total_score >= 75:
        report.grade = "GOOD"
    elif report.total_score >= 50:
        report.grade = "MODERATE"
    elif report.total_score >= 25:
        report.grade = "POOR"
    else:
        report.grade = "CRITICAL"

    return report
