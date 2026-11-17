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
    key_bits: int = 0
    # The k= tag: "rsa" (the default) or "ed25519" (RFC 8463)
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
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class MTASTSResult:
    present: bool = False
    mode: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    present: bool = False
    rua: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


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
    # None, with grade "N/A", when a DNS lookup got no answer: a check that was
    # not verified scored 0, and the total read as a measured bottom of scale.
    total_score: int | None = 0
    grade: str = "F"

    @property
    def unverified(self) -> list[str]:
        """The checks whose DNS lookup got no answer (timeout, SERVFAIL), in report order.

        GPG is not among them: a keyserver that rate-limits withholds at most its
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
    RFC 7489 §6.6.3 — catena di ricerca del record DMARC: si parte dal
    dominio richiesto e si rimuove una label per volta, fermandosi al
    organizational domain. The public suffix itself is never queried:
    un record pubblicato su `it` o `co.uk` non è la policy del dominio.

    asufc.sanita.fvg.it -> [asufc.sanita.fvg.it, sanita.fvg.it]
    """
    labels = _labels(domain)
    if not labels:
        return []
    chain = [".".join(labels)]
    for i in range(1, len(labels) - _org_depth(labels) + 1):
        chain.append(".".join(labels[i:]))
    return chain


class DNSLookupError(Exception):
    """A lookup that got no answer (timeout, SERVFAIL): not the same as no record."""


def _query_txt(name: str) -> list[str]:
    """Query TXT records for a given name."""
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
    """A check_* whose DNS lookup fails returns a result marked as not verified."""
    def decorate(run: Callable[..., _Result]) -> Callable[..., _Result]:
        @functools.wraps(run)
        def wrapper(*args, **kwargs) -> _Result:
            try:
                return run(*args, **kwargs)
            except DNSLookupError as e:
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


def _apply_dmarc_record(result: DMARCResult, record: str) -> None:
    """Popola e valuta un DMARCResult a partire dal record trovato."""
    result.present = True
    result.raw = record

    # RFC 7489 §6.4: tag names and these values are case-insensitive literals,
    # p=REJECT is p=reject
    tags = {key.lower(): value for key, value in _parse_tags(record).items()}

    result.policy = tags.get("p", "none").lower()
    result.sp = tags.get("sp", "").lower()
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
    # An empty rua= or ruf= names nobody to send reports to (RFC 7489 §6.4)
    result.rua = bool(tags.get("rua"))
    result.ruf = bool(tags.get("ruf"))

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
    Cerca il record DMARC risalendo la gerarchia del dominio (RFC 7489
    §6.6.3): prima `_dmarc.<dominio>`, poi si rimuove una label per volta
    fino al dominio organizzativo.
    """
    result = DMARCResult()
    chain = dmarc_lookup_chain(domain)
    requested = chain[0] if chain else ""

    for candidate in chain:
        records = _dmarc_records(f"_dmarc.{candidate}")
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
                f"from parent domain {candidate}"
            )
        _apply_dmarc_record(result, record)
        break

    if not result.present:
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
        network = _spf_network(name, rest)
        if network and qualifier in ("", "+") and network[1].prefixlen == 0:
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
    """The modulus size of a DER-encoded RSA public key; a length estimate if it does not parse."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    try:
        pub = load_der_public_key(base64.b64decode(key_part + "=="))
        if isinstance(pub, RSAPublicKey):
            return pub.key_size
    except Exception:
        pass
    # Fallback to length estimate
    key_len = len(key_part)
    if key_len > 350:
        return 2048
    if key_len > 170:
        return 1024
    return 512


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


@functools.lru_cache(maxsize=256)
def _dkim_key(record: str) -> tuple[str, int] | None:
    """(key type, bits) of a DKIM key record; None when p= is empty (RFC 6376 §3.6.1: revoked).

    Cached by record: the DER parse is the costly part, and the same key is
    often published under several selectors (each a CNAME to the provider's).
    """
    tags = _parse_tags(record)
    key_part = "".join(tags.get("p", "").split())
    if "p" in tags and not key_part:
        return None
    if tags.get("k", "rsa").lower() == "ed25519":
        return "ed25519", _ed25519_bits(key_part)
    return "rsa", _rsa_bits(key_part) if "p" in tags else 0


def _describe_key(key_type: str, bits: int) -> str:
    return "Ed25519" if key_type == "ed25519" else f"{bits}-bit RSA"


def _key_strength(key_type: str, bits: int) -> int:
    """A rank for 'weakest key': a valid Ed25519 key is as strong as RSA 2048 (RFC 8463), a malformed one is nothing."""
    if key_type == "ed25519":
        return 2048 if bits else 0
    return bits


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
    keys: list[tuple[str, str, int, str]] = []  # selector, type, bits, record

    for selector in selectors_to_try:
        try:
            records = _query_txt(f"{selector}._domainkey.{domain}")
        except DNSLookupError as e:
            # One selector that fails says nothing about the next one
            failed = failed or e
            continue
        for record in records:
            if "v=DKIM1" in record or "p=" in record:
                key = _dkim_key(record)
                if key is None:
                    # After a rotation the active key is on another selector
                    revoked.append(selector)
                else:
                    keys.append((selector, key[0], key[1], record))
                break

    if keys:
        selector, key_type, bits, record = min(keys, key=lambda key: _key_strength(key[1], key[2]))
        result.present = True
        result.selector = selector
        result.key_type = key_type
        result.key_bits = bits
        result.raw = record
        result.keys = {name: _describe_key(kind, size) for name, kind, size, _ in keys}
        others = ", ".join(f"{name} {description}" for name, description in result.keys.items())
        found = f" (keys found: {others})" if len(result.keys) > 1 else ""

        if key_type == "ed25519":
            # RFC 8463: 256 bits of elliptic curve, stronger than RSA 2048
            if bits:
                result.score += 15
            else:
                result.issues.append(
                    f"DKIM Ed25519 key under {selector} is malformed — signatures cannot be verified{found}"
                )
        elif bits >= 2048:
            result.score += 15
        elif bits >= 1024:
            result.score += 10
            result.issues.append(f"DKIM key under {selector} is 1024-bit — upgrade to 2048-bit recommended{found}")
        else:
            result.score += 3
            result.issues.append(f"DKIM key under {selector} is weak — upgrade to 2048-bit immediately{found}")
        return result

    if failed:
        raise failed
    if revoked:
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


def _fetchable(url: str) -> bool:
    """
    An https URL that does not name a private, loopback or link-local address.
    BIMI requires https, and l= comes from the analysed domain's DNS, so from a
    third party: fetching anything it says would let it point this tool at
    http://127.0.0.1:8080/admin on the network it runs from.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        return False
    try:
        return ipaddress.ip_address(parts.hostname).is_global
    except ValueError:
        # A host name. What it resolves to is not checked here.
        return True


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
            result.vmc_present = bool(result.vmc_url and result.vmc_url != "")

            # `v=BIMI1; l=; a=;` is how a domain says it does not take part
            if not result.svg_url and not result.vmc_url:
                result.issues.append("BIMI declined by the domain (empty l= and a=)")
                break

            # Validate SVG
            if result.svg_url and not _fetchable(result.svg_url):
                result.issues.append("BIMI logo URL is not a public https:// URL — not fetched")
            elif result.svg_url:
                try:
                    resp = httpx.get(result.svg_url, timeout=5)
                    result.svg_valid = resp.status_code == 200
                    if not result.svg_valid:
                        result.issues.append(f"BIMI SVG not accessible: HTTP {resp.status_code}")
                except Exception:
                    result.issues.append("BIMI SVG fetch timeout or error")

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


@_unless_dns_fails("MTA-STS", MTASTSResult)
def check_mta_sts(domain: str) -> MTASTSResult:
    result = MTASTSResult()
    records = _query_txt(f"_mta-sts.{domain}")

    for record in records:
        if "v=STSv1" in record:
            result.present = True

            try:
                resp = httpx.get(
                    f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                    timeout=5
                )
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if line.startswith("mode:"):
                            result.mode = line.split(":")[1].strip()
                    if result.mode == "enforce":
                        result.score += 5
                    elif result.mode == "testing":
                        result.score += 2
                        result.issues.append("MTA-STS in testing mode — upgrade to enforce")
                    elif result.mode == "none":
                        # RFC 8461 §5: a valid mode, the one that withdraws the policy
                        result.issues.append("MTA-STS mode none — policy disabled, upgrade to enforce")
                    else:
                        result.issues.append(f"MTA-STS mode unknown: {result.mode}")
                else:
                    # The TXT record alone does nothing: senders need the policy
                    result.issues.append(f"MTA-STS policy file not accessible: HTTP {resp.status_code}")
            except Exception:
                result.issues.append("MTA-STS policy file not accessible")
            break

    if not result.present:
        result.issues.append("No MTA-STS configured")

    return result


@_unless_dns_fails("TLS-RPT", TLSRPTResult)
def check_tls_rpt(domain: str) -> TLSRPTResult:
    result = TLSRPTResult()
    records = _query_txt(f"_smtp._tls.{domain}")

    for record in records:
        if "v=TLSRPTv1" in record:
            result.present = True
            if "rua=" in record:
                result.rua = record.split("rua=")[-1].split(";")[0].strip()
            result.score += 3
            break

    if not result.present:
        result.issues.append("No TLS-RPT configured")

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


def analyze_domain(domain: str) -> DomainReport:
    """Run full email security analysis on a domain."""
    # Once, here: `Example.COM.` otherwise reached the keyservers as
    # security@Example.COM. and MTA-STS as https://mta-sts.Example.COM./
    domain = ".".join(_labels(domain))
    report = DomainReport(domain=domain)

    report.dmarc = check_dmarc(domain)
    report.spf = check_spf(domain)
    report.dkim = check_dkim(domain)
    report.bimi = check_bimi(domain)
    report.mta_sts = check_mta_sts(domain)
    report.tls_rpt = check_tls_rpt(domain)

    # GPG lookup
    from mailradar.gpg import lookup_gpg
    report.gpg = lookup_gpg(domain)

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
