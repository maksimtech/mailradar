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
    raw: str = ""
    score: int = 0
    # Set when a DNS lookup failed: the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


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
    total_score: int = 0
    grade: str = "F"


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

    try:
        dns.resolver.resolve(domain, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.DNSException):
        pass
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.DNSException):
        pass
    try:
        dns.resolver.resolve(domain, "NS")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.DNSException):
        return False


def find_domain_variants(domain: str) -> list[str]:
    """
    Given a domain input, find all existing TLD variants.
    e.g. 'apple' -> ['apple.com', 'apple.it', 'apple.eu', ...]
    """
    # The base name, without the TLD
    parts = domain.split(".")
    base = domain if len(parts) == 1 else parts[0]

    # TLD comuni da provare
    tlds = [
        "com", "it", "eu", "org", "net", "io",
        "co.uk", "de", "fr", "es", "nl", "ch",
        "gov.it", "edu", "info", "biz",
    ]

    found = []
    for tld in tlds:
        candidate = f"{base}.{tld}"
        if domain_exists(candidate):
            found.append(candidate)

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


# RFC 7208 §4.6.4: the terms that cost a DNS query, and how many of them one
# evaluation may make, nested include: and redirect= counted in
_SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
SPF_MAX_LOOKUPS = 10


def _spf_domain(rest: str) -> str:
    """The domain after `include:` or `redirect=`; "" if it holds a macro."""
    target = rest[1:].split("/")[0]
    return "" if "%" in target else target


def _spf_redirect(terms: list[tuple[str, str, str]]) -> str:
    """The target of `redirect=`, ignored when the record has `all` (§6.1)."""
    if _spf_all(terms):
        return ""
    for _, name, rest in terms:
        if name == "redirect" and rest.startswith("="):
            return _spf_domain(rest)
    return ""


def _spf_record_of(name: str) -> str | None:
    """The one SPF record of `name`; None if it has none, or more than one."""
    records = [record for record in _query_txt(name) if _is_spf(record)]
    return records[0] if len(records) == 1 else None


def _spf_lookups(record: str, count: int = 0) -> int:
    """
    DNS lookups the evaluation of `record` needs, including those of the
    records it pulls in. It stops as soon as the limit is passed, which is
    also what ends an include loop.
    """
    terms = _spf_terms(record)
    redirect = _spf_redirect(terms)
    for _, name, rest in terms:
        if name not in _SPF_LOOKUP_TERMS or (name == "redirect" and not redirect):
            continue
        count += 1
        if count > SPF_MAX_LOOKUPS:
            return count
        target = _spf_domain(rest) if name in ("include", "redirect") else ""
        nested = _spf_record_of(target) if target else None
        if nested:
            count = _spf_lookups(nested, count)
            if count > SPF_MAX_LOOKUPS:
                return count
    return count


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

    if _spf_lookups(records[0]) > SPF_MAX_LOOKUPS:
        result.permerror = True
        result.issues.append(
            f"SPF needs more than {SPF_MAX_LOOKUPS} DNS lookups — permerror, receivers apply no SPF"
        )
        return result

    # RFC 7208 §6.1: with no `all`, redirect= hands the verdict to another
    # record. The chain is finite: a loop would have failed the count above.
    redirected = terms
    via = ""
    while not result.all_mechanism and (target := _spf_redirect(redirected)):
        record = _spf_record_of(target)
        if record is None:
            result.permerror = True
            result.issues.append(f"SPF redirect={target} has no single SPF record — permerror")
            return result
        redirected = _spf_terms(record)
        result.all_mechanism = _spf_all(redirected)
        # The verdict is the target's: the record shown has no `all` of its own
        via = f" via redirect={target}"

    _apply_spf_verdict(result, terms, via)
    return result


def _apply_spf_verdict(result: SPFResult, terms: list[tuple[str, str, str]], via: str = "") -> None:
    """
    Score and annotate `result` from its `all` mechanism and the record's
    `terms`. No DNS: the lookups, which may change `all_mechanism` through
    redirect=, are check_spf's and have already been made; `via` names the
    redirect= the `all` came from, if it did.
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
    else:
        # RFC 7208 §4.7: no `all` and no redirect= ends in neutral
        result.permissive = True
        result.issues.append("SPF has no all mechanism — the default result is neutral, no enforcement")

    # Check for overly permissive mechanisms
    if any(qualifier == "+" and name in ("a", "mx") for qualifier, name, _ in terms):
        result.permissive = True
        result.issues.append("SPF contains +a or +mx — too permissive")


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
