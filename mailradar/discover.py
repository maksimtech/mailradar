"""
MailRadar — Email address discovery via Certificate Transparency (crt.sh).
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlsplit

import httpx


@dataclass
class DiscoveryResult:
    domain: str = ""
    emails: list[str] = field(default_factory=list)  # found in real sources
    candidates: list[str] = field(default_factory=list)  # guessed, unverified
    sources: dict = field(default_factory=dict)
    gpg_capable: list[str] = field(default_factory=list)
    # Addresses no keyserver answered for (HTTP 429, a timeout): neither with a key nor without
    gpg_unverified: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# RFC 5322 §3.2.3 atext, plus the letters and digits of other scripts that
# RFC 6532 allows in a local part: o'brien, josé.dpo
_ATEXT = r"A-Za-z0-9!#$%&'*+/=?^_`{|}~\-"
_ATOM_CHAR = rf"(?:[{_ATEXT}]|[^\x00-\x7f\W])"
_DOT_ATOM = re.compile(rf"{_ATOM_CHAR}+(?:\.{_ATOM_CHAR}+)*")
# atext that RFC 5322 allows in a local part, but that in a page or a URL ends
# whatever comes before an address: /contact/info@, ?email=info@, 'info@'
_DELIMITERS = re.compile(r"[/=?{}|`]")
# mailto: values are URLs: mailto:%20dpo@ is dpo@, mailto:Privacy%40 is Privacy@
_MAILTO = re.compile(r"mailto:([^\s\"'<>]+)", re.IGNORECASE)


def _extract_emails_from_text(text: str, domain: str) -> list[str]:
    """
    Extract email addresses for a specific domain from text, each whole.

    The local part is RFC 5322's dot-atom, read to its first character: a
    narrower class cut `o'brien@` to `brien@` and `josé.dpo@` to `.dpo@`, and
    reported the cut. A local part that is not a dot-atom is not reported.
    """
    text = _MAILTO.sub(lambda m: "mailto:" + unquote(m.group(1)), text)
    # The run of local-part characters before the @, from its first one; the
    # domain must not continue past the name: this excludes
    # example.community and example.com.evil.org, but accepts a full stop
    # ending a sentence ("info@example.com.")
    pattern = (
        rf"(?<![{_ATEXT}.]|[^\x00-\x7f\W])((?:{_ATOM_CHAR}|\.)+)@{re.escape(domain)}"
        r"(?![a-zA-Z0-9\-]|\.[a-zA-Z0-9])"
    )
    found = set()
    for run in re.findall(pattern, text, re.IGNORECASE):
        local = _DELIMITERS.split(run)[-1].lstrip("'")
        if _DOT_ATOM.fullmatch(local):
            found.add(f"{local}@{domain}".lower())
    return list(found)


# ─── Redirects, followed by hand ─────────────────────────────────────────────

_REDIRECTS = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5


class RedirectRefused(Exception):
    """A redirect to somewhere discover does not go: not https, or not a public address."""


def _addresses_are_global(host: str) -> bool:
    """Every address DNS gives for `host` is a public one (and there is at least one)."""
    import dns.exception
    import dns.resolver

    addresses = []
    for rdtype in ("A", "AAAA"):
        try:
            addresses += [rdata.address for rdata in dns.resolver.resolve(host, rdtype)]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            return False
    return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)


def _may_follow(target: str, origin: str) -> bool:
    """Whether discover follows a redirect to `target`, from a request first made to `origin`.

    https only. An address must be a public one. A name in the registrable
    domain of the first request is followed as that request was; any other name
    only if every address it has is public. httpx followed every redirect,
    `http://127.0.0.1` included: a page, or anyone on the path, could point the
    tool at the network it runs from.
    """
    from mailradar.checker import organizational_domain

    parts = urlsplit(target)
    if parts.scheme.lower() != "https" or not parts.hostname:
        return False
    host = parts.hostname.rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    first = (urlsplit(origin).hostname or "").rstrip(".").lower()
    if first and organizational_domain(host) == organizational_domain(first):
        return True
    return _addresses_are_global(host)


def _get(url: str, **kwargs) -> httpx.Response:
    """httpx.get with its redirects followed by hand, each one past _may_follow; RedirectRefused otherwise."""
    origin = url
    for _ in range(MAX_REDIRECTS + 1):
        resp = httpx.get(url, follow_redirects=False, **kwargs)
        if resp.status_code not in _REDIRECTS:
            return resp
        location = resp.headers.get("location") or ""
        target = urljoin(url, location) if location else ""
        if not target or not _may_follow(target, origin):
            raise RedirectRefused(f"redirect from {url} to {target or 'nowhere'} not followed")
        url = target
    raise RedirectRefused(f"more than {MAX_REDIRECTS} redirects from {origin}")


def _discover_subdomains_via_crtsh(domain: str) -> list[str]:
    """
    Discover subdomains via Certificate Transparency logs (crt.sh).
    Returns subdomains, not emails.
    """
    import time
    subdomains = set()

    for _attempt in range(3):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = _get(url, timeout=20)

            if resp.status_code != 200 or not resp.content:
                time.sleep(2)
                continue

            data = resp.json()

            for entry in data:
                for raw_name in [
                    entry.get("name_value", ""),
                    entry.get("common_name", ""),
                ]:
                    for name in raw_name.splitlines():
                        name = name.replace("*.", "").strip().lower()
                        # Rimuovi link markdown [text](url) con regex
                        name = re.sub(r'\[+([^\]]+)\]\([^\)]+\)', lambda m: m.group(1), name).strip()
                        if (name.endswith(f".{domain}") and
                                name != domain and
                                " " not in name):
                            subdomains.add(name)
            break

        except Exception:
            time.sleep(2)
            continue

    return list(subdomains)


def _discover_via_website(domain: str, extra_subdomains: list[str] | None = None) -> list[str]:
    """
    Scrape the domain's website for email addresses.
    Checks common pages plus subdomains discovered via crt.sh.
    """
    emails = []
    pages = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/contatti",
        f"https://{domain}/privacy",
        f"https://{domain}/about",
        f"https://{domain}/chi-siamo",
        f"https://{domain}/privacy-policy",
        f"https://www.{domain}",
        f"https://www.{domain}/privacy",
        f"https://www.{domain}/contatti",
    ]

    # Aggiungi sottodomini da crt.sh
    if extra_subdomains:
        for sub in extra_subdomains[:10]:  # Max 10 sottodomini
            pages.append(f"https://{sub}")
            pages.append(f"https://{sub}/privacy")
            pages.append(f"https://{sub}/contatti")

    for url in pages:
        try:
            resp = _get(
                url,
                timeout=5,
                headers={"User-Agent": "MailRadar/1.0 (+https://github.com/maksimtech/mailradar)"},
            )
            if resp.status_code == 200:
                found = _extract_emails_from_text(resp.text, domain)
                emails.extend(found)
        except Exception:
            continue

    return list(set(emails))


def _discover_via_dns(domain: str) -> list[str]:
    """Extract email hints from DNS records — SOA, TXT."""
    import dns.exception
    import dns.resolver
    emails = []

    # SOA rname — admin email in dot notation
    try:
        answers = dns.resolver.resolve(domain, "SOA")
        for r in answers:
            # An SOA rname uses its first label boundary where an address has
            # the @: hostmaster.tplfvg.it is hostmaster@tplfvg.it. By labels,
            # not by the first dot of the text: RFC 1035 §8 writes a dot inside
            # the local part as \., and john\.doe.example.com. is
            # john.doe@example.com — split on the text, it matched no domain.
            labels = [label.decode("utf-8", errors="replace") for label in r.rname.labels if label]
            # DNS names are case-insensitive: Hostmaster.Example.COM. counts
            if len(labels) >= 2 and ".".join(labels[1:]).lower() == domain.lower():
                emails.append(f"{labels[0]}@{'.'.join(labels[1:])}".lower())
    except Exception:
        pass

    # TXT records — cerca pattern email
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            # errors="replace": one TXT that is not UTF-8 must not cost the others
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            found = _extract_emails_from_text(txt, domain)
            emails.extend(found)
    except Exception:
        pass

    return list(set(emails))


def _discover_via_whois(domain: str) -> list[str]:
    """
    Extract email addresses from WHOIS data via rdap.
    Uses RDAP (Registration Data Access Protocol) — the modern WHOIS.
    """
    emails = []
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = _get(url, timeout=10)

        if resp.status_code == 200:
            text = resp.text
            found = _extract_emails_from_text(text, domain)
            emails.extend(found)

            # RDAP entities may have emails in vcard
            import json
            data = json.loads(text)

            def extract_from_entity(entity):
                vcards = entity.get("vcardArray", [])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if vcard[0] == "email":
                            email = vcard[3]
                            # endswith, not `in`: admin@example.com.evil.org is not ours
                            if email.lower().endswith(f"@{domain.lower()}"):
                                emails.append(email.lower())
                for sub in entity.get("entities", []):
                    extract_from_entity(sub)

            for entity in data.get("entities", []):
                extract_from_entity(entity)

    except Exception:
        pass

    return list(set(emails))


def _discover_common_contacts(domain: str) -> list[str]:
    """
    Generate common role addresses (RFC 2142) for a domain.

    These are guesses, NOT verified mailboxes: the only check is that the
    domain accepts email at all (has MX records and no null MX, RFC 7505).
    """
    import dns.resolver

    try:
        answers = dns.resolver.resolve(domain, "MX")
    except Exception:
        return []

    # Null MX ("0 .") — the domain states outright that it receives no mail
    if all(str(r.exchange) == "." for r in answers):
        return []

    # Lista standard di contatti comuni
    common = [
        "abuse", "admin", "administrator", "contact", "contatti",
        "dpo", "gdpr", "hostmaster", "info", "legal", "noc",
        "postmaster", "privacy", "security", "support", "webmaster",
    ]

    return [f"{prefix}@{domain}" for prefix in common]


def _check_gpg_for_emails(emails: list[str]) -> tuple[list[str], list[str]]:
    """(the addresses with a GPG key on a keyserver, those no keyserver answered for), in `emails` order.

    The second list used to be dropped: when the keyservers did not answer,
    discover said "No GPG public keys found".
    """
    from mailradar.gpg import lookup_gpg_by_email
    # In parallel: each address queries up to three keyservers with a 15s
    # timeout, which in sequence would be minutes.
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lookup_gpg_by_email, emails))

    pairs = list(zip(emails, results, strict=True))
    found = [email for email, r in pairs if r.found]
    unverified = [email for email, r in pairs if not r.found and r.error]
    return found, unverified


def discover(domain: str, check_gpg: bool = True) -> DiscoveryResult:
    """
    Full email address discovery for a domain.
    Sources: crt.sh, website scraping, RDAP/WHOIS.
    """
    result = DiscoveryResult(domain=domain)
    all_emails = set()

    # crt.sh — subdomains, which widens what the website scraping can reach
    subdomains = _discover_subdomains_via_crtsh(domain)
    result.sources["crt.sh subdomains"] = subdomains

    # Common contacts — indirizzi standard ipotizzati, tenuti separati dalle
    # email realmente trovate
    common = _discover_common_contacts(domain)
    if common:
        result.sources["common contacts"] = common

    # Website scraping — usa i sottodomini trovati da crt.sh
    website_emails = _discover_via_website(domain, extra_subdomains=subdomains)
    if website_emails:
        result.sources["website"] = website_emails
        all_emails.update(website_emails)

    # DNS records — SOA e TXT
    dns_emails = _discover_via_dns(domain)
    if dns_emails:
        result.sources["DNS"] = dns_emails
        all_emails.update(dns_emails)

    # RDAP/WHOIS
    whois_emails = _discover_via_whois(domain)
    if whois_emails:
        result.sources["RDAP/WHOIS"] = whois_emails
        all_emails.update(whois_emails)

    # Deduplicate and sort
    result.emails = sorted(all_emails)
    result.candidates = sorted(set(common) - all_emails)
    # The guessed source is what is left of the guesses: an address a real source
    # found is listed there, once, and is neither counted nor shown as a guess
    # (mailradar#144). The key keeps its place, before the sources that found
    # something, so the output reads in the same order as before.
    if result.candidates:
        result.sources["common contacts"] = result.candidates
    else:
        result.sources.pop("common contacts", None)

    # GPG is checked on the candidates too: a public key for security@ is worth
    to_check = result.emails + result.candidates
    if check_gpg and to_check:
        result.gpg_capable, result.gpg_unverified = _check_gpg_for_emails(to_check)

    return result
