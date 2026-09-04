"""
MailRadar — Email address discovery via Certificate Transparency (crt.sh).
"""

import httpx
import re
from dataclasses import dataclass, field


@dataclass
class DiscoveryResult:
    domain: str = ""
    emails: list[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    gpg_capable: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _extract_emails_from_text(text: str, domain: str) -> list[str]:
    """Extract email addresses for a specific domain from text."""
    pattern = rf'[a-zA-Z0-9._%+\-]+@{re.escape(domain)}'
    found = re.findall(pattern, text, re.IGNORECASE)
    return list(set(e.lower() for e in found))


def _discover_subdomains_via_crtsh(domain: str) -> list[str]:
    """
    Discover subdomains via Certificate Transparency logs (crt.sh).
    Returns subdomains, not emails.
    """
    import time
    subdomains = set()

    for attempt in range(3):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = httpx.get(url, timeout=20, follow_redirects=True)

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


def _discover_via_website(domain: str, extra_subdomains: list[str] = None) -> list[str]:
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
            resp = httpx.get(
                url,
                timeout=5,
                follow_redirects=True,
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
    import dns.resolver
    import dns.exception
    emails = []

    # SOA rname — admin email in dot notation
    try:
        answers = dns.resolver.resolve(domain, "SOA")
        for r in answers:
            rname = str(r.rname).rstrip(".")
            # SOA rname usa il primo punto come @ 
            # es: hostmaster.tplfvg.it → hostmaster@tplfvg.it
            parts = rname.split(".", 1)
            if len(parts) == 2 and parts[1] == domain:
                email = f"{parts[0]}@{parts[1]}"
                emails.append(email.lower())
    except Exception:
        pass

    # TXT records — cerca pattern email
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = b"".join(r.strings).decode()
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
        resp = httpx.get(url, timeout=10, follow_redirects=True)

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
                            if f"@{domain}" in email.lower():
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
    Generate and verify common contact addresses for a domain.
    Checks MX records to verify the domain accepts email.
    """
    import dns.resolver
    import dns.exception

    # Verifica che il dominio abbia MX records
    try:
        dns.resolver.resolve(domain, "MX")
    except Exception:
        return []

    # Lista standard di contatti comuni
    common = [
        "abuse", "admin", "administrator", "contact", "contatti",
        "dpo", "gdpr", "hostmaster", "info", "legal", "noc",
        "postmaster", "privacy", "security", "support", "webmaster",
    ]

    return [f"{prefix}@{domain}" for prefix in common]


def _check_gpg_for_emails(emails: list[str]) -> list[str]:
    """Check which emails have GPG public keys on keyservers."""
    from mailradar.gpg import lookup_gpg_by_email
    gpg_capable = []

    for email in emails:
        result = lookup_gpg_by_email(email)
        if result.found:
            gpg_capable.append(email)

    return gpg_capable


def discover(domain: str, check_gpg: bool = True) -> DiscoveryResult:
    """
    Full email address discovery for a domain.
    Sources: crt.sh, website scraping, RDAP/WHOIS.
    """
    result = DiscoveryResult(domain=domain)
    all_emails = set()

    # crt.sh — scopre sottodomini per ampliare il website scraping
    subdomains = _discover_subdomains_via_crtsh(domain)
    result.sources["crt.sh subdomains"] = subdomains

    # Common contacts — genera e verifica indirizzi standard
    common = _discover_common_contacts(domain)
    if common:
        result.sources["common contacts"] = common
        all_emails.update(common)

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
    result.emails = sorted(list(all_emails))

    # GPG check
    if check_gpg and result.emails:
        result.gpg_capable = _check_gpg_for_emails(result.emails)

    return result
