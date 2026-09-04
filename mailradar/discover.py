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


def _discover_via_crtsh(domain: str) -> list[str]:
    """
    Discover email addresses via Certificate Transparency logs (crt.sh).
    crt.sh stores SSL certificate data including email SANs and CNs.
    """
    emails = []
    try:
        # Query crt.sh for certificates related to the domain
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = httpx.get(url, timeout=15, follow_redirects=True)

        if resp.status_code != 200:
            return []

        data = resp.json()

        for entry in data:
            # Check name_value field — contains SANs
            name_value = entry.get("name_value", "")
            issuer = entry.get("issuer_ca_id", "")

            # Extract emails from name_value
            found = _extract_emails_from_text(name_value, domain)
            emails.extend(found)

            # Check common_name
            common_name = entry.get("common_name", "")
            found_cn = _extract_emails_from_text(common_name, domain)
            emails.extend(found_cn)

    except Exception as e:
        pass

    return list(set(emails))


def _discover_via_website(domain: str) -> list[str]:
    """
    Scrape the domain's website for email addresses.
    Checks common pages: homepage, contact, privacy, about.
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
    ]

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

    # crt.sh
    crtsh_emails = _discover_via_crtsh(domain)
    if crtsh_emails:
        result.sources["crt.sh"] = crtsh_emails
        all_emails.update(crtsh_emails)

    # Website scraping
    website_emails = _discover_via_website(domain)
    if website_emails:
        result.sources["website"] = website_emails
        all_emails.update(website_emails)

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
