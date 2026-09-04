"""
MailRadar — GPG public key lookup on keyservers.
"""

import httpx
from dataclasses import dataclass, field


KEYSERVERS = [
    "https://keys.openpgp.org",
    "https://keyserver.ubuntu.com",
    "https://pgp.mit.edu",
]


@dataclass
class GPGResult:
    found: bool = False
    keyserver: str = ""
    fingerprint: str = ""
    uid: str = ""
    key_id: str = ""
    emails: list[str] = field(default_factory=list)
    raw_key: str = ""
    score: int = 0
    issues: list[str] = field(default_factory=list)


def _search_keyserver(keyserver: str, email: str) -> GPGResult:
    """Search for a GPG key on a specific keyserver."""
    result = GPGResult()

    try:
        # HKP protocol search
        url = f"{keyserver}/pks/lookup"
        params = {
            "op": "get",
            "search": email,
            "options": "mr",
        }
        resp = httpx.get(url, params=params, timeout=5)

        if resp.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in resp.text:
            result.found = True
            result.keyserver = keyserver
            result.raw_key = resp.text

            # Try to extract key ID from the response
            lines = resp.text.splitlines()
            for line in lines:
                if "pub:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        result.key_id = parts[1][:16] if parts[1] else ""
                    break

            return result

        # Try vks API (keys.openpgp.org specific)
        if "openpgp.org" in keyserver:
            vks_url = f"{keyserver}/vks/v1/by-email/{email}"
            resp2 = httpx.get(vks_url, timeout=5)
            if resp2.status_code == 200:
                result.found = True
                result.keyserver = keyserver
                result.raw_key = resp2.text
                return result

    except Exception:
        pass

    return result


def lookup_gpg(domain: str) -> GPGResult:
    """
    Search for GPG public keys associated with a domain.
    Checks security@, dpo@, admin@, postmaster@ addresses.
    """
    contacts = [
        f"security@{domain}",
        f"dpo@{domain}",
        f"admin@{domain}",
        f"postmaster@{domain}",
        f"privacy@{domain}",
    ]

    for email in contacts:
        for keyserver in KEYSERVERS:
            result = _search_keyserver(keyserver, email)
            if result.found:
                result.uid = email
                result.emails.append(email)
                result.score = 5
                return result

    # No key found
    result = GPGResult()
    result.issues.append(f"No GPG public key found for {domain} on any keyserver")
    return result


def lookup_gpg_by_email(email: str) -> GPGResult:
    """Search for a GPG key by specific email address."""
    for keyserver in KEYSERVERS:
        result = _search_keyserver(keyserver, email)
        if result.found:
            result.uid = email
            result.emails.append(email)
            result.score = 5
            return result

    result = GPGResult()
    result.issues.append(f"No GPG public key found for {email}")
    return result
