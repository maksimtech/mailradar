"""
MailRadar — GPG public key lookup on keyservers.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

# keys.openpgp.org lists a key under an address only after the address's owner
# has answered a verification mail; keyserver.ubuntu.com (Hockeypuck, the SKS
# successor) lists whatever anyone uploads. pgp.mit.edu was the third until
# 2026-10-09: that day it took the full 15 s to time out on each of the five
# contact addresses (83 s of an 86 s analysis), answered HTTP 500 at other
# moments, and when it did answer it matched the words of the search, so that
# `postmaster@pec.poste.it` returned the key of a private person none of whose
# 72 uids carried the address or the domain.
KEYSERVERS = [
    "https://keys.openpgp.org",
    "https://keyserver.ubuntu.com",
]

# Hosts whose by-email lookup is only answered for addresses their owner confirmed
VERIFYING_KEYSERVERS = frozenset({"keys.openpgp.org"})

# The role addresses lookup_gpg asks about, in order
CONTACTS = ("security", "dpo", "admin", "postmaster", "privacy")

# Seconds a keyserver has to answer one request
TIMEOUT = 15

_ARMOR = "BEGIN PGP PUBLIC KEY BLOCK"


@dataclass
class GPGResult:
    found: bool = False
    keyserver: str = ""
    fingerprint: str = ""
    uid: str = ""
    key_id: str = ""
    emails: list[str] = field(default_factory=list)
    raw_key: str = ""
    # True when the keyserver confirmed the address's owner published the key
    # (keys.openpgp.org); False for a key anyone could have uploaded
    verified: bool = False
    score: int = 0
    # Set when some address got no answer from any keyserver (HTTP 429, 5xx,
    # timeout): the check then says nothing either way
    error: str = ""
    issues: list[str] = field(default_factory=list)


class KeyserverError(Exception):
    """A keyserver that gave no answer: rate limit, server error, timeout. Not the same as 'no key'."""


def _host(keyserver: str) -> str:
    return urlparse(keyserver).hostname or keyserver


def _machine_readable(text: str, email: str) -> str:
    """
    The fingerprint of the first usable key in an HKP `op=index&options=mr`
    answer that carries `email` as one of its uids, "" if there is none.

    draft-shaw-openpgp-hkp-00 §5.2: `pub:<keyid>:<algo>:<keylen>:<creationdate>:
    <expirationdate>:<flags>` followed by its `uid:<escaped uid>:...` lines;
    flags r, d and e mark a revoked, disabled or expired key. Keyservers search
    by substring or by word, so the uids are checked here: eli.geminder+security
    @gmail.com is not security@gmail.com.
    """
    wanted = email.lower()
    fingerprint = ""
    usable = False
    for line in text.splitlines():
        fields = line.split(":")
        if fields[0] == "pub" and len(fields) >= 7:
            fingerprint = fields[1]
            usable = not set(fields[6].lower()) & {"r", "d", "e"}
        elif fields[0] == "uid" and len(fields) >= 2 and usable and fingerprint:
            uid = fields[1].lower()
            address = re.search(r"<([^<>]+)>", uid)
            if (address.group(1) if address else uid.strip()) == wanted:
                return fingerprint
    return ""


def _search_keyserver(client: httpx.Client, keyserver: str, email: str) -> GPGResult:
    """
    The key `keyserver` publishes for exactly `email`, or a result with
    found=False when it publishes none. Raises KeyserverError when the server
    did not answer the question (HTTP 429, 5xx, a timeout...).
    """
    result = GPGResult()
    host = _host(keyserver)
    try:
        if host in VERIFYING_KEYSERVERS:
            # VKS: an exact-address lookup, answered only for verified addresses;
            # the HKP interface of the same host is a second request against the
            # same rate limit for the same answer
            resp = client.get(f"{keyserver}/vks/v1/by-email/{email}")
            if resp.status_code == 200 and _ARMOR in resp.text:
                result.found = True
                result.verified = True
                result.keyserver = keyserver
                result.raw_key = resp.text
                return result
            if resp.status_code == 404:
                return result
            raise KeyserverError(f"{host}: HTTP {resp.status_code}")

        index = client.get(f"{keyserver}/pks/lookup", params={"op": "index", "search": email, "options": "mr"})
        if index.status_code == 404:
            return result
        if index.status_code != 200:
            raise KeyserverError(f"{host}: HTTP {index.status_code}")
        fingerprint = _machine_readable(index.text, email)
        if not fingerprint:
            return result
        key = client.get(f"{keyserver}/pks/lookup",
                         params={"op": "get", "search": f"0x{fingerprint}", "options": "mr"})
        if key.status_code == 200 and _ARMOR in key.text:
            result.found = True
            result.keyserver = keyserver
            result.fingerprint = fingerprint
            result.key_id = fingerprint[-16:]
            result.raw_key = key.text
            return result
        if key.status_code == 404:
            return result
        raise KeyserverError(f"{host}: HTTP {key.status_code}")
    except httpx.HTTPError as e:
        raise KeyserverError(f"{host}: {type(e).__name__}") from e


def _lookup(emails: list[str], keyservers: list[str]) -> GPGResult:
    """
    The first key any of `keyservers` publishes for any of `emails`, the
    addresses in order. A keyserver that does not answer is not asked again:
    one timeout is 15 s, five would be the whole analysis.
    """
    down: dict[str, str] = {}
    # HTTP/1.1 on purpose: HTTP/2 misbehaves against some of these environments
    with httpx.Client(http2=False, timeout=TIMEOUT) as client:
        for email in emails:
            for keyserver in keyservers:
                if keyserver in down:
                    continue
                try:
                    result = _search_keyserver(client, keyserver, email)
                except KeyserverError as e:
                    down[keyserver] = str(e)
                    continue
                if result.found:
                    result.uid = email
                    result.emails.append(email)
                    if result.verified:
                        result.score = 5
                    else:
                        result.issues.append(
                            f"GPG key for {email} found on {_host(result.keyserver)}, which does not verify "
                            f"addresses — anyone can publish a key there under any name; confirm fingerprint "
                            f"{result.fingerprint} with the domain before relying on it"
                        )
                    return result
    if down:
        # A keyserver that did not answer may hold the key: absence is not proven
        return GPGResult(error="; ".join(down.values()))
    return GPGResult()


def lookup_gpg(domain: str, keyservers: list[str] | None = None) -> GPGResult:
    """
    Search for GPG public keys associated with a domain.
    Checks security@, dpo@, admin@, postmaster@, privacy@ addresses.
    """
    result = _lookup([f"{contact}@{domain}" for contact in CONTACTS], keyservers or KEYSERVERS)
    if result.error:
        result.issues.append(f"GPG not verified — keyserver did not answer: {result.error}")
    elif not result.found:
        result.issues.append(f"No GPG public key found for {domain} on any keyserver")
    return result


def lookup_gpg_by_email(email: str, keyservers: list[str] | None = None) -> GPGResult:
    """Search for a GPG key by specific email address."""
    result = _lookup([email], keyservers or KEYSERVERS)
    if result.error:
        result.issues.append(f"GPG not verified — keyserver did not answer: {result.error}")
    elif not result.found:
        result.issues.append(f"No GPG public key found for {email}")
    return result
