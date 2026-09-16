"""
MailRadar — DNS record checker for email security posture analysis.
"""

import dns.resolver
import dns.exception
from dataclasses import dataclass, field
from typing import Optional
import httpx


@dataclass
class DMARCResult:
    present: bool = False
    policy: str = "none"
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    rua: bool = False
    ruf: bool = False
    raw: str = ""
    score: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class SPFResult:
    present: bool = False
    all_mechanism: str = ""
    permissive: bool = False
    raw: str = ""
    score: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class DKIMResult:
    present: bool = False
    selector: str = ""
    key_bits: int = 0
    raw: str = ""
    score: int = 0
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
    issues: list[str] = field(default_factory=list)


@dataclass
class MTASTSResult:
    present: bool = False
    mode: str = ""
    score: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class TLSRPTResult:
    present: bool = False
    rua: str = ""
    score: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class GPGResult:
    found: bool = False
    keyserver: str = ""
    uid: str = ""
    key_id: str = ""
    emails: list = field(default_factory=list)
    raw_key: str = ""
    score: int = 0
    issues: list = field(default_factory=list)


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
    # Deve avere almeno un punto — senza TLD non è un dominio valido
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
    # Estrai il nome base senza TLD
    parts = domain.split(".")
    if len(parts) == 1:
        base = domain
    else:
        base = parts[0]

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


def _query_txt(name: str) -> list[str]:
    """Query TXT records for a given name."""
    try:
        answers = dns.resolver.resolve(name, "TXT")
        # Concatena le stringhe multiple di ogni record (importante per DKIM)
        # errors="replace": un TXT non UTF-8 non deve far crashare l'analisi
        return [b"".join(rdata.strings).decode("utf-8", errors="replace")
                for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.DNSException):
        return []


def _parse_tags(record: str) -> dict[str, str]:
    """Parse a `k=v; k=v` tag list (DMARC, BIMI). Values may contain '='."""
    tags = {}
    for t in record.split(";"):
        if "=" in t:
            key, value = t.split("=", 1)
            tags[key.strip()] = value.strip()
    return tags


def _parse_pct(value: str) -> Optional[int]:
    """Parse DMARC pct — returns None if not an integer in 0-100."""
    try:
        pct = int(value)
    except ValueError:
        return None
    return pct if 0 <= pct <= 100 else None


def check_dmarc(domain: str) -> DMARCResult:
    result = DMARCResult()
    records = _query_txt(f"_dmarc.{domain}")

    for record in records:
        if record.startswith("v=DMARC1"):
            result.present = True
            result.raw = record

            tags = _parse_tags(record)

            result.policy = tags.get("p", "none")
            pct = _parse_pct(tags.get("pct", "100"))
            if pct is None:
                # RFC 7489 §6.3: valore non valido → si usa il default (100)
                result.issues.append(f"Invalid DMARC pct value: {tags['pct']!r}")
                pct = 100
            result.pct = pct
            result.adkim = tags.get("adkim", "r")
            result.aspf = tags.get("aspf", "r")
            result.rua = "rua" in tags
            result.ruf = "ruf" in tags

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

            break

    if not result.present:
        result.issues.append("No DMARC record found — domain is spoofable")

    return result


def check_spf(domain: str) -> SPFResult:
    result = SPFResult()
    records = _query_txt(domain)

    for record in records:
        if record.startswith("v=spf1"):
            result.present = True
            result.raw = record

            if "-all" in record:
                result.all_mechanism = "-all"
                result.permissive = False
                result.score += 20
            elif "~all" in record:
                result.all_mechanism = "~all"
                result.permissive = True
                result.issues.append("SPF uses ~all (softfail) — consider -all (hardfail)")
                result.score += 10
            elif "+all" in record:
                result.all_mechanism = "+all"
                result.permissive = True
                result.issues.append("SPF uses +all — any server can send as this domain!")
                result.score += 0
            elif "?all" in record:
                result.all_mechanism = "?all"
                result.permissive = True
                result.issues.append("SPF uses ?all (neutral) — no enforcement")
                result.score += 5

            # Check for overly permissive mechanisms
            if "+a" in record or "+mx" in record:
                result.permissive = True
                result.issues.append("SPF contains +a or +mx — too permissive")

            break

    if not result.present:
        result.issues.append("No SPF record found")

    return result


def check_dkim(domain: str, selectors: list[str] | None = None) -> DKIMResult:
    result = DKIMResult()

    # Common selectors to try
    default_selectors = [
        "default", "mail", "email", "dkim", "google",
        "20250324", "20230601", "20240101",
        "selector1", "selector2", "k1", "s1", "s2",
        "mimecast", "mandrill", "sendgrid", "mailchimp",
    ]

    selectors_to_try = selectors or default_selectors

    for selector in selectors_to_try:
        records = _query_txt(f"{selector}._domainkey.{domain}")
        for record in records:
            if "v=DKIM1" in record or "p=" in record:
                result.present = True
                result.selector = selector
                result.raw = record

                # Extract key bits using cryptography
                if "p=" in record:
                    key_part = record.split("p=")[-1].split(";")[0].strip()
                    try:
                        import base64
                        from cryptography.hazmat.primitives.serialization import load_der_public_key
                        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
                        der = base64.b64decode(key_part + "==")
                        pub = load_der_public_key(der)
                        if isinstance(pub, RSAPublicKey):
                            result.key_bits = pub.key_size
                    except Exception:
                        # Fallback to length estimate
                        key_len = len(key_part)
                        if key_len > 350:
                            result.key_bits = 2048
                        elif key_len > 170:
                            result.key_bits = 1024
                        else:
                            result.key_bits = 512

                if result.key_bits >= 2048:
                    result.score += 15
                elif result.key_bits >= 1024:
                    result.score += 10
                    result.issues.append("DKIM key is 1024-bit — upgrade to 2048-bit recommended")
                else:
                    result.score += 3
                    result.issues.append("DKIM key is weak — upgrade to 2048-bit immediately")

                return result

    if not result.present:
        result.issues.append("No DKIM record found with common selectors")

    return result


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

            # Validate SVG
            if result.svg_url:
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
                    else:
                        result.issues.append(f"MTA-STS mode unknown: {result.mode}")
            except Exception:
                result.issues.append("MTA-STS policy file not accessible")
            break

    if not result.present:
        result.issues.append("No MTA-STS configured")

    return result


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


# Punteggio grezzo massimo di ogni check — la somma supera 100, quindi il
# totale viene normalizzato su scala 0-100 in analyze_domain.
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
