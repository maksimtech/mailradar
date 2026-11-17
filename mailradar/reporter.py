"""
MailRadar — Report generator from domain analysis results.
"""

import contextlib
import re
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from mailradar.checker import DomainReport

TEMPLATES_DIR = Path(__file__).parent / "templates"

# C0 controls, DEL and C1 controls: what a terminal reads as a command. ESC
# alone clears the screen, moves the cursor or opens an OSC 8 hyperlink.
_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def visible(text: str, keep: str = "") -> str:
    """`text` with every control character written out as `\\xNN`, those in `keep` excepted.

    For whatever came from outside — a DNS TXT record, a keyserver's answer, an
    MTA-STS policy — before it is printed or put in a letter: the reader sees
    the bytes that were published, and the terminal gets no command from them.
    """
    return _CONTROLS.sub(lambda m: m.group() if m.group() in keep else f"\\x{ord(m.group()):02x}", text)


# The languages a letter is written in, each with its template
LANGUAGES = ("it", "en")


def language(lang: str) -> str:
    """`lang` as one of LANGUAGES, whatever its case; ValueError for any other.

    `IT` found report_IT.j2 on Windows, whose file names ignore case, while the
    code compared `lang == "it"`: an Italian letter with English lines in it.
    `de` was an English letter saved as _de.txt.
    """
    normalised = lang.strip().lower()
    if normalised not in LANGUAGES:
        raise ValueError(f"no letter in that language: choose one of {', '.join(LANGUAGES)}")
    return normalised


def generate_report(
    report: DomainReport,
    lang: str = "it",
    sender_name: str = "[NOME]",
    sender_role: str = "[RUOLO]",
    sender_org: str = "[ORGANIZZAZIONE]",
) -> str:
    """Generate email report text from domain analysis."""
    lang = language(lang)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "htm"),
            disabled_extensions=("j2", "txt"),
        ),
        # A block tag's own line leaves no empty line behind: the letter had
        # runs of two to five of them between sections
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # No fallback: a template that is missing or broken is an error to see,
    # not a letter in another language
    template = env.get_template(f"report_{lang}.j2")

    context = {
        "domain": report.domain,
        "total_score": report.total_score,
        "grade": report.grade,
        "date": date.today().strftime("%Y-%m-%d"),
        "sender_name": sender_name,
        "sender_role": sender_role,
        "sender_org": sender_org,

        # DMARC
        "dmarc_issues": report.dmarc.issues,
        "dmarc_current": report.dmarc.raw or "Not configured",
        "dmarc_present": report.dmarc.present,
        "dmarc_policy": report.dmarc.policy if report.dmarc.present else "",

        # What the letter calls a problem, and the only thing the GDPR art. 32
        # paragraph is written for (owner's decision): DMARC, SPF and DKIM
        # issues. BIMI, MTA-STS and TLS-RPT are improvements, SPF notes are
        # information, and no published GPG key is a suggestion.
        "has_problems": bool(report.dmarc.issues or report.spf.issues or report.dkim.issues),

        # SPF
        "spf_issues": report.spf.issues,
        "spf_notes": report.spf.notes,
        "spf_current": report.spf.raw or "Not configured",
        "spf_present": report.spf.present,

        # DKIM
        "dkim_issues": report.dkim.issues,
        "dkim_present": report.dkim.present,
        "dkim_selector": report.dkim.selector or "N/A",
        "dkim_bits": report.dkim.key_bits or 0,
        "dkim_key": "Ed25519" if report.dkim.key_type == "ed25519" else f"{report.dkim.key_bits or 0}-bit RSA",
        "dkim_current": _dkim_current(report, lang),
        # An Ed25519 key that does not parse: it needs republishing, not RSA
        "dkim_malformed": report.dkim.present and report.dkim.key_type == "ed25519" and not report.dkim.key_bits,

        # BIMI and MTA-STS, what is there now
        "bimi_current": _bimi_current(report, lang),
        "mta_sts_current": _mta_sts_current(report, lang),

        # BIMI
        "bimi_issues": report.bimi.issues,
        "bimi_present": report.bimi.present,
        "bimi_declined": _bimi_declined(report),

        # MTA-STS
        "mta_sts_issues": report.mta_sts.issues,
        "mta_sts_present": report.mta_sts.present,
        "mta_sts_mode": report.mta_sts.mode,

        # TLS-RPT
        "tls_rpt_issues": report.tls_rpt.issues,
    }

    # The letter quotes the domain's own records: printed, saved or mailed, a
    # control character in them is shown, not obeyed
    return visible(template.render(**context), keep="\n")


def _dkim_current(report: DomainReport, lang: str) -> str:
    """What DKIM looks like from DNS: every key found, or why none was."""
    it = lang == "it"
    dkim = report.dkim
    if dkim.present and len(dkim.keys) > 1:
        keys = ", ".join(f"{selector} {key}" for selector, key in dkim.keys.items())
        return (f"Chiavi trovate: {keys}" if it else f"Keys found: {keys}")
    if dkim.present:
        if dkim.key_type == "ed25519":
            key = "Ed25519" if dkim.key_bits else ("Ed25519 malformata" if it else "malformed Ed25519")
        elif dkim.key_type != "rsa":
            # k= of a type neither RFC 6376 nor RFC 8463 defines
            key = (f"chiave di tipo sconosciuto (k={dkim.key_type})" if it
                   else f"key of an unknown type (k={dkim.key_type})")
        elif not dkim.key_bits:
            # Not "0-bit RSA": a key that does not decode is no key of any length
            key = "chiave RSA malformata" if it else "malformed RSA key"
        else:
            key = f"{dkim.key_bits}-bit RSA"
        if "(testing, t=y)" in dkim.keys.get(dkim.selector, ""):
            key += " (in modalità test, t=y)" if it else " (testing, t=y)"
        return (f"Selettore {dkim.selector} | {key}" if it else f"Selector {dkim.selector} | {key}")
    if dkim.selector:
        # Found, but revoked (empty p=)
        return (f"Chiave revocata (p= vuoto) sotto il selettore {dkim.selector}" if it
                else f"Key revoked (empty p=) under selector {dkim.selector}")
    if dkim.tried:
        # A selector is the sender's choice: not found is not absent
        return (f"Nessuna chiave sotto {dkim.tried} selettori comuni — un selettore personalizzato non è escluso "
                "(tag s= dell'intestazione DKIM-Signature di un messaggio inviato)" if it
                else f"No key under {dkim.tried} common selectors — a custom selector cannot be ruled out "
                "(s= tag of a sent message's DKIM-Signature header)")
    return "Non configurato" if it else "Not configured"


def _bimi_declined(report: DomainReport) -> bool:
    """`v=BIMI1; l=; a=;`: the domain's statement that it does not take part, not a record with errors."""
    return report.bimi.present and not report.bimi.svg_url and not report.bimi.vmc_url


def _bimi_current(report: DomainReport, lang: str) -> str:
    it = lang == "it"
    if _bimi_declined(report):
        return ("Rinuncia dichiarata dal dominio (v=BIMI1; l=; a=;)" if it
                else "Declined by the domain (v=BIMI1; l=; a=;)")
    if report.bimi.present:
        return "Presente ma con errori" if it else "Present but with errors"
    return "Non configurato" if it else "Not configured"


def _mta_sts_current(report: DomainReport, lang: str) -> str:
    it = lang == "it"
    if report.mta_sts.present:
        mode = report.mta_sts.mode or ("sconosciuta" if it else "unknown")
        return f"Presente, modalità: {mode}" if it else f"Present, mode: {mode}"
    return "Non configurato" if it else "Not configured"


def _file_name_part(domain: str) -> str:
    """`domain` reduced to [a-z0-9.-]: no separator, no drive, no `:` stream, nothing to climb with.

    `x/../../../evil.com` wrote outside the current directory, and on NTFS
    `example.com:x` wrote to an alternate data stream. An internationalised
    name keeps its ASCII form (società.it is xn--societ-yua.it).
    """
    name = domain.strip().strip(".").lower()
    with contextlib.suppress(UnicodeError):
        name = name.encode("idna").decode("ascii")
    name = re.sub(r"[^a-z0-9.-]", "", name).strip(".")
    # Dots alone are no name, and `..` is no part of one
    name = re.sub(r"\.{2,}", ".", name)
    return name or "domain"


def save_report(text: str, domain: str, lang: str = "it") -> Path:
    """Save the report as mailradar_<domain>_<YYYYMMDD>_<lang>.txt in the current directory.

    OSError (a read-only directory, a directory by that name) is the caller's
    to report.
    """
    filename = f"mailradar_{_file_name_part(domain)}_{date.today().strftime('%Y%m%d')}_{language(lang)}.txt"
    path = Path.cwd() / filename
    path.write_text(text, encoding="utf-8")
    return path
