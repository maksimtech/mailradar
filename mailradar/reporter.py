"""
MailRadar — Report generator from domain analysis results.
"""

from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from mailradar.checker import DomainReport

TEMPLATES_DIR = Path(__file__).parent / "templates"


def generate_report(
    report: DomainReport,
    lang: str = "it",
    sender_name: str = "[NOME]",
    sender_role: str = "[RUOLO]",
    sender_org: str = "[ORGANIZZAZIONE]",
) -> str:
    """Generate email report text from domain analysis."""

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
    template_file = f"report_{lang}.j2"

    try:
        template = env.get_template(template_file)
    except Exception:
        template = env.get_template("report_en.j2")

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

        # SPF
        "spf_issues": report.spf.issues,
        "spf_current": report.spf.raw or "Not configured",
        "spf_present": report.spf.present,

        # DKIM
        "dkim_issues": report.dkim.issues,
        "dkim_present": report.dkim.present,
        "dkim_selector": report.dkim.selector or "N/A",
        "dkim_bits": report.dkim.key_bits or 0,
        "dkim_key": "Ed25519" if report.dkim.key_type == "ed25519" else f"{report.dkim.key_bits or 0}-bit RSA",
        "dkim_current": _dkim_current(report, lang),

        # BIMI and MTA-STS, what is there now
        "bimi_current": _bimi_current(report, lang),
        "mta_sts_current": _mta_sts_current(report, lang),

        # BIMI
        "bimi_issues": report.bimi.issues,
        "bimi_present": report.bimi.present,

        # MTA-STS
        "mta_sts_issues": report.mta_sts.issues,
        "mta_sts_present": report.mta_sts.present,
        "mta_sts_mode": report.mta_sts.mode,

        # TLS-RPT
        "tls_rpt_issues": report.tls_rpt.issues,
    }

    return template.render(**context)


def _dkim_current(report: DomainReport, lang: str) -> str:
    """What DKIM looks like from DNS: every key found, or why none was."""
    it = lang == "it"
    dkim = report.dkim
    if dkim.present and len(dkim.keys) > 1:
        keys = ", ".join(f"{selector} {key}" for selector, key in dkim.keys.items())
        return (f"Chiavi trovate: {keys}" if it else f"Keys found: {keys}")
    if dkim.present:
        key = "Ed25519" if dkim.key_type == "ed25519" else f"{dkim.key_bits or 0}-bit RSA"
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


def _bimi_current(report: DomainReport, lang: str) -> str:
    it = lang == "it"
    if report.bimi.present:
        return "Presente ma con errori" if it else "Present but with errors"
    return "Non configurato" if it else "Not configured"


def _mta_sts_current(report: DomainReport, lang: str) -> str:
    it = lang == "it"
    if report.mta_sts.present:
        mode = report.mta_sts.mode or ("sconosciuta" if it else "unknown")
        return f"Presente, modalità: {mode}" if it else f"Present, mode: {mode}"
    return "Non configurato" if it else "Not configured"


def save_report(text: str, domain: str, lang: str = "it") -> Path:
    """Save report to file."""
    filename = f"mailradar_{domain}_{date.today().strftime('%Y%m%d')}_{lang}.txt"
    path = Path(filename)
    path.write_text(text, encoding="utf-8")
    return path
