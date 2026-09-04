"""
MailRadar — Report generator from domain analysis results.
"""

from datetime import date
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
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

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=False)  # NOSONAR: plain text email templates, not HTML
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

        # SPF
        "spf_issues": report.spf.issues,
        "spf_current": report.spf.raw or "Not configured",
        "spf_present": report.spf.present,

        # DKIM
        "dkim_issues": report.dkim.issues,
        "dkim_present": report.dkim.present,
        "dkim_selector": report.dkim.selector or "N/A",
        "dkim_bits": report.dkim.key_bits or 0,

        # BIMI
        "bimi_issues": report.bimi.issues,
        "bimi_present": report.bimi.present,

        # MTA-STS
        "mta_sts_issues": report.mta_sts.issues,

        # TLS-RPT
        "tls_rpt_issues": report.tls_rpt.issues,
    }

    return template.render(**context)


def save_report(text: str, domain: str, lang: str = "it") -> Path:
    """Save report to file."""
    filename = f"mailradar_{domain}_{date.today().strftime('%Y%m%d')}_{lang}.txt"
    path = Path(filename)
    path.write_text(text, encoding="utf-8")
    return path
