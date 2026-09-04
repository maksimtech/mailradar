"""
MailRadar — CLI interface.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from typing import Optional

from mailradar.checker import analyze_domain, DomainReport

app = typer.Typer(
    name="mailradar",
    help="📡 Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool",
    add_completion=False,
)

console = Console()


def _score_color(score: int) -> str:
    if score >= 90:
        return "bright_green"
    elif score >= 75:
        return "green"
    elif score >= 50:
        return "yellow"
    elif score >= 25:
        return "orange3"
    else:
        return "red"


def _grade_emoji(grade: str) -> str:
    return {
        "EXCELLENT": "🟢",
        "GOOD": "🟢",
        "MODERATE": "🟡",
        "POOR": "🟠",
        "CRITICAL": "🔴",
    }.get(grade, "⚪")


def _bool_icon(value: bool) -> str:
    return "✅" if value else "❌"


def _print_report(report: DomainReport) -> None:
    color = _score_color(report.total_score)
    emoji = _grade_emoji(report.grade)

    console.print()
    console.print(Panel(
        f"[bold]Domain:[/bold] {report.domain}\n"
        f"[bold]Score:[/bold] [{color}]{report.total_score}/100 — {emoji} {report.grade}[/{color}]",
        title="📡 MailRadar Report",
        border_style=color,
    ))

    # DMARC
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Check", style="bold", width=12)
    table.add_column("Status", width=6)
    table.add_column("Details", width=55)
    table.add_column("Score", width=8, justify="right")

    # DMARC row
    d = report.dmarc
    dmarc_detail = ""
    if d.present:
        dmarc_detail = (
            f"p={d.policy} | pct={d.pct} | "
            f"adkim={'s' if d.adkim == 's' else 'r'} | "
            f"aspf={'s' if d.aspf == 's' else 'r'} | "
            f"rua={'✓' if d.rua else '✗'} | ruf={'✓' if d.ruf else '✗'}"
        )
    else:
        dmarc_detail = "[red]Not configured[/red]"

    dmarc_icon = "✅" if d.policy == "reject" else ("⚠️ " if d.present else "❌")
    table.add_row("DMARC", dmarc_icon, dmarc_detail, f"[{_score_color(d.score)}]{d.score}[/{_score_color(d.score)}]")

    # SPF row
    s = report.spf
    spf_detail = s.raw[:55] if s.present else "[red]Not configured[/red]"
    spf_icon = "✅" if (s.present and not s.permissive) else ("⚠️ " if s.present else "❌")
    table.add_row("SPF", spf_icon, spf_detail, f"[{_score_color(s.score)}]{s.score}[/{_score_color(s.score)}]")

    # DKIM row
    k = report.dkim
    dkim_detail = ""
    if k.present:
        dkim_detail = f"selector: {k.selector} | {k.key_bits}-bit RSA"
    else:
        dkim_detail = "[red]Not found (tried common selectors)[/red]"
    dkim_icon = "✅" if k.present else "❌"
    table.add_row("DKIM", dkim_icon, dkim_detail, f"[{_score_color(k.score)}]{k.score}[/{_score_color(k.score)}]")

    # BIMI row
    b = report.bimi
    bimi_detail = ""
    if b.present:
        bimi_detail = f"SVG: {'✓' if b.svg_valid else '✗'} | VMC: {'✓' if b.vmc_present else '✗'}"
    else:
        bimi_detail = "[dim]Not configured[/dim]"
    bimi_icon = "✅" if (b.present and b.vmc_present) else ("⚠️ " if b.present else "❌")
    table.add_row("BIMI/VMC", bimi_icon, bimi_detail, f"[{_score_color(b.score)}]{b.score}[/{_score_color(b.score)}]")

    # MTA-STS row
    m = report.mta_sts
    mts_detail = f"mode: {m.mode}" if m.present else "[dim]Not configured[/dim]"
    mts_icon = "✅" if (m.present and m.mode == "enforce") else ("⚠️ " if m.present else "❌")
    table.add_row("MTA-STS", mts_icon, mts_detail, f"[{_score_color(m.score)}]{m.score}[/{_score_color(m.score)}]")

    # TLS-RPT row
    t = report.tls_rpt
    tls_detail = f"rua: {t.rua[:40]}" if t.present else "[dim]Not configured[/dim]"
    tls_icon = "✅" if t.present else "❌"
    table.add_row("TLS-RPT", tls_icon, tls_detail, f"[{_score_color(t.score)}]{t.score}[/{_score_color(t.score)}]")

    console.print(table)

    # Issues
    all_issues = (
        report.dmarc.issues +
        report.spf.issues +
        report.dkim.issues +
        report.bimi.issues +
        report.mta_sts.issues +
        report.tls_rpt.issues
    )

    if all_issues:
        console.print()
        console.print("[bold yellow]⚠️  Issues found:[/bold yellow]")
        for issue in all_issues:
            console.print(f"  [dim]•[/dim] {issue}")

    console.print()


@app.command()
def check(
    domain: str = typer.Argument(..., help="Domain to analyze"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show raw DNS records"),
):
    """
    Analyze the email security posture of a domain.
    """
    console.print(f"\n[dim]Analyzing [bold]{domain}[/bold]...[/dim]")

    with console.status(f"[cyan]Running DNS checks...[/cyan]"):
        report = analyze_domain(domain)

    _print_report(report)

    if verbose:
        console.print("[bold]Raw records:[/bold]")
        if report.dmarc.raw:
            console.print(f"  DMARC: {report.dmarc.raw}")
        if report.spf.raw:
            console.print(f"  SPF:   {report.spf.raw}")
        if report.dkim.raw:
            console.print(f"  DKIM:  {report.dkim.raw}")
        if report.bimi.raw:
            console.print(f"  BIMI:  {report.bimi.raw}")
        console.print()

    # Exit code based on grade
    if report.grade == "CRITICAL":
        raise typer.Exit(2)
    elif report.grade in ("POOR", "MODERATE"):
        raise typer.Exit(1)


@app.command()
def batch(
    file: str = typer.Argument(..., help="File with one domain per line"),
):
    """
    Analyze multiple domains from a file.
    """
    try:
        with open(file) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    results = []
    for domain in domains:
        console.print(f"[dim]Checking {domain}...[/dim]")
        report = analyze_domain(domain)
        results.append(report)
        _print_report(report)

    # Summary table
    console.print(Panel("[bold]Batch Summary[/bold]", border_style="cyan"))
    summary = Table(box=box.SIMPLE)
    summary.add_column("Domain")
    summary.add_column("Score", justify="right")
    summary.add_column("Grade")

    for r in sorted(results, key=lambda x: x.total_score):
        color = _score_color(r.total_score)
        summary.add_row(
            r.domain,
            f"[{color}]{r.total_score}[/{color}]",
            f"{_grade_emoji(r.grade)} {r.grade}"
        )

    console.print(summary)


def main():
    app()


if __name__ == "__main__":
    main()
